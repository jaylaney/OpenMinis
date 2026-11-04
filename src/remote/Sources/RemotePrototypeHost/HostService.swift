#if os(macOS)
import Foundation
import CryptoKit
import Security
import RemoteExecutionCore
import RemotePrototypeWire
import RemotePrototypeTransport
import RemotePrototypeCertificates

protocol HostListener: Sendable {
    func start() async throws -> UInt16
    func cancel()
}
extension StatusTLSListener: HostListener {}

// Internal injection replaces only external IO. Shipping defaults always use the
// real owner, isolated KeyStore and exact-address native listener.
struct HostDependencies: Sendable {
    var loadPrivateKey: @Sendable () throws -> SecKey = {
        guard let key = try PrototypeKeyStore().loadIdentity(role: .host) else { throw HostBridgeError.unavailable }
        return key
    }
    var makeListener: @Sendable (StatusEndpoint, SecIdentity, @escaping @Sendable (StatusTLSChannel) -> Void,
                                @escaping @Sendable (Bool) -> Void) throws -> any HostListener = { endpoint, identity, accept, availability in
        try StatusTLSListener(endpoint: endpoint, identity: identity, onAvailability: availability, onAccept: accept)
    }
    var openOwner: @Sendable (StatusOnlyHostConfiguration) async throws -> StatusOnlyHostHandles = { try await StatusOnlyHost.open(configuration: $0) }
}

private final class HostRuntime: @unchecked Sendable {
    let fence = ServiceFence()
    let pump = ConnectionPump(role: .host)
    let onChange: @Sendable () -> Void
    let directory: URL
    private let lock = NSLock()
    private var listener: (any HostListener)?
    private var dispatcher: HostRPCDispatcher?
    private var listening = false
    private var identity: Data?
    init(directory: URL, onChange: @escaping @Sendable () -> Void) {
        self.directory = directory; self.onChange = onChange
        fence.onDisable { [weak self] in self?.cancelResources() }
    }
    func recordIdentity(_ identity: Data) { lock.withLock { self.identity = identity } }
    var resolvedIdentity: Data? { lock.withLock { identity } }
    var isListening: Bool { lock.withLock { listening } && !fence.isDisabled }
    func install(_ dispatcher: HostRPCDispatcher) { lock.withLock { self.dispatcher = dispatcher } }
    func install(_ listener: any HostListener) {
        lock.withLock { self.listener = listener }
        if fence.isDisabled { listener.cancel() }
    }
    func availability(_ available: Bool) {
        guard !fence.isDisabled else { return }
        lock.withLock { listening = available }
        onChange()
    }
    func accept(_ channel: StatusTLSChannel) {
        do {
            // Registration is synchronous before the native listener starts TLS.
            try fence.whileEnabled { try pump.accept(channel) }
        } catch { channel.cancel(); return }
        let dispatcher = lock.withLock { self.dispatcher }
        guard let dispatcher else { pump.close(connectionID: channel.connectionID); return }
        Task { [self] in
            do {
                try await dispatcher.register(channel)
                try await pump.run(connectionID: channel.connectionID) { frame, id in
                    try await dispatcher.handle(frame, connectionID: id)
                }
            } catch { pump.close(connectionID: channel.connectionID) }
            await dispatcher.disconnected(channel.connectionID)
        }
    }
    private func cancelResources() {
        // The owner callback performs only synchronous cancellation. Transcript
        // clearing is scheduled and cannot await/reenter the owner queue.
        pump.closeAll()
        let (listener, dispatcher) = lock.withLock {
            listening = false
            return (self.listener, self.dispatcher)
        }
        listener?.cancel()
        if let dispatcher { Task { await dispatcher.clear() } }
        onChange()
    }
}

/// Trusted local Mac orchestration. Each enable has independent cancellation and
/// callbacks; old tasks cannot publish or close a later enable's runtime.
public actor HostService {
    private let dependencies: HostDependencies
    private let onChange: @Sendable () -> Void
    private var runtime: HostRuntime?
    private var handles: StatusOnlyHostHandles?
    private var dispatcher: HostRPCDispatcher?
    public init(onChange: @escaping @Sendable () -> Void = {}) {
        dependencies = HostDependencies(); self.onChange = onChange
    }
    init(dependencies: HostDependencies, onChange: @escaping @Sendable () -> Void = {}) {
        self.dependencies = dependencies; self.onChange = onChange
    }
    public func openLocalPolicy(configuration: StatusOnlyHostConfiguration) async throws {
        if handles != nil {
            // A different selection requires explicit Close; never present A as B.
            guard runtime?.directory.absoluteString == configuration.directory.absoluteString else { throw HostBridgeError.unavailable }
            // This read preserves a retained failure; never replace its owner.
            _ = try await localStatus()
            return
        }
        guard runtime == nil else { throw HostBridgeError.disabled }
        let next = HostRuntime(directory: configuration.directory, onChange: onChange)
        runtime = next
        let wrapped = wrappedConfiguration(configuration, runtime: next, allowsFreshStore: false)
        var opened: StatusOnlyHostHandles?
        do {
            let owner = try await dependencies.openOwner(wrapped)
            opened = owner
            guard runtime === next, !next.fence.isDisabled else { throw HostBridgeError.disabled }
            handles = owner
            onChange()
        } catch {
            next.fence.disable()
            if let opened { await opened.host.close() }
            if runtime === next { runtime = nil; handles = nil; dispatcher = nil }
            throw error
        }
    }
    private func wrappedConfiguration(_ configuration: StatusOnlyHostConfiguration, runtime next: HostRuntime,
                                      allowsFreshStore: Bool) -> StatusOnlyHostConfiguration {
        StatusOnlyHostConfiguration(directory: configuration.directory, clock: configuration.clock,
            random: configuration.random, identityResolver: { [weak next] required in
                let spki = try configuration.identityResolver(required)
                next?.recordIdentity(spki); return spki
            }, onUnavailable: { [weak next] in
                next?.fence.disable()
                configuration.onUnavailable()
            }, allowsFreshStore: allowsFreshStore)
    }
    public func enable(configuration: StatusOnlyHostConfiguration, endpoint: StatusEndpoint) async throws {
        if handles != nil {
            // Explicit network activation cannot silently reopen a failed owner.
            _ = try await localStatus()
        }
        let oldRuntime = runtime, oldHandles = handles
        let next = HostRuntime(directory: configuration.directory, onChange: onChange)
        runtime = next; handles = nil; dispatcher = nil
        oldRuntime?.fence.disable()
        if let oldHandles { await oldHandles.host.close() }
        guard runtime === next, !next.fence.isDisabled else { throw HostBridgeError.disabled }
        let wrapped = wrappedConfiguration(configuration, runtime: next, allowsFreshStore: configuration.allowsFreshStore)
        var opened: StatusOnlyHostHandles?
        do {
            let owner = try await dependencies.openOwner(wrapped)
            opened = owner
            guard runtime === next, !next.fence.isDisabled else { throw HostBridgeError.disabled }
            handles = owner
            let dispatch = HostRPCDispatcher(handles: owner, fence: next.fence, pump: next.pump, endpoint: endpoint, onChange: onChange)
            dispatcher = dispatch; next.install(dispatch)
            let key = try dependencies.loadPrivateKey()
            // The TLS private key must match exactly what the owner resolved,
            // including an existing store's mandatory pin. Never create here.
            guard try Self.spki(key) == next.resolvedIdentity else { throw HostBridgeError.unavailable }
            let identity = try HostCertificate.makeIdentity(key: key, now: Date())
            let listener = try dependencies.makeListener(endpoint, identity, { [weak next] channel in
                guard let next else { channel.cancel(); return }; next.accept(channel)
            }, { [weak next] in next?.availability($0) })
            next.install(listener)
            _ = try await listener.start()
            guard runtime === next, !next.fence.isDisabled else { throw HostBridgeError.disabled }
            onChange()
        } catch {
            next.fence.disable()
            if runtime === next, handles != nil {
                // Published owners outlive network startup. In particular, keep
                // Core's original retained failure and lock until explicit Close.
                onChange()
                throw error
            }
            // Unpublished or superseded results own only their partial resources.
            if let opened { await opened.host.close() }
            // A superseded enable cannot erase a fresh runtime or handles.
            if runtime === next { runtime = nil; handles = nil; dispatcher = nil }
            throw error
        }
    }
    public func disable() async {
        let oldRuntime = runtime, oldHandles = handles
        runtime = nil; handles = nil; dispatcher = nil
        oldRuntime?.fence.disable()
        if let oldHandles { await oldHandles.host.close() }
        onChange()
    }
    public func revokeController() async throws {
        guard let runtime else { throw HostBridgeError.disabled }
        runtime.fence.disable() // latches even an enable awaiting owner publication
        guard let handles else { throw HostBridgeError.disabled }
        try await handles.host.revokeController()
    }
    public func localStatus() async throws -> StatusOnlyLocalSnapshot {
        guard let selected = runtime, let handles else { throw HostBridgeError.disabled }
        do {
            let snapshot = try await handles.host.localStatus()
            guard runtime === selected else { throw HostBridgeError.disabled }
            return snapshot
        } catch {
            guard runtime === selected else { throw HostBridgeError.disabled }
            throw error
        }
    }
    public func openEnrollment() async throws -> Invitation {
        guard let dispatcher else { throw HostBridgeError.disabled }
        return try await dispatcher.openEnrollment()
    }
    @discardableResult public func confirmCandidate(candidateID: UUID) async throws -> HostConfirmationOutcome {
        guard let dispatcher else { throw HostBridgeError.disabled }
        return try await dispatcher.confirmCandidate(candidateID: candidateID)
    }
    public func rejectCandidate(candidateID: UUID) async throws {
        guard let dispatcher else { throw HostBridgeError.disabled }
        try await dispatcher.rejectCandidate(candidateID: candidateID)
    }
    public func presentation() async -> HostPresentation {
        guard let runtime, !runtime.fence.isDisabled, let dispatcher else { return HostPresentation(isEnabled: false, isListening: false, invitation: nil, candidate: nil, hasOpenOwner: handles != nil) }
        let result = await dispatcher.presentation(listening: runtime.isListening)
        guard self.runtime === runtime, !runtime.fence.isDisabled else {
            return HostPresentation(isEnabled: false, isListening: false, invitation: nil, candidate: nil, hasOpenOwner: handles != nil)
        }
        // Availability may change during the Core refresh. Sample it only after
        // the awaited result is known to belong to this still-enabled runtime.
        return HostPresentation(isEnabled: result.isEnabled, isListening: runtime.isListening,
                                invitation: result.invitation, candidate: result.candidate, hasOpenOwner: true, enrollment: result.enrollment)
    }
    public static func makeProductionConfiguration(directory: URL, onUnavailable: @escaping @Sendable () -> Void = {}) -> StatusOnlyHostConfiguration {
        StatusOnlyHostConfiguration(directory: directory, clock: HostClock(), random: HostRandom(), identityResolver: { requiredPin in
            // KeyStore is non-Sendable: construct, use and release locally on the
            // owner's serial queue. Existing pins are strictly LOAD ONLY.
            let store = PrototypeKeyStore()
            let key: SecKey
            if requiredPin != nil {
                guard let existing = try store.loadIdentity(role: .host) else { throw HostBridgeError.unavailable }
                key = existing
            } else { key = try store.createIdentityIfAbsent(role: .host) }
            let spki = try Self.spki(key)
            if let requiredPin, Data(SHA256.hash(data: spki)) != requiredPin { throw StatusHostError.identityMismatch }
            return spki
        }, onUnavailable: onUnavailable)
    }
    private static func spki(_ key: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(key), let bytes = SecKeyCopyExternalRepresentation(publicKey, nil) else { throw HostBridgeError.unavailable }
        return try P256.Signing.PublicKey(x963Representation: bytes as Data).derRepresentation
    }
}
private struct HostClock: StatusClock { func nowNanoseconds() -> UInt64 { StatusTLSClock.nowNanoseconds() } }
private struct HostRandom: StatusRandomSource {
    func bytes(count: Int) throws -> Data {
        var bytes = Data(count: count)
        let result = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        guard result == errSecSuccess else { throw HostBridgeError.unavailable }; return bytes
    }
}
#endif
