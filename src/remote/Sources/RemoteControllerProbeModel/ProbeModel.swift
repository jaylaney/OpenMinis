import Foundation
import Combine
import Security
import RemotePrototypeWire
import RemotePrototypeTransport

@MainActor public protocol ProbeIdentity: AnyObject {
    func prepareIdentity(allowCreation: Bool) throws -> Data
    func proof(transcript: AuthTranscript, exporter: Data, secret: Data?) throws -> Proof
}
@MainActor public protocol ProbePinStore: AnyObject {
    func load() throws -> PairedHostRecord?
    func save(_ record: PairedHostRecord) throws
    func forget() throws
}
/// Returned only after TLS is READY with the requested exact host pin.
@MainActor public protocol ProbeChannelFactory: AnyObject {
    func connect(endpoint: StatusEndpoint, pin: Data) async throws -> any ProbeChannel
}
@MainActor public protocol ProbeChannel: AnyObject, Sendable {
    var connectionID: UUID { get }
    func exporter(context: Data) throws -> Data
    func send(_ frame: WireFrame) async throws
    func run(dispatch: @escaping @MainActor @Sendable (WireFrame, UUID) async throws -> WireFrame?) async throws
    func cancel()
}
public struct ProbeComparison: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let connectionID: UUID
    public let claimDigest: Data
    public let code: String
    public var description: String { "ProbeComparison(redacted)" }
    public var debugDescription: String { description }
}
public enum ProbeModelError: Error { case noPairing, pairingExists, pairingUnavailable, staleConnection, invalidResponse, missingIdentity, randomUnavailable }

@MainActor public final class ProbeModel: ObservableObject {
    public let commandsAvailability = "Commands unavailable"
    @Published public private(set) var connectionID: UUID?
    @Published public private(set) var comparison: ProbeComparison?
    @Published public private(set) var storageEpoch: UUID?
    @Published public private(set) var status = "Disconnected"
    @Published public private(set) var errorMessage: String?
    @Published public private(set) var endpointAddress = ""
    @Published public private(set) var endpointPort: UInt16 = 49152
    @Published public private(set) var hasPairing = false
    private let identity: any ProbeIdentity
    private let pins: any ProbePinStore
    private let channels: any ProbeChannelFactory
    private let nonce: @MainActor () throws -> Data
    private var saved: PairedHostRecord?
    private var tentative: PairedHostRecord?
    private var invitation: Invitation?
    private var incarnation = UUID()
    private var channel: (any ProbeChannel)?
    private var connectingTask: Task<any ProbeChannel, Error>?
    private var receiveTask: Task<Void, Never>?
    private var hello: Hello?
    private var transcript: AuthTranscript?
    private var ownDigest: Data?
    private var authenticated = false
    private var accepted = false
    private var committed = false
    private var pinReadFailed = false

    public init(identity: any ProbeIdentity, pins: any ProbePinStore, channels: any ProbeChannelFactory,
                nonce: @escaping @MainActor () throws -> Data) {
        self.identity = identity; self.pins = pins; self.channels = channels; self.nonce = nonce
        do { saved = try pins.load(); showEndpoint(saved?.endpoint); hasPairing = saved != nil }
        catch { pinReadFailed = true; errorMessage = "Pairing unavailable: \(error)" }
    }
    public static func production() -> ProbeModel {
        let store = ProductionProbeStore()
        return ProbeModel(identity: store, pins: store, channels: NativeProbeChannels(), nonce: {
            var bytes = Data(count: 32)
            guard bytes.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else { throw ProbeModelError.randomUnavailable }
            return bytes
        })
    }
    public func enterInvitation(_ text: String) throws {
        guard !pinReadFailed else { throw ProbeModelError.pairingUnavailable }
        guard saved == nil else { errorMessage = "Forget the existing pairing before entering a new invitation."; throw ProbeModelError.pairingExists }
        do {
            let value = try Invitation.decode(text)
            disconnect()
            invitation = value
            tentative = try PairedHostRecord(hostID: value.hostID, hostPin: value.hostPin, endpoint: value.endpoint)
            showEndpoint(value.endpoint); hasPairing = true; errorMessage = nil
            status = "Invitation entered. Connect, then compare the code on the Mac."
        } catch { errorMessage = "Invalid invitation."; throw error }
    }
    /// Connect consumes an explicit invitation at most once. Later attempts are normal authentication.
    public func connect() async { await start(useInvitation: invitation != nil) }
    public func reconnect() async { await start(useInvitation: false) }
    public func disconnect(reason: String? = nil) {
        fence()
        status = "Disconnected"
        errorMessage = reason
    }
    public func suspended() { disconnect(reason: "Disconnected: probe is no longer in the foreground.") }
    public func editEndpoint(ipv4: String, port: UInt16) throws {
        let endpoint = try StatusEndpoint(ipv4: ipv4, port: port)
        guard let record = saved ?? tentative else { throw ProbeModelError.noPairing }
        disconnect()
        let edited = try PairedHostRecord(hostID: record.hostID, hostPin: record.hostPin, endpoint: endpoint)
        if saved != nil { saved = edited } else { tentative = edited }
        invitation = nil // An address edit never replays an enrollment.
        showEndpoint(endpoint)
    }
    public func forgetPairing() throws {
        // No await may separate fencing, validation and exact synchronous deletion.
        fence()
        let current = incarnation
        tentative = nil; invitation = nil; status = "Disconnected"
        guard current == incarnation else { throw ProbeModelError.staleConnection }
        do {
            try pins.forget()
            saved = nil; pinReadFailed = false; hasPairing = false; showEndpoint(nil); errorMessage = nil
        } catch {
            errorMessage = "Forget pairing failed; saved pairing may remain: \(error)"
            throw error
        }
    }
    private func fence() {
        incarnation = UUID()
        connectingTask?.cancel(); connectingTask = nil
        receiveTask?.cancel(); receiveTask = nil
        channel?.cancel(); channel = nil
        connectionID = nil; comparison = nil; storageEpoch = nil
        hello = nil; transcript = nil; ownDigest = nil; authenticated = false; accepted = false; committed = false
    }
    private func start(useInvitation: Bool) async {
        fence()
        let operation = incarnation
        errorMessage = nil; status = "Connecting"
        do {
            guard !pinReadFailed else { throw ProbeModelError.pairingUnavailable }
            guard let record = saved ?? tentative else { throw ProbeModelError.noPairing }
            let enrollment = useInvitation ? invitation : nil
            invitation = nil // Never retry enrollment automatically, even after failure/lost ACK.
            let point = try identity.prepareIdentity(allowCreation: saved == nil && enrollment != nil)
            let message = try Hello(mode: enrollment == nil ? .normal : .enrollment, hostID: record.hostID, hostPin: record.hostPin,
                                    controllerPoint: point, clientNonce: nonce(), invitationID: enrollment?.invitationID ?? .zero)
            let pending = Task { try await channels.connect(endpoint: record.endpoint, pin: record.hostPin) }
            connectingTask = pending
            let connected = try await pending.value
            guard incarnation == operation else { connected.cancel(); return }
            connectingTask = nil
            channel = connected; connectionID = connected.connectionID; hello = message
            let id = connected.connectionID
            try await connected.send(.hello(message))
            guard isCurrent(operation, id) else { connected.cancel(); return }
            status = "Authenticating"
            receiveTask = Task { [weak self, connected] in
                do {
                    try await connected.run { [weak self] frame, callbackID in
                        guard let self else { throw ProbeModelError.staleConnection }
                        return try self.handle(frame, operation: operation, connectionID: callbackID, record: record, secret: enrollment?.secret)
                    }
                    guard let self, self.isCurrent(operation, id) else { return }
                    let confirmed = self.committed
                    self.disconnect(reason: confirmed ? nil : "Disconnected: channel closed.")
                    if confirmed { self.status = "Mac confirmed. Reconnect to authenticate and save pairing." }
                } catch {
                    self?.failed(operation: operation, id: id, message: "Disconnected: \(error)")
                }
            }
        } catch {
            guard incarnation == operation else { return }
            disconnect(reason: "Connection failed: \(error)")
        }
    }
    private func isCurrent(_ operation: UUID, _ id: UUID) -> Bool { incarnation == operation && connectionID == id && channel?.connectionID == id }
    private func handle(_ frame: WireFrame, operation: UUID, connectionID id: UUID, record: PairedHostRecord, secret: Data?) throws -> WireFrame? {
        guard isCurrent(operation, id), let channel, let hello else { throw ProbeModelError.staleConnection }
        do {
            switch frame {
            case .challenge(let challenge):
                guard transcript == nil, !authenticated else { throw ProbeModelError.invalidResponse }
                let transcript = try AuthTranscript(hello: hello, challenge: challenge)
                let exporter = try channel.exporter(context: transcript.exporterContext())
                let proof = try identity.proof(transcript: transcript, exporter: exporter, secret: secret)
                self.transcript = transcript
                ownDigest = try transcript.claimDigest(exporter: exporter, signature: proof.signature, secretProof: proof.secretProof)
                return .proof(proof)
            case .candidateAccepted(let candidate):
                guard hello.mode == .enrollment, transcript != nil, !accepted, let secret,
                      let ownDigest, candidate.claimDigest == ownDigest else { throw ProbeModelError.invalidResponse }
                comparison = ProbeComparison(connectionID: id, claimDigest: ownDigest,
                    code: try comparisonCode(secret: secret, claimDigest: ownDigest, sasNonce: candidate.sasNonce))
                accepted = true; status = "Compare this code on the Mac and confirm there."
                return nil
            case .enrollmentCommitted(let committed):
                guard hello.mode == .enrollment, accepted, !self.committed, let ownDigest, committed.claimDigest == ownDigest else { throw ProbeModelError.invalidResponse }
                self.committed = true; comparison = nil
                status = "Mac confirmed. Reconnect to authenticate and save pairing."
                return nil
            case .authenticated(let result):
                guard hello.mode == .normal, let transcript, !authenticated,
                      result.controllerID == transcript.challenge.controllerID,
                      result.generation == transcript.challenge.generation else { throw ProbeModelError.invalidResponse }
                // This MainActor check and synchronous save are indivisible by another model action.
                guard isCurrent(operation, id) else { throw ProbeModelError.staleConnection }
                try pins.save(record)
                saved = record; tentative = nil; hasPairing = true; authenticated = true
                comparison = nil; status = "Connected; requesting status"
                return .statusRequest
            case .statusResponse(let response):
                guard authenticated else { throw ProbeModelError.invalidResponse }
                storageEpoch = response.storageEpoch; status = "Connected"
                return nil
            default: throw ProbeModelError.invalidResponse
            }
        } catch {
            failed(operation: operation, id: id, message: "Disconnected: invalid or refused response (\(error)).")
            throw error
        }
    }
    private func failed(operation: UUID, id: UUID, message: String) {
        guard isCurrent(operation, id) else { return }
        disconnect(reason: message)
    }
    private func showEndpoint(_ endpoint: StatusEndpoint?) { endpointAddress = endpoint?.ipv4 ?? ""; endpointPort = endpoint?.port ?? 49152 }
}

/// Internal seam replaces only Keychain IO, keeping the production identity policy in tests.
@MainActor protocol ProbeStoreBackend: AnyObject {
    func loadControllerIdentity() throws -> SecKey?
    func createControllerIdentityIfAbsent() throws -> SecKey
    func loadPairedHost() throws -> PairedHostRecord?
    func savePairedHost(_ record: PairedHostRecord) throws
    func forgetPairedHost() throws
}
@MainActor private final class SystemProbeStoreBackend: ProbeStoreBackend {
    private let store = PrototypeKeyStore()
    func loadControllerIdentity() throws -> SecKey? { try store.loadIdentity(role: .controller) }
    func createControllerIdentityIfAbsent() throws -> SecKey { try store.createIdentityIfAbsent(role: .controller) }
    func loadPairedHost() throws -> PairedHostRecord? { try store.loadPairedHost() }
    func savePairedHost(_ record: PairedHostRecord) throws { try store.savePairedHost(record) }
    func forgetPairedHost() throws { try store.forgetPairedHost() }
}
@MainActor final class ProductionProbeStore: ProbeIdentity, ProbePinStore {
    // Constructed and used solely on MainActor; no unchecked transfer of KeyStore.
    private let store: any ProbeStoreBackend
    private var key: SecKey?
    convenience init() { self.init(backend: SystemProbeStoreBackend()) }
    init(backend: any ProbeStoreBackend) { store = backend }
    func prepareIdentity(allowCreation: Bool) throws -> Data {
        // Every connection loads the retained item, including normal retry after a
        // lost ACK. Only an explicit fresh enrollment may create an absent key.
        key = nil
        let selected: SecKey
        if let existing = try store.loadControllerIdentity() { selected = existing }
        else {
            guard allowCreation else { throw ProbeModelError.missingIdentity }
            selected = try store.createControllerIdentityIfAbsent()
        }
        guard let publicKey = SecKeyCopyPublicKey(selected), let point = SecKeyCopyExternalRepresentation(publicKey, nil) else { throw ProbeModelError.missingIdentity }
        key = selected
        return point as Data
    }
    func proof(transcript: AuthTranscript, exporter: Data, secret: Data?) throws -> Proof {
        // Proof uses exactly the key prepared for Hello; it never creates or
        // switches identity after the transcript has fixed the public point.
        guard let key else { throw ProbeModelError.missingIdentity }
        return try PeerAuthentication.makeProof(transcript: transcript, exporter: exporter, key: key, invitationSecret: secret)
    }
    func load() throws -> PairedHostRecord? { try store.loadPairedHost() }
    func save(_ record: PairedHostRecord) throws { try store.savePairedHost(record) }
    func forget() throws { try store.forgetPairedHost() }
}
@MainActor private final class NativeProbeChannels: ProbeChannelFactory {
    func connect(endpoint: StatusEndpoint, pin: Data) async throws -> any ProbeChannel {
        let channel = try await StatusTLSChannel.connect(endpoint: endpoint, pin: pin)
        return try NativeProbeChannel(channel)
    }
}
@MainActor private final class NativeProbeChannel: ProbeChannel {
    let channel: StatusTLSChannel
    let pump = ConnectionPump(role: .controller)
    var connectionID: UUID { channel.connectionID }
    init(_ channel: StatusTLSChannel) throws { self.channel = channel; try pump.accept(channel) }
    func exporter(context: Data) throws -> Data { try channel.exporter(context: context) }
    func send(_ frame: WireFrame) async throws { try await pump.send(frame, over: connectionID) }
    func run(dispatch: @escaping @MainActor @Sendable (WireFrame, UUID) async throws -> WireFrame?) async throws {
        try await pump.run(connectionID: connectionID) { frame, id in try await dispatch(frame, id) }
    }
    func cancel() { pump.closeAll(); channel.cancel() }
}
