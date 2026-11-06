import Foundation
import Network
import Security
import Darwin
import RemotePrototypeWire

/// A reusable continuous-time origin shared with an injected Core StatusClock.
public enum StatusTLSClock {
    public static func nowNanoseconds() -> UInt64 { continuousNanoseconds() }
}

/// Serial-owner lifecycle used by the native listener. Presence changes invalidate
/// the listener and all accepted channels before any attempt to rebind.
final class ExactAddressLifecycle {
    let endpoint: StatusEndpoint
    private let present: (StatusEndpoint) -> Bool
    private let bind: (StatusEndpoint) throws -> Void
    private let stop: () -> Void
    private var active = false
    private var cancelled = false
    init(endpoint: StatusEndpoint, present: @escaping (StatusEndpoint) -> Bool,
         bind: @escaping (StatusEndpoint) throws -> Void, stop: @escaping () -> Void) throws {
        guard present(endpoint) else { throw StatusTLSError.unavailableAddress }
        self.endpoint = endpoint; self.present = present; self.bind = bind; self.stop = stop
    }
    func refresh() throws {
        guard !cancelled else { return }
        guard present(endpoint) else { invalidate(); return }
        if !active { try bind(endpoint); active = true }
    }
    func invalidate() { if active { active = false; stop() } }
    func cancel() { cancelled = true; invalidate() }
}

// The native monitor combines path notifications with address-presence polling:
// path viability alone does not identify loss of one exact interface address.
protocol StatusTLSAddressMonitor: Sendable {
    func start(queue: DispatchQueue, onChange: @escaping @Sendable () -> Void)
    func cancel()
}
private final class NativeAddressMonitor: StatusTLSAddressMonitor, @unchecked Sendable {
    private var timer: DispatchSourceTimer?
    private var monitor: NWPathMonitor?
    // Owned exclusively by the listener queue.
    func start(queue: DispatchQueue, onChange: @escaping @Sendable () -> Void) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250))
        timer.setEventHandler(handler: onChange)
        self.timer = timer; timer.resume()
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { _ in onChange() }
        self.monitor = monitor; monitor.start(queue: queue)
    }
    func cancel() { timer?.cancel(); timer = nil; monitor?.cancel(); monitor = nil }
    deinit { timer?.cancel(); monitor?.cancel() }
}

/// Native listener for one explicit saved tailnet address. No wildcard, resolver,
/// address substitution, or default interface route exists in the public API.
public final class StatusTLSListener: @unchecked Sendable {
    private let queue = DispatchQueue(label: "org.openminis.prototype.tls-listener")
    private let identity: SecIdentity
    private let onAccept: @Sendable (StatusTLSChannel) -> Void
    private let onAvailability: @Sendable (Bool) -> Void
    private var available = false
    private let now: @Sendable () -> UInt64
    private let endpoint: StatusEndpoint?
    private let loopback: Bool
    private let present: @Sendable (StatusEndpoint) -> Bool
    private let addressMonitor: any StatusTLSAddressMonitor
    private var listener: NWListener?
    private var generation = UUID()
    private var channels: [UUID: StatusTLSChannel] = [:]
    private var lifecycle: ExactAddressLifecycle?
    private var startWaiter: CheckedContinuation<UInt16, Error>?
    private var boundPort: UInt16?
    private var started = false
    private var cancelled = false
    private let cancelLock = NSLock()
    private var cancelRequested = false

    public convenience init(endpoint: StatusEndpoint, identity: SecIdentity,
                            onAvailability: @escaping @Sendable (Bool) -> Void = { _ in },
                            onAccept: @escaping @Sendable (StatusTLSChannel) -> Void) throws {
        guard Self.addressPresent(endpoint) else { throw StatusTLSError.unavailableAddress }
        self.init(endpoint: endpoint, identity: identity, loopback: false,
                  now: StatusTLSClock.nowNanoseconds, present: Self.addressPresent, monitor: NativeAddressMonitor(), onAvailability: onAvailability, onAccept: onAccept)
    }
    private init(endpoint: StatusEndpoint?, identity: SecIdentity, loopback: Bool,
                 now: @escaping @Sendable () -> UInt64,
                 present: @escaping @Sendable (StatusEndpoint) -> Bool, monitor: any StatusTLSAddressMonitor,
                 onAvailability: @escaping @Sendable (Bool) -> Void = { _ in },
                 onAccept: @escaping @Sendable (StatusTLSChannel) -> Void) {
        self.endpoint = endpoint; self.identity = identity; self.loopback = loopback
        self.now = now; self.onAccept = onAccept; self.onAvailability = onAvailability
        self.present = present; self.addressMonitor = monitor
    }
    // Internal-only disposable acceptance path: shipping endpoint policy is unchanged.
    static func loopback(identity: SecIdentity, now: @escaping @Sendable () -> UInt64 = StatusTLSClock.nowNanoseconds,
                         selectedEndpoint: StatusEndpoint? = nil,
                         present: @escaping @Sendable (StatusEndpoint) -> Bool = { _ in true },
                         monitor: any StatusTLSAddressMonitor = NativeAddressMonitor(),
                         onAccept: @escaping @Sendable (StatusTLSChannel) -> Void) throws -> StatusTLSListener {
        if let selectedEndpoint, !present(selectedEndpoint) { throw StatusTLSError.unavailableAddress }
        return StatusTLSListener(endpoint: selectedEndpoint, identity: identity, loopback: true,
                                 now: now, present: present, monitor: monitor, onAccept: onAccept)
    }
    /// Returns the actual listening port (ephemeral only for internal loopback fixtures).
    public func start() async throws -> UInt16 {
        do {
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    queue.async { [self] in
                        guard !isCancellationRequested else { continuation.resume(throwing: StatusTLSError.closed); return }
                        if let boundPort { continuation.resume(returning: boundPort); return }
                        guard !started else { continuation.resume(throwing: StatusTLSError.busy); return }
                        started = true; startWaiter = continuation
                        do {
                            if let endpoint {
                                lifecycle = try ExactAddressLifecycle(endpoint: endpoint, present: present,
                                    bind: { [weak self] saved in
                                        guard let self else { return }
                                        try bind(address: loopback ? .loopback : IPv4Address(saved.ipv4)!,
                                                 port: loopback ? .any : NWEndpoint.Port(rawValue: saved.port)!)
                                    }, stop: { [weak self] in self?.stopResources() })
                                try lifecycle?.refresh()
                                addressMonitor.start(queue: queue) { [weak self] in self?.refreshPresence() }
                            } else if loopback { try bind(address: .loopback, port: .any) }

                        } catch { failStart(error) }
                    }
                }
            } onCancel: { cancel() }
        } catch {
            if error as? StatusTLSError != .busy { cancel() }
            throw error
        }
    }
    public func cancel() {
        cancelLock.withLock { cancelRequested = true }
        queue.async { [self] in
            guard !cancelled else { return }
            cancelled = true
            addressMonitor.cancel()
            lifecycle?.cancel()
            stopResources()
            failStart(StatusTLSError.closed)
        }
    }
    private var isCancellationRequested: Bool { cancelLock.withLock { cancelRequested } }
    private func refreshPresence() {
        guard !isCancellationRequested else { return }
        do { try lifecycle?.refresh() } catch { failStart(error) }
    }
    private func bind(address: IPv4Address, port: NWEndpoint.Port) throws {
        guard !isCancellationRequested else { throw StatusTLSError.closed }
        let parameters = NWParameters(tls: try PinnedTLS.serverOptions(identity: identity))
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(address), port: port)
        let newListener = try NWListener(using: parameters, on: port)
        let id = UUID(); generation = id
        listener = newListener
        newListener.newConnectionHandler = { [weak self] connection in
            // Capture trusted metadata before TLS start, user callbacks or owner work.
            guard let self else { connection.cancel(); return }
            let acceptedAt = now()
            let connectionID = UUID()
            guard !isCancellationRequested, generation == id,
                  endpoint.map(present) ?? loopback else {
                connection.cancel(); refreshPresence(); return
            }
            let native = NativeTLSChannel(connection: connection, acceptedAtNanoseconds: acceptedAt, onClose: { [weak self] in
                guard let self else { return }
                queue.async { [self] in channels.removeValue(forKey: connectionID) }
            })
            let channel = StatusTLSChannel(connectionID: connectionID, acceptedAtNanoseconds: acceptedAt, backend: native)
            channels[connectionID] = channel
            onAccept(channel)
            native.start()
        }
        newListener.stateUpdateHandler = { [weak self, weak newListener] state in
            guard let self, generation == id, !isCancellationRequested else { return }
            switch state {
            case .ready:
                guard let port = newListener?.port?.rawValue else { failStart(StatusTLSError.closed); return }
                boundPort = port
                if !available { available = true; onAvailability(true) }
                let waiter = startWaiter; startWaiter = nil; waiter?.resume(returning: port)
            case .failed(let error), .waiting(let error):
                lifecycle?.invalidate(); stopResources(); failStart(error)
            default: break
            }
        }
        newListener.start(queue: queue)
    }
    private func stopResources() {
        if available { available = false; onAvailability(false) }
        generation = UUID()
        listener?.cancel(); listener = nil; boundPort = nil
        let closing = channels.values
        channels.removeAll()
        for channel in closing { channel.cancel() }
    }
    private func failStart(_ error: any Error) {
        let waiter = startWaiter; startWaiter = nil; waiter?.resume(throwing: error)
    }
    private static func addressPresent(_ endpoint: StatusEndpoint) -> Bool {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return false }
        defer { freeifaddrs(list) }
        var current = list
        while let entry = current {
            defer { current = entry.pointee.ifa_next }
            guard let address = entry.pointee.ifa_addr,
                  address.pointee.sa_family == UInt8(AF_INET),
                  entry.pointee.ifa_flags & UInt32(IFF_UP) != 0 else { continue }
            var ipv4 = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            if inet_ntop(AF_INET, &ipv4, &buffer, socklen_t(buffer.count)) != nil,
               String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self) == endpoint.ipv4 { return true }
        }
        return false
    }
    deinit {
        listener?.cancel(); addressMonitor.cancel()
        for channel in channels.values { channel.cancel() }
    }
}
