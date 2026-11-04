import Foundation
import Network
import Security
import Darwin
import RemotePrototypeWire

/// Internal seam for deterministic pump fixtures; shipping channels always use Network.
protocol StatusTLSChannelBackend: Sendable {
    func ready() async throws
    func receive(maximumBytes: Int) async throws -> Data
    func send(_ data: Data) async throws
    func exporter(context: Data) throws -> Data
    func cancel()
}

/// One TLS byte stream. At most one bounded read and one bounded send may be pending.
/// Framing, authentication and RPC state belong to ConnectionPump, not this adapter.
public final class StatusTLSChannel: Sendable {
    public let connectionID: UUID
    public let acceptedAtNanoseconds: UInt64
    private let backend: any StatusTLSChannelBackend

    init(connectionID: UUID = UUID(), acceptedAtNanoseconds: UInt64, backend: any StatusTLSChannelBackend) {
        self.connectionID = connectionID
        self.acceptedAtNanoseconds = acceptedAtNanoseconds
        self.backend = backend
    }
    public func ready() async throws { try await backend.ready() }
    public func receive(maximumBytes: Int) async throws -> Data {
        guard (1...4100).contains(maximumBytes) else { throw StatusTLSError.invalidSize }
        return try await backend.receive(maximumBytes: maximumBytes)
    }
    public func send(_ data: Data) async throws {
        guard (1...4100).contains(data.count) else { throw StatusTLSError.invalidSize }
        try await backend.send(data)
    }
    public func exporter(context: Data) throws -> Data {
        guard context.count == AuthTranscript.exporterLength else { throw StatusTLSError.invalidContext }
        return try backend.exporter(context: context)
    }
    public func cancel() { backend.cancel() }

    public static func connect(endpoint: StatusEndpoint, pin: Data) async throws -> StatusTLSChannel {
        try await connect(host: .ipv4(IPv4Address(endpoint.ipv4)!), port: NWEndpoint.Port(rawValue: endpoint.port)!, pin: pin)
    }
    // No public initializer accepts a hostname, wildcard or alternate address.
    static func connectLoopback(port: UInt16, pin: Data) async throws -> StatusTLSChannel {
        try await connect(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: port)!, pin: pin)
    }
    private static func connect(host: NWEndpoint.Host, port: NWEndpoint.Port, pin: Data) async throws -> StatusTLSChannel {
        let connection = NWConnection(host: host, port: port, using: NWParameters(tls: try PinnedTLS.clientOptions(pin: pin)))
        let acceptedAt = StatusTLSClock.nowNanoseconds()
        let native = NativeTLSChannel(connection: connection, acceptedAtNanoseconds: acceptedAt)
        let channel = StatusTLSChannel(acceptedAtNanoseconds: acceptedAt, backend: native)
        native.start()
        do { try await channel.ready(); return channel }
        catch { channel.cancel(); throw error }
    }
}

/// Fixed continuous-clock budget shared by native handshake and send completion.
struct ContinuousTLSDeadline {
    private let end: UInt64
    init(start: UInt64) throws {
        let (end, overflow) = start.addingReportingOverflow(10_000_000_000)
        guard !overflow else { throw StatusTLSError.timedOut }
        self.end = end
    }
    func check(now: UInt64) throws {
        guard now < end else { throw StatusTLSError.timedOut }
    }
}

// All protocol and continuation state is owned by queue. The separate cancellation
// latch makes cancel visible synchronously, before any queued callback can send bytes.
final class NativeTLSChannel: StatusTLSChannelBackend, @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "org.openminis.prototype.tls-channel")
    private let cancellation = NSLock()
    private var cancelled = false
    private var started = false
    private var isReady = false
    private var failure: (any Error)?
    private var readyWaiter: CheckedContinuation<Void, Error>?
    private var readWaiter: CheckedContinuation<Data, Error>?
    private var sendWaiter: CheckedContinuation<Void, Error>?
    private var sendTimer: DispatchSourceTimer?
    private var handshakeTimer: DispatchSourceTimer?
    private var sendID: UUID?
    private let onClose: @Sendable () -> Void
    private let acceptedAtNanoseconds: UInt64
    private var handshakeDeadline: ContinuousTLSDeadline?

    init(connection: NWConnection, acceptedAtNanoseconds: UInt64 = StatusTLSClock.nowNanoseconds(),
         onClose: @escaping @Sendable () -> Void = {}) {
        self.connection = connection; self.acceptedAtNanoseconds = acceptedAtNanoseconds; self.onClose = onClose
    }
    private var isCancelled: Bool { cancellation.withLock { cancelled } }
    func start() {
        queue.async { [self] in
            guard !started, !isCancelled else { finish(StatusTLSError.closed); return }
            started = true
            connection.stateUpdateHandler = { [weak self] state in self?.stateChanged(state) }
            do {
                let deadline = try ContinuousTLSDeadline(start: acceptedAtNanoseconds)
                try deadline.check(now: StatusTLSClock.nowNanoseconds())
                handshakeDeadline = deadline
                handshakeTimer = deadlineTimer(deadline)
            } catch { finish(error); return }
            connection.start(queue: queue)
        }
    }
    func ready() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                queue.async { [self] in
                    if let error = currentFailure { continuation.resume(throwing: error) }
                    else if isReady { continuation.resume() }
                    else if readyWaiter != nil { continuation.resume(throwing: StatusTLSError.busy) }
                    else { readyWaiter = continuation }
                }
            }
        } onCancel: { cancel() }
    }
    func receive(maximumBytes: Int) async throws -> Data {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                queue.async { [self] in
                    if let error = currentFailure { continuation.resume(throwing: error); return }
                    guard isReady else { continuation.resume(throwing: StatusTLSError.closed); return }
                    guard readWaiter == nil else { continuation.resume(throwing: StatusTLSError.busy); return }
                    readWaiter = continuation
                    connection.receive(minimumIncompleteLength: 1, maximumLength: maximumBytes) { [weak self] data, _, complete, error in
                        guard let self, let waiter = readWaiter else { return }
                        readWaiter = nil
                        if let error = currentFailure ?? error { waiter.resume(throwing: error); finish(error) }
                        else if let data, !data.isEmpty {
                            waiter.resume(returning: data)
                            if complete { finish(StatusTLSError.closed) }
                        } else { waiter.resume(throwing: StatusTLSError.closed); finish(StatusTLSError.closed) }
                    }
                }
            }
        } onCancel: { cancel() }
    }
    func send(_ data: Data) async throws {
        let deadline = try ContinuousTLSDeadline(start: StatusTLSClock.nowNanoseconds())
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                queue.async { [self] in
                    if let error = currentFailure { continuation.resume(throwing: error); return }
                    guard isReady else { continuation.resume(throwing: StatusTLSError.closed); return }
                    guard sendWaiter == nil else { continuation.resume(throwing: StatusTLSError.busy); return }
                    do { try deadline.check(now: StatusTLSClock.nowNanoseconds()) }
                    catch { continuation.resume(throwing: error); finish(error); return }
                    let id = UUID()
                    sendID = id
                    sendWaiter = continuation
                    sendTimer = deadlineTimer(deadline)
                    connection.send(content: data, completion: .contentProcessed { [weak self] error in
                        guard let self, sendID == id, let waiter = sendWaiter else { return }
                        sendWaiter = nil
                        sendID = nil
                        sendTimer?.cancel(); sendTimer = nil
                        if let error = currentFailure ?? error { waiter.resume(throwing: error); finish(error) }
                        else {
                            do { try deadline.check(now: StatusTLSClock.nowNanoseconds()); waiter.resume() }
                            catch { waiter.resume(throwing: error); finish(error) }
                        }
                    })
                }
            }
        } onCancel: { cancel() }
    }
    func exporter(context: Data) throws -> Data {
        try queue.sync {
            if let error = currentFailure { throw error }
            guard isReady, context.count == 32,
                  let metadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else { throw StatusTLSError.exporterUnavailable }
            let exported = context.withUnsafeBytes { bytes in
                AuthTranscript.exporterLabel.withCString { label in
                    sec_protocol_metadata_create_secret_with_context(metadata.securityProtocolMetadata,
                        AuthTranscript.exporterLabel.utf8.count, label, context.count,
                        bytes.bindMemory(to: UInt8.self).baseAddress!, AuthTranscript.exporterLength)
                }
            }
            guard let exported else { throw StatusTLSError.exporterUnavailable }
            let result = Data(exported as DispatchData)
            guard result.count == 32 else { throw StatusTLSError.exporterUnavailable }
            return result
        }
    }
    func cancel() {
        cancellation.withLock { cancelled = true }
        // Network cancellation is thread safe. Do it before scheduling continuation cleanup.
        connection.cancel()
        queue.async { [self] in finish(StatusTLSError.closed) }
    }
    private var currentFailure: (any Error)? { isCancelled ? StatusTLSError.closed : failure }
    private func stateChanged(_ state: NWConnection.State) {
        switch state {
        case .ready:
            do {
                guard let handshakeDeadline else { throw StatusTLSError.closed }
                try handshakeDeadline.check(now: StatusTLSClock.nowNanoseconds())
            } catch { finish(error); return }
            guard currentFailure == nil,
                  let metadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata,
                  sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata.securityProtocolMetadata) == .TLSv13,
                  !sec_protocol_metadata_get_early_data_accepted(metadata.securityProtocolMetadata),
                  negotiatedProtocol(metadata.securityProtocolMetadata) == PinnedTLS.applicationProtocol else {
                finish(StatusTLSError.incompatibleTLS); return
            }
            isReady = true
            handshakeTimer?.cancel(); handshakeTimer = nil
            let waiter = readyWaiter; readyWaiter = nil; waiter?.resume()
        case .failed(let error): finish(error)
        case .cancelled: finish(StatusTLSError.closed)
        case .waiting(let error): finish(error)
        default: break
        }
    }
    private func deadlineTimer(_ deadline: ContinuousTLSDeadline) -> DispatchSourceTimer {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        // Dispatch uptime deadlines exclude sleep. Poll the continuous deadline,
        // and check again at completion, so sleep cannot extend the budget.
        timer.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250))
        timer.setEventHandler { [weak self] in
            do { try deadline.check(now: StatusTLSClock.nowNanoseconds()) }
            catch { self?.finish(error) }
        }
        timer.resume()
        return timer
    }
    private func finish(_ error: any Error) {
        guard failure == nil else { return }
        failure = error
        isReady = false
        connection.cancel()
        handshakeTimer?.cancel(); handshakeTimer = nil
        sendTimer?.cancel(); sendTimer = nil; sendID = nil
        let ready = readyWaiter; readyWaiter = nil
        let read = readWaiter; readWaiter = nil
        let send = sendWaiter; sendWaiter = nil
        ready?.resume(throwing: error); read?.resume(throwing: error); send?.resume(throwing: error)
        onClose()
    }
    deinit { connection.cancel(); handshakeTimer?.cancel(); sendTimer?.cancel() }
}

private func negotiatedProtocol(_ metadata: sec_protocol_metadata_t) -> String? {
    if #available(macOS 15.5, iOS 18.5, *) {
        guard let value = sec_protocol_metadata_copy_negotiated_protocol(metadata) else { return nil }
        defer { free(UnsafeMutableRawPointer(mutating: value)) }
        return String(cString: value)
    }
    guard let value = sec_protocol_metadata_get_negotiated_protocol(metadata) else { return nil }
    return String(cString: value)
}

func continuousNanoseconds() -> UInt64 {
    // mach_continuous_time includes sleep, unlike DispatchTime's uptime clock.
    var info = mach_timebase_info_data_t()
    mach_timebase_info(&info)
    let ticks = mach_continuous_time()
    let numerator = UInt64(info.numer), denominator = UInt64(info.denom)
    return (ticks / denominator) * numerator + (ticks % denominator) * numerator / denominator
}
