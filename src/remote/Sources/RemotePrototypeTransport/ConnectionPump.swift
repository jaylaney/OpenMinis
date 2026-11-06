import Foundation
import RemotePrototypeWire

protocol ConnectionPumpTimer: Sendable { func cancel() }
protocol ConnectionPumpTimers: Sendable {
    /// Must not invoke action inline. Cancellation may race a callback.
    func schedule(deadlineNanoseconds: UInt64, _ action: @escaping @Sendable () -> Void) -> any ConnectionPumpTimer
}

public enum ConnectionPumpError: Error, Equatable, Sendable {
    case capacity, closed, busy, wrongState, timedOut
}

/// Bounded byte-stream/protocol owner. This type grants no authentication authority:
/// only a trusted dispatch bridge may produce successful proof responses.
public final class ConnectionPump: @unchecked Sendable {
    public enum Role: Sendable { case host, controller }
    private enum State {
        case hostHello, hostChallenge(HandshakeMode), hostProof(HandshakeMode), hostProofPending(HandshakeMode)
        case hostCandidateUnsent, hostCandidate, hostAuthenticated, hostStatus
        case controllerHello, controllerChallenge(HandshakeMode), controllerProof(HandshakeMode), controllerResult(HandshakeMode)
        case controllerCandidate, controllerAuthenticated, controllerStatus, finished
    }
    private final class Entry: @unchecked Sendable {
        let channel: StatusTLSChannel
        var state: State
        var pending = true
        var running = false
        var sending = false
        var deadline: UInt64?
        var deadlineID = UUID()
        var timer: (any ConnectionPumpTimer)?
        var sendTimer: (any ConnectionPumpTimer)?
        var sendID = UUID()
        init(_ channel: StatusTLSChannel, state: State) { self.channel = channel; self.state = state }
        func cancel() { timer?.cancel(); sendTimer?.cancel(); channel.cancel() }
    }
    private let role: Role
    private let lock = NSLock()
    private var entries: [UUID: Entry] = [:]
    private let now: @Sendable () -> UInt64
    private let timers: any ConnectionPumpTimers

    public convenience init(role: Role) {
        self.init(role: role, now: { StatusTLSClock.nowNanoseconds() }, timers: ContinuousPumpTimers())
    }
    init(role: Role, now: @escaping @Sendable () -> UInt64, timers: any ConnectionPumpTimers) {
        self.role = role; self.now = now; self.timers = timers
    }

    public func accept(_ channel: StatusTLSChannel) throws {
        do {
            try lock.withLock {
                guard entries[channel.connectionID] == nil else { throw ConnectionPumpError.busy }
                guard entries.values.filter({ $0.pending }).count < 2 else { throw ConnectionPumpError.capacity }
                let deadline = try addingBudget(to: channel.acceptedAtNanoseconds, budget: 10_000_000_000)
                guard now() < deadline else { throw ConnectionPumpError.timedOut }
                let entry = Entry(channel, state: role == .host ? .hostHello : .controllerHello)
                entries[channel.connectionID] = entry
                setDeadline(deadline, entry: entry)
            }
        } catch { channel.cancel(); throw error }
    }

    /// Trusted host bridge only: after owner acceptance, pass the ORIGINAL window
    /// deadline. Never use a peer value. Single-use; cannot revive an expired proof.
    public func retainCandidate(connectionID: UUID, untilNanoseconds: UInt64) throws {
        do {
            try lock.withLock {
                let entry = try live(connectionID)
                guard role == .host, case .hostProofPending(.enrollment) = entry.state else { throw ConnectionPumpError.wrongState }
                guard now() < untilNanoseconds else { throw ConnectionPumpError.timedOut }
                entry.state = .hostCandidateUnsent
                setDeadline(untilNanoseconds, entry: entry)
            }
        } catch { close(connectionID: connectionID); throw error }
    }

    public func run(connectionID: UUID, dispatch: @Sendable (WireFrame, UUID) async throws -> WireFrame?) async throws {
        let entry: Entry
        do {
            entry = try lock.withLock {
                let entry = try live(connectionID)
                guard !entry.running else { throw ConnectionPumpError.busy }
                entry.running = true
                return entry
            }
        } catch { close(connectionID: connectionID); throw error }
        do {
            try await withTaskCancellationHandler {
                try await entry.channel.ready()
                var decoder = FrameDecoder()
                while true {
                    try check(entry)
                    // Input suffix plus partial decoder state never exceeds 4100 bytes.
                    let bytes = try await entry.channel.receive(maximumBytes: 4100 - decoder.bufferedByteCount)
                    guard !bytes.isEmpty, bytes.count <= 4100 - decoder.bufferedByteCount else { throw ConnectionPumpError.closed }
                    var offset = 0
                    while offset < bytes.count {
                        try check(entry)
                        let step = try decoder.consume(Data(bytes.dropFirst(offset)))
                        offset += step.bytesConsumed
                        guard let frame = step.frame else { continue }
                        try lock.withLock {
                            try requireLive(entry)
                            // A suffix delivered with a client request was already pipelined
                            // before its response. Awaiting dispatch cannot legalize it.
                            if offset < bytes.count {
                                if role == .host { throw ConnectionPumpError.wrongState }
                                // Challenge, authentication, and each snapshot require a
                                // new client message before a subsequent result/snapshot.
                                // Dispatch cannot legitimize bytes delivered before it.
                                // CandidateAccepted -> EnrollmentCommitted needs no
                                // intervening client message and remains coalescible.
                                switch frame {
                                case .challenge, .authenticated, .statusResponse:
                                    throw ConnectionPumpError.wrongState
                                default: break
                                }
                            }
                            try transition(frame, incoming: true, entry: entry)
                        }
                        let response = try await dispatch(frame, connectionID)
                        try check(entry) // close/replacement during dispatch drops late output
                        if let response { try await send(response, entry: entry) }
                        let finished = lock.withLock { if case .finished = entry.state { return true }; return false }
                        if finished { close(entry); return }
                    }
                }
            } onCancel: { self.close(entry) }
        } catch { close(entry); throw error }
    }

    public func send(_ frame: WireFrame, over connectionID: UUID) async throws {
        let entry: Entry
        do { entry = try lock.withLock { try live(connectionID) } }
        catch { close(connectionID: connectionID); throw error }
        try await send(frame, entry: entry)
    }
    private func send(_ frame: WireFrame, entry: Entry) async throws {
        do {
            let bytes = try frame.encode()
            let sendDeadline = try addingBudget(to: now(), budget: 10_000_000_000)
            try lock.withLock {
                try requireLive(entry)
                guard !entry.sending else { throw ConnectionPumpError.busy }
                try transition(frame, incoming: false, entry: entry)
                entry.sending = true
                let sendID = UUID(); entry.sendID = sendID
                entry.sendTimer = timers.schedule(deadlineNanoseconds: sendDeadline) { [weak self, weak entry] in
                    guard let self, let entry else { return }
                    self.expire(entry) { entry.sending && entry.sendID == sendID && self.now() >= sendDeadline }
                }
            }
            try await withTaskCancellationHandler {
                try await entry.channel.send(bytes)
            } onCancel: { self.close(entry) }
            let finished = try lock.withLock {
                try requireLive(entry)
                guard now() < sendDeadline else { throw ConnectionPumpError.timedOut }
                entry.sendTimer?.cancel(); entry.sendTimer = nil; entry.sending = false
                switch entry.state {
                case .hostAuthenticated: authenticated(entry)
                case .finished: return true
                default: break
                }
                return false
            }
            if finished { close(entry) }
        } catch { close(entry); throw error }
    }

    /// Synchronous, thread-safe cancellation only. No owner/store/UI work occurs here.
    public func close(connectionID: UUID) {
        let entry = lock.withLock { entries.removeValue(forKey: connectionID) }
        entry?.cancel()
    }
    public func closeAll() {
        let removed = lock.withLock { let all = Array(entries.values); entries.removeAll(); return all }
        for entry in removed { entry.cancel() }
    }
    private func close(_ entry: Entry) {
        let removed = lock.withLock { () -> Entry? in
            guard entries[entry.channel.connectionID] === entry else { return nil }
            return entries.removeValue(forKey: entry.channel.connectionID)
        }
        removed?.cancel()
    }
    private func expire(_ entry: Entry, when condition: () -> Bool) {
        let removed = lock.withLock { () -> Entry? in
            guard entries[entry.channel.connectionID] === entry, condition() else { return nil }
            return entries.removeValue(forKey: entry.channel.connectionID)
        }
        removed?.cancel()
    }
    private func check(_ entry: Entry) throws { try lock.withLock { try requireLive(entry) } }
    private func live(_ id: UUID) throws -> Entry {
        guard let entry = entries[id] else { throw ConnectionPumpError.closed }
        try requireLive(entry); return entry
    }
    private func requireLive(_ entry: Entry) throws {
        guard entries[entry.channel.connectionID] === entry else { throw ConnectionPumpError.closed }
        if let deadline = entry.deadline, now() >= deadline { throw ConnectionPumpError.timedOut }
    }
    private func addingBudget(to start: UInt64, budget: UInt64) throws -> UInt64 {
        let (end, overflow) = start.addingReportingOverflow(budget)
        guard !overflow else { throw ConnectionPumpError.timedOut }; return end
    }
    // Called under lock; timer callbacks recheck both identity and the active deadline.
    private func setDeadline(_ end: UInt64, entry: Entry) {
        entry.timer?.cancel(); entry.deadline = end
        let id = UUID(); entry.deadlineID = id
        entry.timer = timers.schedule(deadlineNanoseconds: end) { [weak self, weak entry] in
            guard let self, let entry else { return }
            self.expire(entry) { entry.deadlineID == id && self.now() >= end }
        }
    }
    private func authenticated(_ entry: Entry) {
        entry.pending = false; entry.deadline = nil; entry.deadlineID = UUID()
        entry.timer?.cancel(); entry.timer = nil
    }
    private func transition(_ frame: WireFrame, incoming: Bool, entry: Entry) throws {
        // Refusal never grants progress or another attempt.
        if case .refused = frame {
            guard (role == .controller) == incoming else { throw ConnectionPumpError.wrongState }
            switch entry.state { case .finished: throw ConnectionPumpError.wrongState; default: entry.state = .finished; return }
        }
        switch (entry.state, incoming, frame) {
        case (.hostHello, true, .hello(let hello)): entry.state = .hostChallenge(hello.mode)
        case (.hostChallenge(let mode), false, .challenge(let challenge)):
            try challenge.validate(mode: mode); entry.state = .hostProof(mode)
        case (.hostProof(let mode), true, .proof(let proof)):
            try proof.validate(mode: mode); entry.state = .hostProofPending(mode)
        case (.hostCandidateUnsent, false, .candidateAccepted): entry.state = .hostCandidate
        case (.hostCandidate, false, .enrollmentCommitted): entry.state = .finished
        case (.hostProofPending(.normal), false, .authenticated): entry.state = .hostAuthenticated
        case (.hostAuthenticated, true, .statusRequest): entry.state = .hostStatus
        case (.hostStatus, false, .statusResponse): entry.state = .hostAuthenticated
        case (.controllerHello, false, .hello(let hello)): entry.state = .controllerChallenge(hello.mode)
        case (.controllerChallenge(let mode), true, .challenge(let challenge)):
            try challenge.validate(mode: mode); entry.state = .controllerProof(mode)
        case (.controllerProof(let mode), false, .proof(let proof)):
            try proof.validate(mode: mode); entry.state = .controllerResult(mode)
        case (.controllerResult(.enrollment), true, .candidateAccepted):
            // The wire does not reveal the host window origin. This local ceiling
            // is conservative; the host enforces its exact original deadline.
            let end = try addingBudget(to: entry.channel.acceptedAtNanoseconds, budget: 120_000_000_000)
            guard now() < end else { throw ConnectionPumpError.timedOut }
            entry.state = .controllerCandidate; setDeadline(end, entry: entry)
        case (.controllerCandidate, true, .enrollmentCommitted): entry.state = .finished
        case (.controllerResult(.normal), true, .authenticated): entry.state = .controllerAuthenticated; authenticated(entry)
        case (.controllerAuthenticated, false, .statusRequest): entry.state = .controllerStatus
        case (.controllerStatus, true, .statusResponse): entry.state = .controllerAuthenticated
        default: throw ConnectionPumpError.wrongState
        }
    }
    deinit { for entry in entries.values { entry.cancel() } }
}

private struct ContinuousPumpTimers: ConnectionPumpTimers {
    func schedule(deadlineNanoseconds: UInt64, _ action: @escaping @Sendable () -> Void) -> any ConnectionPumpTimer {
        ContinuousPumpTimer(deadline: deadlineNanoseconds, action: action)
    }
}
private final class ContinuousPumpTimer: ConnectionPumpTimer, @unchecked Sendable {
    private let source: DispatchSourceTimer
    init(deadline: UInt64, action: @escaping @Sendable () -> Void) {
        source = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        // Continuous time includes suspension/sleep. Poll, and also recheck on every
        // operation/completion; an uptime timer cannot extend a protocol deadline.
        source.schedule(deadline: .now(), repeating: .milliseconds(250))
        source.setEventHandler { if StatusTLSClock.nowNanoseconds() >= deadline { action() } }
        source.resume()
    }
    func cancel() { source.cancel() }
    deinit { source.cancel() }
}
