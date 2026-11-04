import Dispatch
import Foundation

/// The queue owns every mutable field and every synchronous journal job. No job
/// suspends between policy validation and a future transaction's commit.
final class StatusOnlyOwner: @unchecked Sendable {
    // Sendability here transfers an exclusively queue-confined box, never permits
    // direct concurrent access. Owner jobs are the only users of State.
    final class State: @unchecked Sendable {
        let configuration: StatusOnlyHostConfiguration
        var journal: StatusOnlyJournal?
        var incarnation: UUID?
        var currentLease: StatusControllerLease?
        var handshakeContexts: [UUID: StatusFixedHandshake] = [:]
        var enrollmentWindow: StatusOpenEnrollment?
        var fixedEnrollmentClaim: StatusFixedEnrollmentClaim?
        var enrollmentCandidate: StatusAcceptedCandidate?
        private var retainedFailure: (any Error)?

        init(configuration: StatusOnlyHostConfiguration) { self.configuration = configuration }

        func requireJournal() throws -> StatusOnlyJournal {
            if let retainedFailure { throw retainedFailure }
            guard let journal, incarnation != nil else { throw StatusHostError.closed }
            return journal
        }

        func run<T>(_ operation: (State) throws -> T) throws -> T {
            do {
                // Retained/storage health always precedes capability/policy checks.
                try requireJournal().checkHealth()
                return try operation(self)
            } catch let refusal as StatusHostError {
                throw refusal
            } catch {
                if retainedFailure == nil {
                    retainedFailure = error
                    invalidateAuthority()
                    // Synchronous cancellation only: the bridge must never reenter.
                    configuration.onUnavailable()
                }
                throw retainedFailure!
            }
        }

        func invalidateAuthority() {
            incarnation = nil
            invalidateControllerAuthority()
        }

        // Ordinary local revocation must retain the healthy owner incarnation.
        // This clears all pending/live controller authority before any policy job.
        func invalidateControllerAuthority() {
            currentLease = nil
            clearEnrollment()
            handshakeContexts.removeAll()
        }

        func close() {
            invalidateAuthority()
            // SQLite closes while the journal still retains directory ownership.
            journal = nil
            retainedFailure = nil
        }
    }

    private let queue: DispatchQueue
    private let state: State

    init(configuration: StatusOnlyHostConfiguration, queue: DispatchQueue) {
        self.queue = queue
        state = State(configuration: configuration)
    }

    deinit {
        // Even callers dropping every handle without close cannot release SQLite
        // on their own executor. Outstanding submissions retain their state box.
        let state = state
        queue.async { state.close() }
    }

    func initialize(native: any SQLiteNative, backupExclusion: any StatusBackupExclusion) async throws {
        let state = state
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            queue.async {
                do {
                    state.journal = try StatusOnlyJournal.open(configuration: state.configuration, native: native,
                                                              backupExclusion: backupExclusion)
                    state.incarnation = UUID()
                    continuation.resume()
                } catch {
                    // A failed open has no published authority or retained owner.
                    // All partial journal resources unwind on this same queue.
                    state.close()
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    func perform<T: Sendable>(_ operation: @escaping @Sendable (State) throws -> T) async throws -> T {
        let state = state
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do { continuation.resume(returning: try state.run(operation)) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }

    func close() async {
        let state = state
        await withCheckedContinuation { continuation in
            queue.async { state.close(); continuation.resume() }
        }
    }
}
