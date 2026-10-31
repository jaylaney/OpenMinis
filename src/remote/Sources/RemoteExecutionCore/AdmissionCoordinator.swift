import Foundation

/// Serialized admission and reconnect reconciliation. The host must authenticate
/// its controller and independently supervise processes; this actor does neither.
/// Use exactly one coordinator owner per journal directory.
public actor AdmissionCoordinator {
    private let journal: AdmissionJournal
    private let controllerID: ControllerID
    private var currentToken: UUID?

    public init(directory: URL, controllerID: ControllerID) throws {
        let journal = try AdmissionJournal(directory: directory)
        try journal.bindController(controllerID)
        self.journal = journal
        self.controllerID = controllerID
    }

    /// Replaces any previous connection. A rejected foreign connection leaves it intact.
    public func connect(controllerID: ControllerID) throws -> ConnectionLease {
        guard controllerID == self.controllerID else { throw AdmissionError.wrongController }
        let token = UUID()
        currentToken = token
        return ConnectionLease(token: token, controllerID: controllerID)
    }

    public func submit(_ request: MutationRequest, over lease: ConnectionLease) throws -> RequestRecord {
        guard request.controllerID == controllerID else { throw AdmissionError.wrongController }
        try validate(lease, epoch: request.epoch)
        // No suspension between capability/epoch validation and the durable transaction.
        return try journal.record(request)
    }

    /// An unknown ID becomes a durable rejection before this returns; delayed sends
    /// can never execute that ID in this storage epoch, including after reconnect/reopen.
    public func reconcile(requestID: RequestID, epoch: StorageEpoch,
                          over lease: ConnectionLease) throws -> RequestRecord {
        try validate(lease, epoch: epoch)
        return try journal.lookupOrRejectAbsent(requestID, controllerID: controllerID)
    }

    public func status() -> AdmissionStatus { journal.status }

    public func runStatus(for runID: RunID) throws -> RunRecord? {
        try journal.runStatus(for: runID)
    }

    /// Host-internal: observe actual termination and supply the epoch captured at admission.
    /// Settlement remains independent of connection leases, which may change during a run.
    public func settle(runID: RunID, epoch: StorageEpoch, outcome: RunOutcome) throws {
        try journal.settle(runID: runID, epoch: epoch, outcome: outcome)
    }

    /// Host-internal: the caller must independently verify recovered processes are absent.
    /// Successful recovery confirmation also invalidates every previously issued lease.
    public func confirmRecoveredProcessesAbsent() throws {
        try journal.confirmRecoveredProcessesAbsent()
        currentToken = nil
    }

    /// Host-internal: succeeds only without active or recovery-blocked work.
    /// Controller binding is preserved; all prior leases and storage epochs are invalidated.
    public func reset() throws -> StorageEpoch {
        let epoch = try journal.reset()
        currentToken = nil
        return epoch
    }

    private func validate(_ lease: ConnectionLease, epoch: StorageEpoch) throws {
        try lease.validate(controllerID: controllerID, currentToken: currentToken)
        guard epoch == journal.epoch else { throw AdmissionError.staleEpoch }
    }
}
