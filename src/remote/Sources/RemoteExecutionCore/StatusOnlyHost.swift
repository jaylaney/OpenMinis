import Dispatch
import Foundation

/// Async publication boundary for the status-only store. The synchronous journal
/// and identity resolver are initialized on a dedicated serial owner queue.
public enum StatusOnlyHost {
    public static func open(configuration: StatusOnlyHostConfiguration) async throws -> StatusOnlyHostHandles {
        try await open(configuration: configuration, native: SystemSQLiteNative(),
                       backupExclusion: FoundationStatusBackupExclusion(),
                       queue: DispatchQueue(label: "org.openminis.status-owner.\(UUID())"))
    }

    // Instance-owned dependencies and queue barriers are internal qualification
    // boundaries; ordinary importers cannot supply or bypass storage ownership.
    static func open(configuration: StatusOnlyHostConfiguration, native: any SQLiteNative,
                     backupExclusion: any StatusBackupExclusion,
                     queue: DispatchQueue) async throws -> StatusOnlyHostHandles {
        let owner = StatusOnlyOwner(configuration: configuration, queue: queue)
        try await owner.initialize(native: native, backupExclusion: backupExclusion)
        return StatusOnlyHostHandles(host: TrustedStatusHostHandle(owner: owner),
                                     controller: StatusControllerHandle(owner: owner))
    }
}

public struct TrustedStatusHostHandle: Sendable {
    let owner: StatusOnlyOwner

    public func localStatus() async throws -> StatusOnlyLocalSnapshot {
        try await owner.perform { state in
            state.expireEnrollment()
            let policy = try state.requireJournal().readPolicy()
            return StatusOnlyLocalSnapshot(snapshot: policy.snapshot, controllerState: policy.controllerState,
                                           enrollment: state.enrollmentState, readiness: .available)
        }
    }


    public func openEnrollment() async throws -> StatusEnrollmentWindow {
        try await owner.perform { try $0.openEnrollment() }
    }

    public func beginHandshake(_ input: StatusHandshakeInput) async throws -> StatusHandshakeContext {
        try await owner.perform { try $0.beginHandshake(input) }
    }

    public func recordProofFailure(contextID: UUID) async throws {
        try await owner.perform { try $0.recordProofFailure(contextID: contextID) }
    }

    /// The trusted bridge must verify the fixed context's proof before this call.
    public func acceptCandidate(contextID: UUID, claimDigest: Data) async throws -> StatusAcceptedCandidate {
        try await owner.perform { try $0.acceptCandidate(contextID: contextID, claimDigest: claimDigest) }
    }

    public func confirmCandidate(candidateID: UUID) async throws {
        try await owner.perform { try $0.confirmCandidate(candidateID: candidateID) }
    }

    public func rejectCandidate(candidateID: UUID) async throws {
        try await owner.perform { state in
            state.expireEnrollment()
            guard state.enrollmentCandidate?.candidateID == candidateID else { throw StatusHostError.invalidCandidate }
            state.clearEnrollment()
        }
    }

    public func disconnect(connectionID: UUID) async {
        // Disconnect cannot expose errors; perform still retains any original
        // storage failure and synchronously fences transport before returning.
        _ = try? await owner.perform { state in
            state.handshakeContexts = state.handshakeContexts.filter { $0.value.input.connectionID != connectionID }
            if state.fixedEnrollmentClaim?.connectionID == connectionID { state.clearEnrollment() }
            if state.currentLease?.connectionID == connectionID { state.currentLease = nil }
        }
    }

    /// The trusted bridge verifies the proof over this fixed context first.
    /// Peer-supplied keys or policy cannot be passed at the authority boundary.
    public func authenticate(contextID: UUID) async throws -> StatusControllerLease {
        try await owner.perform { try $0.authenticate(contextID: contextID) }
    }

    public func revokeController() async throws {
        try await owner.perform { try $0.revokeController() }
    }

    public func close() async { await owner.close() }
}

/// Holds only the status operation; trusted host mutation methods are separate.
public struct StatusControllerHandle: Sendable {
    let owner: StatusOnlyOwner

    public func status(over lease: StatusControllerLease) async throws -> StatusOnlySnapshot {
        try await owner.perform { state in
            guard state.incarnation == lease.incarnation, state.currentLease == lease else {
                throw StatusHostError.staleLease
            }
            let policy = try state.requireJournal().readPolicy()
            guard policy.controllerState == .enrolled, policy.storageEpoch == lease.storageEpoch,
                  policy.controllerGeneration == lease.controllerGeneration else {
                throw StatusHostError.staleLease
            }
            return policy.snapshot
        }
    }
}
