import Foundation

public protocol StatusClock: Sendable {
    func nowNanoseconds() -> UInt64
}

public protocol StatusRandomSource: Sendable {
    func bytes(count: Int) throws -> Data
}

/// The resolver must load-only when given a pin. A nil pin permits creation only
/// after the owner has established freshness. Callbacks run on the owner queue.
public struct StatusOnlyHostConfiguration: Sendable {
    public let directory: URL
    public let allowsFreshStore: Bool
    public let clock: any StatusClock
    public let random: any StatusRandomSource
    public let identityResolver: @Sendable (Data?) throws -> Data
    public let onUnavailable: @Sendable () -> Void

    public init(directory: URL, clock: any StatusClock, random: any StatusRandomSource,
                identityResolver: @escaping @Sendable (Data?) throws -> Data,
                onUnavailable: @escaping @Sendable () -> Void, allowsFreshStore: Bool = true) {
        self.directory = directory
        self.allowsFreshStore = allowsFreshStore
        self.clock = clock
        self.random = random
        self.identityResolver = identityResolver
        self.onUnavailable = onUnavailable
    }
}

public enum StatusExecutionCapability: Sendable { case unsupported }
public enum StatusControllerState: String, Sendable { case unenrolled, enrolled, revoked }
public enum StatusEnrollmentState: Sendable { case closed, open, candidate }
public enum StatusReadiness: Sendable { case available }

/// Policy refusals are distinct from storage errors, which disable the owner.
public enum StatusHostError: Error, Equatable, Sendable {
    case notEnrolled, alreadyEnrolled, invalidKey, generationOverflow
    case closed, staleLease
    case identityMismatch, invalidHandshake, enrollmentClosed, invalidContext, invalidCandidate
    case deadlineExpired, deadlineOverflow
}

public struct StatusOnlySnapshot: Equatable, Sendable {
    public let hostID: UUID
    public let storageEpoch: UUID
    public let controllerID: UUID
    public let controllerGeneration: UInt64
    public let executionCapability: StatusExecutionCapability
}

public struct StatusOnlyLocalSnapshot: Equatable, Sendable {
    public let snapshot: StatusOnlySnapshot
    public let controllerState: StatusControllerState
    public let enrollment: StatusEnrollmentState
    public let readiness: StatusReadiness
}

public enum StatusHandshakeMode: UInt8, Sendable { case enrollment = 1, normal = 2 }

public struct StatusHandshakeInput: Sendable {
    public let connectionID: UUID
    public let acceptedAtNanoseconds: UInt64
    public let mode: StatusHandshakeMode
    public let hostID: UUID
    public let hostPin: Data
    public let controllerSPKI: Data
    public let clientNonce: Data
    public let invitationID: UUID

    public init(connectionID: UUID, acceptedAtNanoseconds: UInt64, mode: StatusHandshakeMode,
                hostID: UUID, hostPin: Data, controllerSPKI: Data, clientNonce: Data, invitationID: UUID) {
        self.connectionID = connectionID
        self.acceptedAtNanoseconds = acceptedAtNanoseconds
        self.mode = mode
        self.hostID = hostID
        self.hostPin = hostPin
        self.controllerSPKI = controllerSPKI
        self.clientNonce = clientNonce
        self.invitationID = invitationID
    }
}

public struct StatusHandshakeContext: Sendable {
    public let contextID: UUID
    public let serverNonce: Data
    public let controllerID: UUID
    public let generation: UInt64
    public let invitationSecret: Data?
}

public struct StatusEnrollmentWindow: Sendable {
    public let hostID: UUID
    public let hostPin: Data
    public let invitationID: UUID
    public let secret: Data
    public let deadlineNanoseconds: UInt64
}

public struct StatusAcceptedCandidate: Sendable {
    public let candidateID: UUID
    public let connectionID: UUID
    public let claimDigest: Data
    public let sasNonce: Data
}

struct StatusStoredPolicy: Equatable, Sendable {
    let hostID: UUID
    let storageEpoch: UUID
    let controllerID: UUID
    let controllerGeneration: UInt64
    let controllerState: StatusControllerState
    let controllerSPKI: Data?
    let hostPin: Data

    var executionCapability: StatusExecutionCapability { .unsupported }

    var snapshot: StatusOnlySnapshot {
        StatusOnlySnapshot(hostID: hostID, storageEpoch: storageEpoch, controllerID: controllerID,
                           controllerGeneration: controllerGeneration, executionCapability: executionCapability)
    }
}

/// Authority has no public constructor or serialization. Only owner authentication
/// may mint it after a same-job policy recheck.
public struct StatusControllerLease: Equatable, Sendable {
    let incarnation: UUID
    let connectionToken: UUID
    let connectionID: UUID
    let storageEpoch: UUID
    let controllerGeneration: UInt64
}

public struct StatusOnlyHostHandles: Sendable {
    public let host: TrustedStatusHostHandle
    public let controller: StatusControllerHandle
}
