import Foundation

/// A journal namespace. Losing or resetting storage creates a different namespace.
public struct StorageEpoch: Codable, Hashable, Sendable {
    public let rawValue: UUID
    public init(rawValue: UUID = UUID()) { self.rawValue = rawValue }
}
public struct ControllerID: Codable, Hashable, Sendable {
    public let rawValue: UUID
    public init(rawValue: UUID = UUID()) { self.rawValue = rawValue }
}
public struct RequestID: Codable, Hashable, Sendable {
    public let rawValue: UUID
    public init(rawValue: UUID = UUID()) { self.rawValue = rawValue }
}
public struct SessionID: Codable, Hashable, Sendable {
    public let rawValue: UUID
    public init(rawValue: UUID = UUID()) { self.rawValue = rawValue }
}
public struct RunID: Codable, Hashable, Sendable {
    public let rawValue: UUID
    public init(rawValue: UUID = UUID()) { self.rawValue = rawValue }
}

public enum MutationKind: String, Codable, Sendable { case startRun, stopRun }

public struct MutationRequest: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let epoch: StorageEpoch
    public let controllerID: ControllerID
    public let requestID: RequestID
    public let sessionID: SessionID
    public let runID: RunID
    public let kind: MutationKind
    public let payload: Data

    public init(epoch: StorageEpoch, controllerID: ControllerID, requestID: RequestID,
                sessionID: SessionID, runID: RunID, kind: MutationKind, payload: Data) {
        self.epoch = epoch
        self.controllerID = controllerID
        self.requestID = requestID
        self.sessionID = sessionID
        self.runID = runID
        self.kind = kind
        self.payload = payload
    }

    public var description: String { "MutationRequest(id: \(requestID.rawValue), kind: \(kind.rawValue))" }
    public var debugDescription: String { description }
}

public enum RequestDisposition: String, Codable, Sendable {
    case admitted, stopRequested, rejectedBusy, rejectedAbsent, rejectedRunUnavailable
}

/// A durable admission decision, never evidence that a run or command finished.
public struct RequestRecord: Codable, Equatable, Sendable {
    public let epoch: StorageEpoch
    public let controllerID: ControllerID
    public let requestID: RequestID
    public let sessionID: SessionID?
    public let runID: RunID?
    public let kind: MutationKind?
    public let digest: Data?
    public let disposition: RequestDisposition
}

/// Whether this call inserted the durable decision or returned an existing one.
/// A new admission is not proof of process launch or durable execution ownership.
public struct SubmissionResult: Equatable, Sendable {
    public let record: RequestRecord
    public let isReplay: Bool
}

public enum RunOutcome: String, Codable, Sendable { case completed, failed, interruptedUnknown }
public enum RunState: String, Codable, Sendable { case active, stopRequested, settled }

public struct RunRecord: Codable, Equatable, Sendable {
    public let sessionID: SessionID
    public let runID: RunID
    public let state: RunState
    public let outcome: RunOutcome?
}

public struct AdmissionStatus: Equatable, Sendable {
    public let epoch: StorageEpoch
    public let recoveryRequired: Bool
    public let activeRun: RunRecord?
}

public enum AdmissionError: Error, Equatable, Sendable {
    case staleEpoch, payloadConflict, recoveryRequired, invalidTransition, wrongController, staleConnection
}

/// An opaque capability for one connection to one coordinator instance.
/// Obtain a lease through `AdmissionCoordinator.connect(controllerID:)`.
public struct ConnectionLease: Sendable {
    private let token: UUID
    private let controllerID: ControllerID

    internal init(token: UUID, controllerID: ControllerID) {
        self.token = token
        self.controllerID = controllerID
    }

    internal func validate(controllerID: ControllerID, currentToken: UUID?) throws {
        guard self.controllerID == controllerID else { throw AdmissionError.wrongController }
        guard token == currentToken else { throw AdmissionError.staleConnection }
    }
}
