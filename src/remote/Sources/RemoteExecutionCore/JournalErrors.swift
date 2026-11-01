import Foundation

/// Stable storage classifications with diagnostics captured before resources close.
/// No request payloads are stored or included in these errors.
public struct JournalStorageError: Error, LocalizedError, Sendable {
    public enum Kind: Sendable {
        case alreadyOwned, sqlite, filesystem, invalidDirectory, invalidState
    }

    public let kind: Kind
    public let message: String
    public let sqliteCode: Int32?
    public let sqliteExtendedCode: Int32?
    public let posixCode: Int32?

    public init(kind: Kind, message: String, sqliteCode: Int32? = nil,
                sqliteExtendedCode: Int32? = nil, posixCode: Int32? = nil) {
        self.kind = kind
        self.message = message
        self.sqliteCode = sqliteCode
        self.sqliteExtendedCode = sqliteExtendedCode
        self.posixCode = posixCode
    }

    public var errorDescription: String? { message }
}

/// A failed rollback cannot hide the cause that prompted it, including AdmissionError.
public struct JournalTransactionError: Error, LocalizedError, Sendable {
    public let originalError: any Error
    public let rollbackError: any Error

    public init(originalError: any Error, rollbackError: any Error) {
        self.originalError = originalError
        self.rollbackError = rollbackError
    }

    public var errorDescription: String? {
        "Journal transaction failed: \(originalError.localizedDescription). Rollback failed: \(rollbackError.localizedDescription)"
    }
}
