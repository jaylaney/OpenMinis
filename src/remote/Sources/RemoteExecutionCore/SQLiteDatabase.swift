import CSQLite
import Foundation

enum SQLiteValue {
    case text(String), null
}

/// Holds ownership until after SQLite closes, including failed database initialization.
private final class SQLiteConnection {
    let pointer: OpaquePointer
    private let ownershipLock: JournalDirectoryLock?

    init(pointer: OpaquePointer, ownershipLock: JournalDirectoryLock?) {
        self.pointer = pointer
        self.ownershipLock = ownershipLock
    }

    deinit {
        _ = withExtendedLifetime(ownershipLock) { sqlite3_close_v2(pointer) }
    }
}

final class SQLiteDatabase {
    private let handle: SQLiteConnection
    private let native: any SQLiteNative
    private var terminalFailure: (any Error)?
    private var connection: OpaquePointer { handle.pointer }

    init(url: URL, ownershipLock: JournalDirectoryLock? = nil, native: any SQLiteNative = SystemSQLiteNative()) throws {
        self.native = native
        // Cover open failure cleanup as well as successful transfer to the connection.
        defer { withExtendedLifetime(ownershipLock) {} }
        var opened: OpaquePointer?
        let result = sqlite3_open_v2(url.path, &opened, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
        guard result == SQLITE_OK, let opened else {
            let code = opened.map { sqlite3_errcode($0) } ?? result
            let extendedCode = opened.map { sqlite3_extended_errcode($0) } ?? result
            let message = opened.map { String(cString: sqlite3_errmsg($0)) } ?? "Cannot open journal"
            if let opened { sqlite3_close_v2(opened) }
            throw JournalStorageError(kind: .sqlite, message: message, sqliteCode: code, sqliteExtendedCode: extendedCode)
        }
        handle = SQLiteConnection(pointer: opened, ownershipLock: ownershipLock)
        try execute("PRAGMA foreign_keys = ON")
        // The setter returns the effective mode; success alone does not establish
        // the DELETE policy. Reject missing or unexpected results before schema work.
        guard try query("PRAGMA journal_mode = DELETE") == [["delete"]] else {
            throw JournalStorageError(kind: .sqlite, message: "SQLite journal_mode policy requires DELETE")
        }
        // DELETE commits need the directory sync after unlinking the rollback
        // journal. fullfsync selects a sync method, not this additional sync point.
        try execute("PRAGMA synchronous = EXTRA")
        // The synchronous setter returns no rows, so check it separately.
        guard try query("PRAGMA synchronous") == [["3"]] else {
            throw JournalStorageError(kind: .sqlite, message: "SQLite synchronous policy requires EXTRA (3)")
        }
        try execute("PRAGMA fullfsync = ON")
    }

    func execute(_ sql: String, _ values: [SQLiteValue] = []) throws {
        _ = try query(sql, values)
    }

    func query(_ sql: String, _ values: [SQLiteValue] = []) throws -> [[String?]] {
        try checkHealth()
        var prepared: OpaquePointer?
        guard sqlite3_prepare_v2(connection, sql, -1, &prepared, nil) == SQLITE_OK, let statement = prepared else {
            throw failure()
        }
        defer { sqlite3_finalize(statement) }
        for (index, value) in values.enumerated() {
            let result: Int32
            switch value {
            case .null: result = sqlite3_bind_null(statement, Int32(index + 1))
            case .text(let text):
                result = text.withCString {
                    sqlite3_bind_text(statement, Int32(index + 1), $0, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
                }
            }
            guard result == SQLITE_OK else { throw failure() }
        }
        var rows: [[String?]] = []
        while true {
            switch native.step(statement) {
            case SQLITE_ROW:
                rows.append(try (0..<sqlite3_column_count(statement)).map { index in
                    guard sqlite3_column_type(statement, index) != SQLITE_NULL else { return nil }
                    guard let text = native.columnText(statement, index) else {
                        // Capture errcode before any subsequent native call or finalization.
                        throw failure()
                    }
                    return String(cString: text)
                })
            case SQLITE_DONE: return rows
            default: throw failure()
            }
        }
    }

    func transaction<T>(_ body: () throws -> T) throws -> T {
        try execute("BEGIN IMMEDIATE")
        var commitAttempted = false
        do {
            let value = try body()
            commitAttempted = true
            try execute("COMMIT")
            return value
        } catch {
            let originalError = error
            let transactionActive = sqlite3_get_autocommit(connection) == 0
            if commitAttempted && !transactionActive {
                // Autocommit cannot distinguish committed work from an automatic
                // rollback after COMMIT failed. Cached state is no longer safe.
                let failure = JournalCommitOutcomeUnknownError(originalError: originalError)
                terminalFailure = failure
                throw failure
            }
            // SQLITE_FULL and other failures can already have rolled back the transaction.
            if transactionActive {
                do {
                    try execute("ROLLBACK")
                } catch {
                    let failure = JournalTransactionError(originalError: originalError, rollbackError: error)
                    terminalFailure = failure
                    throw failure
                }
            }
            throw originalError
        }
    }

    /// A failed rollback or unknown COMMIT outcome abandons this owner.
    /// Retain the original terminal diagnostic until destruction; no operation repairs it.
    func checkHealth() throws {
        if let terminalFailure { throw terminalFailure }
    }

    private func failure() -> JournalStorageError { native.failure(connection) }
}
