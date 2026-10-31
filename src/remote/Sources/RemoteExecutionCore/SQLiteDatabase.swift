import CSQLite
import Foundation

/// Errors expose SQLite diagnostics, never opaque request payloads (which are not stored).
struct JournalStorageError: Error {
    let message: String
}

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

struct JournalTransactionError: Error {
    let originalError: any Error
    let rollbackError: any Error
}

final class SQLiteDatabase {
    private let handle: SQLiteConnection
    private var connection: OpaquePointer { handle.pointer }

    init(url: URL, ownershipLock: JournalDirectoryLock? = nil) throws {
        // Cover open failure cleanup as well as successful transfer to the connection.
        defer { withExtendedLifetime(ownershipLock) {} }
        var opened: OpaquePointer?
        let result = sqlite3_open_v2(url.path, &opened, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil)
        guard result == SQLITE_OK, let opened else {
            let message = opened.map { String(cString: sqlite3_errmsg($0)) } ?? "Cannot open journal"
            if let opened { sqlite3_close_v2(opened) }
            throw JournalStorageError(message: message)
        }
        handle = SQLiteConnection(pointer: opened, ownershipLock: ownershipLock)
        try execute("PRAGMA foreign_keys = ON")
        try execute("PRAGMA journal_mode = DELETE")
        try execute("PRAGMA synchronous = FULL")
        try execute("PRAGMA fullfsync = ON")
    }

    func execute(_ sql: String, _ values: [SQLiteValue] = []) throws {
        _ = try query(sql, values)
    }

    func query(_ sql: String, _ values: [SQLiteValue] = []) throws -> [[String?]] {
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
            switch sqlite3_step(statement) {
            case SQLITE_ROW:
                rows.append((0..<sqlite3_column_count(statement)).map { index in
                    guard sqlite3_column_type(statement, index) != SQLITE_NULL,
                          let text = sqlite3_column_text(statement, index) else { return nil }
                    return String(cString: text)
                })
            case SQLITE_DONE: return rows
            default: throw failure()
            }
        }
    }

    func transaction<T>(_ body: () throws -> T) throws -> T {
        try execute("BEGIN IMMEDIATE")
        do {
            let value = try body()
            try execute("COMMIT")
            return value
        } catch {
            let originalError = error
            // SQLITE_FULL and other failures can already have rolled back the transaction.
            if sqlite3_get_autocommit(connection) == 0 {
                do {
                    try execute("ROLLBACK")
                } catch {
                    throw JournalTransactionError(originalError: originalError, rollbackError: error)
                }
            }
            throw originalError
        }
    }

    private func failure() -> JournalStorageError {
        JournalStorageError(message: String(cString: sqlite3_errmsg(connection)))
    }
}
