import CSQLite
import Foundation

/// The original store is never opened with CREATE, writable flags or writable
/// pragmas during validation. Every statement is finalized before returning.
final class StatusReadOnlyDatabase {
    private var connection: OpaquePointer?
    private let native: any SQLiteNative

    init(url: URL, native: any SQLiteNative = SystemSQLiteNative()) throws {
        self.native = native
        var opened: OpaquePointer?
        let result = sqlite3_open_v2(url.path, &opened,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
        guard result == SQLITE_OK, let opened else {
            let error = opened.map { native.failure($0) } ?? JournalStorageError(kind: .sqlite, message: "Cannot open status validator", sqliteCode: result)
            if let opened { sqlite3_close_v2(opened) }
            throw error
        }
        connection = opened
    }

    deinit { if let connection { sqlite3_close_v2(connection) } }

    /// Explicit closure is required before file recheck and the writable open.
    func close() throws {
        guard let connection else { return }
        guard sqlite3_close(connection) == SQLITE_OK else { throw native.failure(connection) }
        self.connection = nil
    }

    func query(_ sql: String) throws -> [[String?]] {
        guard let connection else { throw JournalStorageError(kind: .sqlite, message: "Status validator is closed") }
        return try Self.read(sql, connection: connection, native: native)
    }

    /// Shared only with the disposable in-memory reference-schema connection.
    static func read(_ sql: String, connection: OpaquePointer,
                     native: any SQLiteNative = SystemSQLiteNative()) throws -> [[String?]] {
        var prepared: OpaquePointer?
        guard sqlite3_prepare_v2(connection, sql, -1, &prepared, nil) == SQLITE_OK, let statement = prepared else {
            throw native.failure(connection)
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_stmt_readonly(statement) != 0 else {
            throw JournalStorageError(kind: .sqlite, message: "Status validator only accepts read-only statements")
        }
        var rows: [[String?]] = []
        while true {
            switch native.step(statement) {
            case SQLITE_ROW:
                rows.append(try (0..<sqlite3_column_count(statement)).map { column in
                    guard sqlite3_column_type(statement, column) != SQLITE_NULL else { return nil }
                    guard let text = native.columnText(statement, column) else { throw native.failure(connection) }
                    // Use the byte count so embedded NULs cannot hide a suffix.
                    let count = Int(sqlite3_column_bytes(statement, column))
                    guard let value = String(bytes: UnsafeBufferPointer(start: text, count: count), encoding: .utf8) else {
                        throw JournalStorageError(kind: .invalidState, message: "Status validator found invalid UTF-8")
                    }
                    return value
                })
            case SQLITE_DONE: return rows
            default: throw native.failure(connection)
            }
        }
    }
}
