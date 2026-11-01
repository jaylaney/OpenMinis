import CSQLite
import Foundation

/// Instance-owned native boundary. The journal always defaults to real SQLite;
/// internal dependency injection permits deterministic native-result qualification.
protocol SQLiteNative: Sendable {
    func step(_ statement: OpaquePointer) -> Int32
    func columnText(_ statement: OpaquePointer, _ index: Int32) -> UnsafePointer<UInt8>?
    func failure(_ connection: OpaquePointer) -> JournalStorageError
}

extension SQLiteNative {
    func step(_ statement: OpaquePointer) -> Int32 { sqlite3_step(statement) }
    func columnText(_ statement: OpaquePointer, _ index: Int32) -> UnsafePointer<UInt8>? {
        sqlite3_column_text(statement, index)
    }
    func failure(_ connection: OpaquePointer) -> JournalStorageError {
        // After a failed column conversion, errcode must be the very next SQLite call.
        let code = sqlite3_errcode(connection)
        let extendedCode = sqlite3_extended_errcode(connection)
        let message = String(cString: sqlite3_errmsg(connection))
        return JournalStorageError(kind: .sqlite, message: message,
                                   sqliteCode: code, sqliteExtendedCode: extendedCode)
    }
}

struct SystemSQLiteNative: SQLiteNative {}
