import CSQLite
import Foundation
import os
import XCTest
@testable import RemoteExecutionCore

/// Only configuration-result mismatches/errors are simulated. All SQL and storage
/// otherwise use system SQLite, including initialization and connection closure.
private final class ConfigurationResultNative: SQLiteNative, @unchecked Sendable {
    let sql: String
    let replacement: UnsafeMutablePointer<CChar>?
    let fail: Bool
    private let injectedFailure = OSAllocatedUnfairLock(initialState: false)
    init(sql: String, value: String?, fail: Bool = false) {
        self.sql = sql
        replacement = value.flatMap { strdup($0) }
        self.fail = fail
    }
    deinit { free(replacement) }
    func step(_ statement: OpaquePointer) -> Int32 {
        if String(cString: sqlite3_sql(statement)) == sql {
            if fail {
                injectedFailure.withLock { $0 = true }
                return SQLITE_IOERR
            }
            if replacement == nil { return SQLITE_DONE }
        }
        return sqlite3_step(statement)
    }
    func columnText(_ statement: OpaquePointer, _ index: Int32) -> UnsafePointer<UInt8>? {
        if String(cString: sqlite3_sql(statement)) == sql, let replacement {
            return UnsafeRawPointer(replacement).assumingMemoryBound(to: UInt8.self)
        }
        return sqlite3_column_text(statement, index)
    }
    func failure(_ connection: OpaquePointer) -> JournalStorageError {
        let simulated = injectedFailure.withLock { pending in
            let result = pending
            pending = false
            return result
        }
        if simulated {
            return JournalStorageError(kind: .sqlite, message: "Simulated configuration I/O failure",
                                       sqliteCode: SQLITE_IOERR, sqliteExtendedCode: 1034)
        }
        return SystemSQLiteNative().failure(connection)
    }
}

final class SQLiteStoragePolicyTests: XCTestCase {
    private func fixture(_ body: (URL) throws -> Void) throws {
        let root = URL(fileURLWithPath: "/private/tmp/openminis-remote-storage-policy-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        try body(root)
    }
    func testWrongOrMissingEffectiveSettingsRefuseBeforeSchemaAndReleaseOwnership() throws {
        for (sql, wrong) in [("PRAGMA journal_mode = DELETE", "wal"), ("PRAGMA synchronous", "2")] {
            for value: String? in [wrong, nil] {
                try fixture { root in
                    let native = ConfigurationResultNative(sql: sql, value: value)
                    let controller = ControllerID()
                    XCTAssertThrowsError(try AdmissionJournal(directory: root, controllerID: controller, native: native)) {
                        XCTAssertEqual(($0 as? JournalStorageError)?.kind, .sqlite)
                        XCTAssertTrue(($0 as? JournalStorageError)?.message.contains("policy") == true)
                    }
                    do {
                        let lock = try JournalDirectoryLock(directory: root)
                        let raw = try SQLiteDatabase(url: root.appendingPathComponent("admission.sqlite3"), ownershipLock: lock)
                        XCTAssertEqual(try raw.query("SELECT name FROM sqlite_master WHERE type = 'table'"), [])
                    }
                    let reopened = try AdmissionJournal(directory: root, controllerID: controller)
                    XCTAssertNil(try reopened.status.activeRun)
                }
            }
        }
    }

    func testConfigurationNativeFailureIsPreservedAndOwnershipReleased() throws {
        for sql in ["PRAGMA journal_mode = DELETE", "PRAGMA synchronous"] {
            try fixture { root in
                let native = ConfigurationResultNative(sql: sql, value: nil, fail: true)
                let controller = ControllerID()
                XCTAssertThrowsError(try AdmissionJournal(directory: root, controllerID: controller, native: native)) {
                    let error = $0 as? JournalStorageError
                    XCTAssertEqual(error?.sqliteCode, SQLITE_IOERR)
                    XCTAssertEqual(error?.sqliteExtendedCode, 1034)
                    XCTAssertEqual(error?.message, "Simulated configuration I/O failure")
                }
                let reopened = try AdmissionJournal(directory: root, controllerID: controller)
                XCTAssertNil(try reopened.status.activeRun)
            }
        }
    }
}
