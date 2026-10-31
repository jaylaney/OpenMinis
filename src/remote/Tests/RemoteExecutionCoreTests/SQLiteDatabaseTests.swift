import Foundation
import XCTest
@testable import RemoteExecutionCore

final class SQLiteDatabaseTests: XCTestCase {
    // SQLITE_FULL automatically rolls back; a second rollback must not hide the original error.
    func testAutomaticRollbackPreservesFullDatabaseDiagnostic() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("remote-sqlite-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let database = try SQLiteDatabase(url: directory.appendingPathComponent("full.sqlite3"))
        try database.execute("PRAGMA max_page_count = 2")
        try database.execute("CREATE TABLE fixture(value BLOB)")
        XCTAssertThrowsError(try database.transaction {
            try database.execute("INSERT INTO fixture VALUES(zeroblob(65536))")
        }) {
            XCTAssertTrue(($0 as? JournalStorageError)?.message.contains("full") == true,
                          "Expected original SQLITE_FULL diagnostic, received \($0)")
        }
        try database.transaction { try database.execute("INSERT INTO fixture VALUES(NULL)") }
        XCTAssertEqual(try database.query("SELECT count(*) FROM fixture").first?[0], "1")
    }
    func testOrdinaryFailureRollsBackAndPreservesOriginalError() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("remote-sqlite-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let database = try SQLiteDatabase(url: directory.appendingPathComponent("rollback.sqlite3"))
        try database.execute("CREATE TABLE fixture(value TEXT)")
        XCTAssertThrowsError(try database.transaction {
            try database.execute("INSERT INTO fixture VALUES('uncommitted')")
            throw AdmissionError.invalidTransition
        }) { XCTAssertEqual($0 as? AdmissionError, .invalidTransition) }
        XCTAssertEqual(try database.query("SELECT count(*) FROM fixture").first?[0], "0")
        try database.transaction { try database.execute("INSERT INTO fixture VALUES('committed')") }
        XCTAssertEqual(try database.query("SELECT count(*) FROM fixture").first?[0], "1")
    }

}
