import Darwin
import Foundation
import XCTest
@testable import RemoteExecutionCore

final class SQLiteDatabaseTests: XCTestCase {
    // SQLITE_FULL automatically rolls back; a second rollback must not hide the original error.
    func testAutomaticRollbackPreservesFullDatabaseDiagnostic() throws {
        let directory = URL(fileURLWithPath: "/private/tmp")
            .appendingPathComponent("remote-sqlite-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let database = try SQLiteDatabase(url: directory.appendingPathComponent("full.sqlite3"))
        try database.execute("PRAGMA max_page_count = 2")
        try database.execute("CREATE TABLE fixture(value BLOB)")
        XCTAssertThrowsError(try database.transaction {
            try database.execute("INSERT INTO fixture VALUES(zeroblob(65536))")
        }) {
            XCTAssertEqual(($0 as? JournalStorageError)?.kind, .sqlite)
            XCTAssertEqual(($0 as? JournalStorageError)?.sqliteCode, 13) // SQLITE_FULL
            XCTAssertEqual(($0 as? JournalStorageError)?.sqliteExtendedCode, 13)
            XCTAssertTrue(($0 as? JournalStorageError)?.message.contains("full") == true,
                          "Expected original SQLITE_FULL diagnostic, received \($0)")
        }
        try database.transaction { try database.execute("INSERT INTO fixture VALUES(NULL)") }
        XCTAssertEqual(try database.query("SELECT count(*) FROM fixture").first?[0], "1")
    }
    func testOrdinaryFailureRollsBackAndPreservesOriginalError() throws {
        let directory = URL(fileURLWithPath: "/private/tmp")
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

    func testAdmissionDiagnosticsRemainReadableInsideCompositeFailures() {
        let cases: [(AdmissionError, String)] = [
            (.staleEpoch, "Storage epoch is stale"),
            (.payloadConflict, "Request payload conflicts with its durable record"),
            (.recoveryRequired, "Process recovery is required"),
            (.invalidTransition, "Run state transition is invalid"),
            (.wrongController, "Controller does not match the journal"),
            (.staleConnection, "Connection lease is stale")
        ]
        for (original, text) in cases {
            let composite = JournalTransactionError(originalError: original,
                rollbackError: JournalStorageError(kind: .sqlite, message: "Simulated rollback I/O failure", sqliteCode: 10))
            XCTAssertTrue(composite.localizedDescription.contains(text))
            XCTAssertTrue(composite.localizedDescription.contains("Simulated rollback I/O failure"))
        }
    }

    // These direct boundary opens bypass preflight intentionally: native no-follow
    // and opened-descriptor checks remain independent of the directory inspector.
    func testDirectNativeOpensRejectSymlinkFilesAndMultiplyLinkedLock() throws {
        let directory = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remote-native-path-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("target")
        try Data().write(to: target)
        let lock = directory.appendingPathComponent("admission.lock")
        try FileManager.default.createSymbolicLink(at: lock, withDestinationURL: target)
        XCTAssertThrowsError(try JournalDirectoryLock(directory: directory))
        XCTAssertEqual(try Data(contentsOf: target), Data())
        try FileManager.default.removeItem(at: lock)
        try FileManager.default.linkItem(at: target, to: lock)
        XCTAssertThrowsError(try JournalDirectoryLock(directory: directory))
        XCTAssertEqual(try Data(contentsOf: target), Data())
        let database = directory.appendingPathComponent("fixture.sqlite3")
        try FileManager.default.createSymbolicLink(at: database, withDestinationURL: target)
        XCTAssertThrowsError(try SQLiteDatabase(url: database)) {
            XCTAssertEqual(($0 as? JournalStorageError)?.sqliteCode, 14) // SQLITE_CANTOPEN
        }
        XCTAssertEqual(try Data(contentsOf: target), Data())
    }

    // Existing/EEXIST files must remain accepted without privacy migration.
    func testExisting0644FilesRemainUsableWithoutModeOrInodeChanges() throws {
        let directory = URL(fileURLWithPath: "/private/tmp/remote-existing-modes-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let controller = ControllerID()
        let epoch: StorageEpoch
        do { epoch = try AdmissionJournal(directory: directory, controllerID: controller).epoch }
        let files = ["admission.lock", "admission.sqlite3"].map { directory.appendingPathComponent($0) }
        var before: [ino_t] = []
        for file in files {
            XCTAssertEqual(chmod(file.path, 0o644), 0)
            var info = stat()
            XCTAssertEqual(lstat(file.path, &info), 0)
            before.append(info.st_ino)
        }
        do {
            let journal = try AdmissionJournal(directory: directory, controllerID: controller)
            XCTAssertEqual(try journal.epoch, epoch)
            let record = try journal.lookupOrRejectAbsent(RequestID(), epoch: epoch, controllerID: controller)
            XCTAssertEqual(record.disposition, .rejectedAbsent)
        }
        for (index, file) in files.enumerated() {
            var info = stat()
            XCTAssertEqual(lstat(file.path, &info), 0)
            XCTAssertEqual(info.st_mode & 0o7777, 0o644)
            XCTAssertEqual(info.st_ino, before[index])
        }
    }

    // Normalization must never repair an existing file merely because open failed.
    func testExistingReadOnlyFilesRefuseWithoutRepairOrReplacement() throws {
        for name in ["admission.lock", "admission.sqlite3"] {
            let directory = URL(fileURLWithPath: "/private/tmp/remote-readonly-mode-\(UUID())")
            defer { try? FileManager.default.removeItem(at: directory) }
            let controller = ControllerID()
            do { _ = try AdmissionJournal(directory: directory, controllerID: controller) }
            let file = directory.appendingPathComponent(name)
            XCTAssertEqual(chmod(file.path, 0o400), 0)
            var before = stat()
            XCTAssertEqual(lstat(file.path, &before), 0)
            XCTAssertThrowsError(try AdmissionJournal(directory: directory, controllerID: controller))
            var after = stat()
            XCTAssertEqual(lstat(file.path, &after), 0)
            XCTAssertEqual(after.st_mode & 0o7777, 0o400)
            XCTAssertEqual(after.st_ino, before.st_ino)
            // Test cleanup restores only this disposable fixture, after assertions.
            XCTAssertEqual(chmod(file.path, 0o600), 0)
            let reopened = try AdmissionJournal(directory: directory, controllerID: controller)
            XCTAssertNil(try reopened.status.activeRun)
        }
    }

    func testOwnershipRefusalDoesNotCreateMissingMainDatabase() throws {
        let directory = URL(fileURLWithPath: "/private/tmp/remote-owned-precreation-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let leaf = try JournalStateDirectory.prepare(directory)
        let lock = try JournalDirectoryLock(directory: leaf)
        XCTAssertThrowsError(try AdmissionJournal(directory: leaf, controllerID: ControllerID())) {
            XCTAssertEqual(($0 as? JournalStorageError)?.kind, .alreadyOwned)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: leaf.appendingPathComponent("admission.sqlite3").path))
        withExtendedLifetime(lock) {}
    }

    // Foreign-owner acceptance is checked on the stat snapshot, without chowning
    // fixtures or claiming a native foreign-account filesystem experiment.
    func testForeignOwnerArtifactStatIsRejected() throws {
        var info = stat()
        info.st_mode = S_IFREG | 0o600
        info.st_nlink = 1
        info.st_uid = geteuid() == 0 ? 1 : 0
        XCTAssertThrowsError(try JournalStateDirectory.validateArtifact(info)) {
            XCTAssertEqual(($0 as? JournalStorageError)?.kind, .filesystem)
        }
    }

    // DELETE requires EXTRA's directory sync after journal unlink. The native
    // readback qualifies this configuration policy, not physical power-loss safety.
    func testDeleteJournalUsesExtraDurabilityAndCommittedRecordSurvivesReopen() throws {
        let directory = URL(fileURLWithPath: "/private/tmp")
            .appendingPathComponent("remote-durability-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("fixture.sqlite3")
        do {
            let database = try SQLiteDatabase(url: url)
            XCTAssertEqual(try database.query("PRAGMA journal_mode")[0][0], "delete")
            XCTAssertEqual(try database.query("PRAGMA synchronous")[0][0], "3", "DELETE durability policy requires EXTRA (3)")
            XCTAssertEqual(try database.query("PRAGMA fullfsync")[0][0], "1")
            try database.execute("CREATE TABLE fixture(epoch TEXT, disposition TEXT)")
            try database.transaction {
                try database.execute("INSERT INTO fixture VALUES(?, ?)", [.text("captured-epoch"), .text("rejectedAbsent")])
            }
        }
        let reopened = try SQLiteDatabase(url: url)
        XCTAssertEqual(try reopened.query("PRAGMA journal_mode")[0][0], "delete")
        XCTAssertEqual(try reopened.query("PRAGMA synchronous")[0][0], "3", "Reopened connections must retain the EXTRA policy")
        XCTAssertEqual(try reopened.query("PRAGMA fullfsync")[0][0], "1")
        XCTAssertEqual(try reopened.query("SELECT epoch, disposition FROM fixture"), [["captured-epoch", "rejectedAbsent"]])
    }

}
