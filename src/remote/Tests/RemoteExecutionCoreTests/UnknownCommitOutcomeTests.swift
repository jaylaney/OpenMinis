import CSQLite
import Foundation
import XCTest
@testable import RemoteExecutionCore

final class UnknownCommitOutcomeTests: XCTestCase {
    // A reported COMMIT error after native success must fence all subsequent SQL.
    func testRealCommitThenReportedFailurePermanentlyDisablesSQL() throws {
        let directory = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remote-unknown-sql-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("fixture.sqlite3")
        let native = ScriptedSQLiteNative()
        var database: SQLiteDatabase? = try SQLiteDatabase(url: url, native: native)
        try database!.execute("CREATE TABLE fixture(value TEXT)")
        native.failNextCommit(afterRealCommit: true)
        XCTAssertThrowsError(try database!.transaction {
            try database!.execute("INSERT INTO fixture VALUES('committed')")
        }) { assertUnknownCommitFailure($0) }
        for operation in [
            { _ = try database!.query("SELECT * FROM fixture") },
            { try database!.execute("INSERT INTO fixture VALUES('later')") },
            { try database!.transaction {} },
            { try database!.checkHealth() }
        ] {
            XCTAssertThrowsError(try operation()) { assertUnknownCommitFailure($0) }
        }
        database = nil
        let reopened = try SQLiteDatabase(url: url)
        XCTAssertEqual(try reopened.query("SELECT value FROM fixture"), [["committed"]])
    }

    // An active native transaction after failed COMMIT can still roll back cleanly.
    func testFailedCommitWithSuccessfulRollbackKeepsConnectionUsable() throws {
        let directory = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remote-commit-rollback-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let native = ScriptedSQLiteNative()
        let database = try SQLiteDatabase(url: directory.appendingPathComponent("fixture.sqlite3"), native: native)
        try database.execute("CREATE TABLE fixture(value TEXT)")
        native.failNextCommit(afterRealCommit: false)
        XCTAssertThrowsError(try database.transaction { try database.execute("INSERT INTO fixture VALUES('rolled back')") }) {
            XCTAssertEqual(($0 as? JournalStorageError)?.sqliteCode, SQLITE_IOERR)
            XCTAssertEqual(($0 as? JournalStorageError)?.message, "Simulated commit I/O failure")
        }
        XCTAssertEqual(try database.query("SELECT count(*) FROM fixture"), [["0"]])
        try database.transaction { try database.execute("INSERT INTO fixture VALUES('later')") }
        XCTAssertEqual(try database.query("SELECT value FROM fixture"), [["later"]])
    }
}

private func assertUnknownCommitFailure(_ error: any Error, file: StaticString = #filePath, line: UInt = #line) {
    guard let unknown = error as? JournalCommitOutcomeUnknownError else {
        XCTFail("Expected unknown commit outcome, received \(error)", file: file, line: line)
        return
    }
    let original = unknown.originalError as? JournalStorageError
    XCTAssertEqual(original?.sqliteCode, SQLITE_IOERR, file: file, line: line)
    XCTAssertEqual(original?.sqliteExtendedCode, 1034, file: file, line: line) // SQLITE_IOERR_FSYNC
    XCTAssertEqual(original?.message, "Simulated reported failure after real COMMIT", file: file, line: line)
    XCTAssertTrue(error.localizedDescription.lowercased().contains("unknown"), "Expected unknown commit outcome, received \(error)", file: file, line: line)
    XCTAssertTrue(error.localizedDescription.lowercased().contains("reopen"), file: file, line: line)
    XCTAssertTrue(error.localizedDescription.contains("Simulated reported failure after real COMMIT"), file: file, line: line)
    XCTAssertFalse(error is JournalTransactionError, file: file, line: line)
}

@MainActor
final class CoordinatorUnknownCommitOutcomeTests: XCTestCase {
    // Both Start and reset can persist despite an error; neither may leave a healthy
    // cached epoch, usable lease or administrative path on the old owner.
    func testStartUnknownOutcomeFencesEveryActorAPIUntilReopen() async throws {
        try await assertTerminalOwnerAfterUnknownOutcome(reset: false)
    }

    func testResetUnknownOutcomeFencesEveryActorAPIUntilReopen() async throws {
        try await assertTerminalOwnerAfterUnknownOutcome(reset: true)
    }

    private func assertTerminalOwnerAfterUnknownOutcome(reset: Bool) async throws {
        let directory = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remote-unknown-actor-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let controller = ControllerID()
        let native = ScriptedSQLiteNative()
        var owner: AdmissionCoordinator? = try AdmissionCoordinator(directory: directory, controllerID: controller, native: native)
        let lease = try await owner!.connect(controllerID: controller)
        let epoch = try await owner!.status().epoch
        let start = MutationRequest(epoch: epoch, controllerID: controller, requestID: RequestID(),
            sessionID: SessionID(), runID: RunID(), kind: .startRun, payload: Data([1]))
        native.failNextCommit(afterRealCommit: true)
        do {
            if reset { _ = try await owner!.reset() }
            else { _ = try await owner!.submit(start, over: lease) }
            XCTFail("Expected reported commit failure")
        } catch { assertUnknownCommitFailure(error) }
        do {
            let coordinator = owner!
            let operations: [@MainActor () async throws -> Void] = [
                { _ = try await coordinator.status() },
                { _ = try await coordinator.status(over: lease) },
                { _ = try await coordinator.connect(controllerID: controller) },
                { _ = try await coordinator.connect(controllerID: ControllerID()) },
                { _ = try await coordinator.submit(start, over: lease) },
                { _ = try await coordinator.reconcile(requestID: RequestID(), epoch: epoch, over: lease) },
                { _ = try await coordinator.runStatus(for: start.runID, epoch: epoch) },
                { _ = try await coordinator.runStatus(for: start.runID, epoch: StorageEpoch(), over: lease) },
                { try await coordinator.settle(runID: start.runID, epoch: epoch, outcome: .completed) },
                { try await coordinator.confirmRecoveredProcessesAbsent() },
                { _ = try await coordinator.reset() }
            ]
            for operation in operations {
                do { try await operation(); XCTFail("Expected terminal owner") }
                catch { assertUnknownCommitFailure(error) }
            }
            XCTAssertThrowsError(try AdmissionCoordinator(directory: directory, controllerID: controller)) {
                XCTAssertEqual(($0 as? JournalStorageError)?.kind, .alreadyOwned)
            }
            withExtendedLifetime(coordinator) {}
        }
        owner = nil
        let reopened = try AdmissionCoordinator(directory: directory, controllerID: controller)
        let persisted = try await reopened.status()
        let fresh = try await reopened.connect(controllerID: controller)
        if reset {
            XCTAssertNotEqual(persisted.epoch, epoch)
            XCTAssertFalse(persisted.recoveryRequired)
            XCTAssertNil(persisted.activeRun)
            do { _ = try await reopened.reconcile(requestID: start.requestID, epoch: epoch, over: fresh); XCTFail("Expected stale epoch") }
            catch { XCTAssertEqual(error as? AdmissionError, .staleEpoch) }
            let replacement = MutationRequest(epoch: persisted.epoch, controllerID: controller, requestID: start.requestID,
                sessionID: start.sessionID, runID: start.runID, kind: .startRun, payload: start.payload)
            let result = try await reopened.submit(replacement, over: fresh)
            XCTAssertEqual(result.record.disposition, .admitted)
            XCTAssertFalse(result.isReplay)
        } else {
            XCTAssertEqual(persisted.epoch, epoch)
            XCTAssertTrue(persisted.recoveryRequired)
            XCTAssertEqual(persisted.activeRun?.runID, start.runID)
            let recorded = try await reopened.reconcile(requestID: start.requestID, epoch: epoch, over: fresh)
            XCTAssertEqual(recorded.disposition, .admitted)
            let replay = try await reopened.submit(start, over: fresh)
            XCTAssertTrue(replay.isReplay)
            XCTAssertEqual(replay.record, recorded)
            try await reopened.confirmRecoveredProcessesAbsent()
            let recovered = try await reopened.runStatus(for: start.runID, epoch: epoch)
            XCTAssertEqual(recovered?.outcome, .interruptedUnknown)
        }
    }
}
