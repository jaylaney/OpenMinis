import CSQLite
import Foundation
import os
import XCTest
@testable import RemoteExecutionCore

/// Instance-scoped simulated native results; every unselected call uses real SQLite.
/// This does not reproduce genuine native allocation or disk I/O failure.
final class ScriptedSQLiteNative: SQLiteNative, Sendable {
    private struct State {
        var failControllerText = false
        var failCommit = false
        var commitBeforeFailure = false
        var failRollback = false
        var clearOnRollback = false
        var diagnostic: JournalStorageError?
    }
    private let state = OSAllocatedUnfairLock(initialState: State())

    func failNextControllerConversion() {
        state.withLock { $0.failControllerText = true }
    }
    func failNextRollback(clearTransaction: Bool) {
        state.withLock {
            $0.failRollback = true
            $0.clearOnRollback = clearTransaction
        }
    }
    func failNextCommitAndRollback(clearTransaction: Bool) {
        state.withLock {
            $0.failCommit = true
            $0.failRollback = true
            $0.clearOnRollback = clearTransaction
        }
    }
    func failNextCommit(afterRealCommit: Bool) {
        state.withLock {
            $0.failCommit = true
            $0.commitBeforeFailure = afterRealCommit
        }
    }
    func columnText(_ statement: OpaquePointer, _ index: Int32) -> UnsafePointer<UInt8>? {
        let sql = String(cString: sqlite3_sql(statement))
        let failed = state.withLock { state in
            guard state.failControllerText, sql == "SELECT controller FROM journal" else { return false }
            state.failControllerText = false
            state.diagnostic = JournalStorageError(kind: .sqlite, message: "Simulated non-NULL text conversion failure",
                                                    sqliteCode: SQLITE_NOMEM, sqliteExtendedCode: SQLITE_NOMEM)
            return true
        }
        return failed ? nil : sqlite3_column_text(statement, index)
    }
    func step(_ statement: OpaquePointer) -> Int32 {
        let sql = String(cString: sqlite3_sql(statement))
        let failure: (Bool, Bool) = state.withLock { state in
            if sql == "COMMIT", state.failCommit {
                state.failCommit = false
                let commitFirst = state.commitBeforeFailure
                state.commitBeforeFailure = false
                state.diagnostic = JournalStorageError(kind: .sqlite,
                    message: commitFirst ? "Simulated reported failure after real COMMIT" : "Simulated commit I/O failure",
                    sqliteCode: SQLITE_IOERR, sqliteExtendedCode: commitFirst ? 1034 : SQLITE_IOERR) // SQLITE_IOERR_FSYNC
                return (true, commitFirst)
            }
            if sql == "ROLLBACK", state.failRollback {
                state.failRollback = false
                state.diagnostic = JournalStorageError(kind: .sqlite, message: "Simulated rollback I/O failure",
                                                        sqliteCode: SQLITE_IOERR, sqliteExtendedCode: SQLITE_IOERR)
                return (true, state.clearOnRollback)
            }
            return (false, false)
        }
        if failure.0 {
            if failure.1 {
                let result = sqlite3_step(statement)
                // Do not hide a failure of the real operation behind the simulation.
                guard result == SQLITE_DONE else {
                    state.withLock { $0.diagnostic = nil }
                    return result
                }
            }
            return SQLITE_IOERR
        }
        return sqlite3_step(statement)
    }
    func failure(_ connection: OpaquePointer) -> JournalStorageError {
        if let diagnostic = state.withLock({ state in
            let diagnostic = state.diagnostic
            state.diagnostic = nil
            return diagnostic
        }) { return diagnostic }
        let code = sqlite3_errcode(connection)
        let extendedCode = sqlite3_extended_errcode(connection)
        let message = String(cString: sqlite3_errmsg(connection))
        return JournalStorageError(kind: .sqlite, message: message, sqliteCode: code, sqliteExtendedCode: extendedCode)
    }
}

final class SQLiteFaultTests: XCTestCase {
    // Nil conversion must throw a captured diagnostic rather than presenting SQL NULL.
    func testNonNullTextConversionFailureIsNotSQLNullAndDoesNotRebindController() throws {
        let directory = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remote-row-fault-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let original = ControllerID()
        var journal: AdmissionJournal? = try AdmissionJournal(directory: directory, controllerID: original)
        let epoch = try journal!.epoch
        journal = nil
        let native = ScriptedSQLiteNative()
        native.failNextControllerConversion()
        XCTAssertThrowsError(try AdmissionJournal(directory: directory, controllerID: ControllerID(), native: native)) {
            let error = $0 as? JournalStorageError
            XCTAssertEqual(error?.sqliteCode, SQLITE_NOMEM)
            XCTAssertEqual(error?.message, "Simulated non-NULL text conversion failure")
        }
        let reopened = try AdmissionJournal(directory: directory, controllerID: original)
        XCTAssertEqual(try reopened.epoch, epoch)
        XCTAssertNil(try reopened.status.activeRun)
        // Legitimate native SQL NULL remains nullable, rather than a conversion error.
        let raw = try SQLiteDatabase(url: directory.appendingPathComponent("nullable.sqlite3"))
        XCTAssertNil(try raw.query("SELECT NULL")[0][0])
    }

    func testRollbackFailureDoesNotDowngradeOriginalAdmissionRefusal() throws {
        let directory = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remote-refusal-fault-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let native = ScriptedSQLiteNative()
        let database = try SQLiteDatabase(url: directory.appendingPathComponent("fixture.sqlite3"), native: native)
        native.failNextRollback(clearTransaction: true)
        for operation in [
            { try database.transaction { throw AdmissionError.invalidTransition } },
            { _ = try database.query("SELECT 1") }
        ] {
            XCTAssertThrowsError(try operation()) {
                let composite = $0 as? JournalTransactionError
                XCTAssertEqual(composite?.originalError as? AdmissionError, .invalidTransition)
                XCTAssertEqual((composite?.rollbackError as? JournalStorageError)?.message, "Simulated rollback I/O failure")
                XCTAssertTrue($0.localizedDescription.contains("Run state transition is invalid"))
                XCTAssertTrue($0.localizedDescription.contains("Simulated rollback I/O failure"))
                XCTAssertFalse($0 is AdmissionError)
            }
        }
    }

    func testRollbackFailurePermanentlyDisablesSQLAfterNativeTransactionClears() throws {
        let directory = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remote-rollback-fault-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let native = ScriptedSQLiteNative()
        let database = try SQLiteDatabase(url: directory.appendingPathComponent("fixture.sqlite3"), native: native)
        try database.execute("CREATE TABLE fixture(value TEXT)")
        native.failNextCommitAndRollback(clearTransaction: true)
        for operation in [
            { try database.transaction { try database.execute("INSERT INTO fixture VALUES('uncommitted')") } },
            { _ = try database.query("SELECT * FROM fixture") },
            { try database.execute("INSERT INTO fixture VALUES('later')") },
            { try database.transaction {} },
            { try database.checkHealth() }
        ] {
            XCTAssertThrowsError(try operation()) { assertTerminalFailure($0) }
        }
    }
}

func assertTerminalFailure(_ error: any Error, file: StaticString = #filePath, line: UInt = #line) {
    guard let composite = error as? JournalTransactionError else {
        XCTFail("Expected terminal composite, received \(error)", file: file, line: line)
        return
    }
    XCTAssertEqual((composite.originalError as? JournalStorageError)?.message, "Simulated commit I/O failure", file: file, line: line)
    XCTAssertEqual((composite.rollbackError as? JournalStorageError)?.message, "Simulated rollback I/O failure", file: file, line: line)
    XCTAssertTrue(composite.localizedDescription.contains("Simulated commit I/O failure"), file: file, line: line)
    XCTAssertTrue(composite.localizedDescription.contains("Simulated rollback I/O failure"), file: file, line: line)
}

@MainActor
final class CoordinatorStorageFaultTests: XCTestCase {
    // A failed rollback must fence cached reads, lease issuance, and all administration,
    // even with invalid credentials or after native autocommit becomes true again.
    func testEveryActorAPIIsTerminalUntilReopen() async throws {
        for clearTransaction in [false, true] {
            let directory = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remote-actor-fault-\(UUID())")
            defer { try? FileManager.default.removeItem(at: directory) }
            let controller = ControllerID()
            let native = ScriptedSQLiteNative()
            var owner: AdmissionCoordinator? = try AdmissionCoordinator(directory: directory, controllerID: controller, native: native)
            let lease = try await owner!.connect(controllerID: controller)
            let epoch = try await owner!.status().epoch
            let first = MutationRequest(epoch: epoch, controllerID: controller, requestID: RequestID(),
                sessionID: SessionID(), runID: RunID(), kind: .startRun, payload: Data())
            // In one branch retain real committed work to verify reopen recovery.
            if clearTransaction { _ = try await owner!.submit(first, over: lease) }
            let mutation = MutationRequest(epoch: epoch, controllerID: controller, requestID: RequestID(),
                sessionID: first.sessionID, runID: first.runID, kind: clearTransaction ? .stopRun : .startRun, payload: Data())
            native.failNextCommitAndRollback(clearTransaction: clearTransaction)
            do { _ = try await owner!.submit(mutation, over: lease); XCTFail("Expected failed commit") }
            catch { assertTerminalFailure(error) }
            do {
                let coordinator = owner!
                let operations: [@MainActor () async throws -> Void] = [
                    { _ = try await coordinator.status() },
                    { _ = try await coordinator.status(over: lease) },
                    { _ = try await coordinator.connect(controllerID: controller) },
                    { _ = try await coordinator.connect(controllerID: ControllerID()) },
                    { _ = try await coordinator.submit(mutation, over: lease) },
                    { _ = try await coordinator.reconcile(requestID: RequestID(), epoch: StorageEpoch(), over: lease) },
                    { _ = try await coordinator.runStatus(for: first.runID, epoch: epoch) },
                    { _ = try await coordinator.runStatus(for: first.runID, epoch: StorageEpoch(), over: lease) },
                    { try await coordinator.settle(runID: first.runID, epoch: epoch, outcome: .completed) },
                    { try await coordinator.confirmRecoveredProcessesAbsent() },
                    { _ = try await coordinator.reset() }
                ]
                for operation in operations {
                    do { try await operation(); XCTFail("Expected terminal owner") }
                    catch { assertTerminalFailure(error) }
                }
            }
            owner = nil
            let reopened = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let persisted = try await reopened.status()
            XCTAssertEqual(persisted.epoch, epoch)
            XCTAssertEqual(persisted.recoveryRequired, clearTransaction)
            XCTAssertEqual(persisted.activeRun?.state, clearTransaction ? .active : nil)
            let fresh = try await reopened.connect(controllerID: controller)
            let absent = try await reopened.reconcile(requestID: mutation.requestID, epoch: epoch, over: fresh)
            XCTAssertEqual(absent.disposition, .rejectedAbsent)
            if clearTransaction {
                try await reopened.confirmRecoveredProcessesAbsent()
                let settled = try await reopened.runStatus(for: first.runID, epoch: epoch)
                XCTAssertEqual(settled?.outcome, .interruptedUnknown)
            } else {
                let missing = try await reopened.runStatus(for: first.runID, epoch: epoch)
                XCTAssertNil(missing)
            }
        }
    }
}
