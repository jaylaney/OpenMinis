import Darwin
import Foundation
import XCTest
import RemoteExecutionCore

@MainActor
final class HostBoundaryAPITests: XCTestCase {
    private func fixture(_ body: @MainActor (URL) async throws -> Void) async throws {
        let leaf = FileManager.default.temporaryDirectory.appendingPathComponent("remote-public-api-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: leaf) }
        try await body(leaf)
    }
    private func request(_ epoch: StorageEpoch, controller: ControllerID, run: RunID = RunID()) -> MutationRequest {
        MutationRequest(epoch: epoch, controllerID: controller, requestID: RequestID(),
                        sessionID: SessionID(), runID: run, kind: .startRun, payload: Data([1]))
    }
    private func expect(_ expected: AdmissionError, _ body: () async throws -> Void,
                        file: StaticString = #filePath, line: UInt = #line) async {
        do { try await body(); XCTFail("Expected \(expected)", file: file, line: line) }
        catch { XCTAssertEqual(error as? AdmissionError, expected, file: file, line: line) }
    }
    // A non-testable importer must be able to classify actual initialization failures.
    func testPublicInitializationErrorsCarryStableKindsAndCodes() async throws {
        try await fixture { leaf in
            let controller = ControllerID()
            let owner = try AdmissionCoordinator(directory: leaf, controllerID: controller)
            XCTAssertThrowsError(try AdmissionCoordinator(directory: leaf, controllerID: controller)) { error in
                guard let storage = error as? JournalStorageError else { return XCTFail("Unexpected \(error)") }
                XCTAssertEqual(storage.kind, .alreadyOwned)
                XCTAssertEqual(storage.posixCode, EWOULDBLOCK)
                XCTAssertNil(storage.sqliteCode)
                XCTAssertTrue(storage.localizedDescription.contains("owned"))
            }
            withExtendedLifetime(owner) {}
        }
        try await fixture { leaf in
            try FileManager.default.createDirectory(at: leaf, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try Data("invalid SQLite database".utf8).write(to: leaf.appendingPathComponent("admission.sqlite3"))
            XCTAssertThrowsError(try AdmissionCoordinator(directory: leaf, controllerID: ControllerID())) { error in
                guard let storage = error as? JournalStorageError else { return XCTFail("Unexpected \(error)") }
                XCTAssertEqual(storage.kind, .sqlite)
                XCTAssertEqual(storage.sqliteCode, 26) // SQLITE_NOTADB
                XCTAssertEqual(storage.sqliteExtendedCode, 26)
                XCTAssertNil(storage.posixCode)
                XCTAssertFalse(storage.message.isEmpty)
                XCTAssertEqual(storage.localizedDescription, storage.message)
            }
        }
        try await fixture { leaf in
            try FileManager.default.createDirectory(at: leaf, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
            XCTAssertThrowsError(try AdmissionCoordinator(directory: leaf, controllerID: ControllerID())) { error in
                guard let storage = error as? JournalStorageError else { return XCTFail("Unexpected \(error)") }
                XCTAssertEqual(storage.kind, .invalidDirectory)
                XCTAssertNil(storage.sqliteCode)
                XCTAssertFalse(storage.localizedDescription.isEmpty)
            }
        }
        try await fixture { leaf in
            XCTAssertThrowsError(try AdmissionCoordinator(directory: leaf.appendingPathComponent("missing-parent/leaf"), controllerID: ControllerID())) { error in
                guard let storage = error as? JournalStorageError else { return XCTFail("Unexpected \(error)") }
                XCTAssertEqual(storage.kind, .filesystem)
                XCTAssertEqual(storage.posixCode, ENOENT)
            }
        }
    }
    // Constructed composite verifies the public diagnostic contract, not rollback I/O.
    func testPublicCompositeRetainsBothCauses() {
        let rollback = JournalStorageError(kind: .sqlite, message: "synthetic rollback failure", sqliteCode: 10, sqliteExtendedCode: 10)
        let composite = JournalTransactionError(originalError: AdmissionError.invalidTransition, rollbackError: rollback)
        XCTAssertEqual(composite.originalError as? AdmissionError, .invalidTransition)
        XCTAssertEqual((composite.rollbackError as? JournalStorageError)?.sqliteCode, 10)
        XCTAssertTrue(composite.localizedDescription.contains("Run state transition is invalid"))
        XCTAssertTrue(composite.localizedDescription.contains("synthetic rollback failure"))
        XCTAssertFalse((composite as any Error) is AdmissionError)
    }
    // Status bootstrap needs no known epoch, but all connection reads require the current lease.
    func testReadLeasesFenceReplacementResetAndForeignControllers() async throws {
        try await fixture { leaf in
            let controller = ControllerID()
            let owner = try AdmissionCoordinator(directory: leaf, controllerID: controller)
            let original = try await owner.connect(controllerID: controller)
            let initial = try await owner.status(over: original)
            let start = request(initial.epoch, controller: controller)
            _ = try await owner.submit(start, over: original)
            let current = try await owner.connect(controllerID: controller)
            await expect(.staleConnection) { _ = try await owner.status(over: original) }
            await expect(.staleConnection) { _ = try await owner.runStatus(for: start.runID, epoch: initial.epoch, over: original) }
            let run = try await owner.runStatus(for: start.runID, epoch: initial.epoch, over: current)
            XCTAssertEqual(run?.epoch, initial.epoch)
            XCTAssertEqual(run?.sessionID, start.sessionID)
            let trusted = try await owner.runStatus(for: start.runID, epoch: initial.epoch)
            XCTAssertEqual(trusted, run)
            let active = try await owner.status(over: current)
            XCTAssertEqual(active.activeRun?.epoch, initial.epoch)
            let foreignController = ControllerID()
            let foreign = try AdmissionCoordinator(directory: leaf.appendingPathComponent("foreign"), controllerID: foreignController)
            let foreignLease = try await foreign.connect(controllerID: foreignController)
            await expect(.wrongController) { _ = try await owner.status(over: foreignLease) }
            await expect(.wrongController) { _ = try await owner.runStatus(for: start.runID, epoch: initial.epoch, over: foreignLease) }
            // A lease from another coordinator with the same controller is still stale.
            let other = try AdmissionCoordinator(directory: leaf.appendingPathComponent("other"), controllerID: controller)
            let otherLease = try await other.connect(controllerID: controller)
            await expect(.staleConnection) { _ = try await owner.status(over: otherLease) }
            try await owner.settle(runID: start.runID, epoch: initial.epoch, outcome: .completed)
            let next = try await owner.reset()
            await expect(.staleConnection) { _ = try await owner.status(over: current) }
            await expect(.staleConnection) { _ = try await owner.runStatus(for: start.runID, epoch: next, over: current) }
            let fresh = try await owner.connect(controllerID: controller)
            let bootstrap = try await owner.status(over: fresh)
            XCTAssertEqual(bootstrap.epoch, next)
            let reused = request(next, controller: controller, run: start.runID)
            _ = try await owner.submit(reused, over: fresh)
            await expect(.staleEpoch) { _ = try await owner.runStatus(for: reused.runID, epoch: initial.epoch) }
            await expect(.staleEpoch) { _ = try await owner.runStatus(for: reused.runID, epoch: initial.epoch, over: fresh) }
            let replacement = try await owner.runStatus(for: reused.runID, epoch: next, over: fresh)
            XCTAssertEqual(replacement?.epoch, next)
            XCTAssertEqual(replacement?.sessionID, reused.sessionID)
        }
    }
    func testRecoveryFencesReadLeasesAndPreservesInterruptedUnknown() async throws {
        try await fixture { leaf in
            let controller = ControllerID()
            var first: AdmissionCoordinator? = try AdmissionCoordinator(directory: leaf, controllerID: controller)
            let old = try await first!.connect(controllerID: controller)
            let start = request(try await first!.status().epoch, controller: controller)
            _ = try await first!.submit(start, over: old)
            first = nil
            let owner = try AdmissionCoordinator(directory: leaf, controllerID: controller)
            await expect(.staleConnection) { _ = try await owner.status(over: old) }
            let recovery = try await owner.connect(controllerID: controller)
            let recovering = try await owner.status(over: recovery)
            XCTAssertTrue(recovering.recoveryRequired)
            try await owner.confirmRecoveredProcessesAbsent()
            await expect(.staleConnection) { _ = try await owner.status(over: recovery) }
            await expect(.staleConnection) { _ = try await owner.runStatus(for: start.runID, epoch: start.epoch, over: recovery) }
            let fresh = try await owner.connect(controllerID: controller)
            let recovered = try await owner.runStatus(for: start.runID, epoch: start.epoch, over: fresh)
            XCTAssertEqual(recovered?.epoch, start.epoch)
            XCTAssertEqual(recovered?.outcome, .interruptedUnknown)
        }
    }
}
