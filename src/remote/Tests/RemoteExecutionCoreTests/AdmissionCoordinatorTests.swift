import Foundation
import XCTest
@testable import RemoteExecutionCore

/// Orders delivery without sleeps: tests release the send only after replacement/reconciliation.
private actor DeliveryGate {
    private var delivery: CheckedContinuation<Void, Never>?
    private var observer: CheckedContinuation<Void, Never>?
    private var blocked = false

    func wait() async {
        await withCheckedContinuation { continuation in
            delivery = continuation
            blocked = true
            observer?.resume()
            observer = nil
        }
    }
    func waitUntilBlocked() async {
        if blocked { return }
        await withCheckedContinuation { observer = $0 }
    }
    func release() { delivery?.resume(); delivery = nil }
}

@MainActor
final class AdmissionCoordinatorTests: XCTestCase {
    private func fixture(_ body: @MainActor (URL) async throws -> Void) async throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("remote-coordinator-tests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        try await body(directory)
    }

    private func request(_ epoch: StorageEpoch, controller: ControllerID,
                         id: RequestID = RequestID(), session: SessionID = SessionID(),
                         run: RunID = RunID(), kind: MutationKind = .startRun) -> MutationRequest {
        MutationRequest(epoch: epoch, controllerID: controller, requestID: id,
                        sessionID: session, runID: run, kind: kind, payload: Data([0, 1, 255]))
    }

    private func assertError(_ expected: AdmissionError,
                             _ body: @MainActor () async throws -> Void,
                             file: StaticString = #filePath, line: UInt = #line) async {
        do {
            try await body()
            XCTFail("Expected \(expected)", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? AdmissionError, expected, file: file, line: line)
        }
    }

    // Removing token replacement would admit the explicitly delayed original channel.
    func testReplacingLeaseFencesDelayedOriginal() async throws {
        try await fixture { directory in
            let controller = ControllerID()
            let coordinator = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let first = try await coordinator.connect(controllerID: controller)
            let mutation = request(await coordinator.status().epoch, controller: controller)
            let gate = DeliveryGate()
            let delayed = Task {
                await gate.wait()
                return try await coordinator.submit(mutation, over: first)
            }
            await gate.waitUntilBlocked()
            let replacement = try await coordinator.connect(controllerID: controller)
            await gate.release()
            await assertError(.staleConnection) { _ = try await delayed.value }
            let status = await coordinator.status()
            XCTAssertNil(status.activeRun)
            let admitted = try await coordinator.submit(mutation, over: replacement)
            XCTAssertEqual(admitted.record.disposition, .admitted)
        }
    }

    // Removing durable absence insertion would admit the delayed send even on a valid lease.
    func testAbsentLookupTombstonesRequestBeforeNewSend() async throws {
        try await fixture { directory in
            let controller = ControllerID()
            let coordinator = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let original = try await coordinator.connect(controllerID: controller)
            let mutation = request(await coordinator.status().epoch, controller: controller)
            let gate = DeliveryGate()
            let delayed = Task {
                await gate.wait()
                return try await coordinator.submit(mutation, over: original)
            }
            await gate.waitUntilBlocked()
            let current = try await coordinator.connect(controllerID: controller)
            let absent = try await coordinator.reconcile(requestID: mutation.requestID, epoch: mutation.epoch, over: current)
            XCTAssertEqual(absent.disposition, .rejectedAbsent)
            XCTAssertNil(absent.digest)
            await gate.release()
            await assertError(.staleConnection) { _ = try await delayed.value }
            let retry = try await coordinator.submit(mutation, over: current)
            XCTAssertEqual(retry.record, absent)
            XCTAssertTrue(retry.isReplay)
            let status = await coordinator.status()
            XCTAssertNil(status.activeRun)
        }
    }

    // In-memory-only tombstones or reconnect state clearing would allow this ID to execute.
    func testTombstoneSurvivesReconnectAndReopen() async throws {
        try await fixture { directory in
            let controller = ControllerID()
            var coordinator: AdmissionCoordinator? = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let lease = try await coordinator!.connect(controllerID: controller)
            let mutation = request(await coordinator!.status().epoch, controller: controller)
            let absent = try await coordinator!.reconcile(requestID: mutation.requestID, epoch: mutation.epoch, over: lease)
            let reconnected = try await coordinator!.connect(controllerID: controller)
            let retry = try await coordinator!.submit(mutation, over: reconnected)
            XCTAssertEqual(retry.record, absent)
            XCTAssertTrue(retry.isReplay)
            coordinator = nil
            let reopened = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let freshLease = try await reopened.connect(controllerID: controller)
            let persisted = try await reopened.submit(mutation, over: freshLease)
            XCTAssertEqual(persisted.record, absent)
            XCTAssertTrue(persisted.isReplay)
            let lookup = try await reopened.reconcile(requestID: mutation.requestID, epoch: mutation.epoch, over: freshLease)
            XCTAssertEqual(lookup, absent)
            let status = await reopened.status()
            XCTAssertNil(status.activeRun)
        }
    }

    // A foreign connect must neither replace the valid lease nor persist a foreign mutation.
    func testWrongControllerCannotConnectOrMutate() async throws {
        try await fixture { directory in
            let controller = ControllerID()
            let coordinator = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let valid = try await coordinator.connect(controllerID: controller)
            let foreign = ControllerID()
            await assertError(.wrongController) { _ = try await coordinator.connect(controllerID: foreign) }
            let epoch = await coordinator.status().epoch
            let foreignMutation = request(epoch, controller: foreign)
            await assertError(.wrongController) { _ = try await coordinator.submit(foreignMutation, over: valid) }
            let authorized = request(epoch, controller: controller, id: foreignMutation.requestID)
            let admitted = try await coordinator.submit(authorized, over: valid)
            XCTAssertEqual(admitted.record.disposition, .admitted)
            let foreignCoordinator = try AdmissionCoordinator(directory: directory.appendingPathComponent("other"), controllerID: foreign)
            let foreignLease = try await foreignCoordinator.connect(controllerID: foreign)
            let unknown = RequestID()
            await assertError(.wrongController) {
                _ = try await coordinator.reconcile(requestID: unknown, epoch: epoch, over: foreignLease)
            }
            let stop = request(epoch, controller: controller, id: unknown, session: authorized.sessionID,
                               run: authorized.runID, kind: .stopRun)
            let stopped = try await coordinator.submit(stop, over: valid)
            XCTAssertEqual(stopped.record.disposition, .stopRequested)
        }
    }

    // Binding only on the first request would let an unused configured database change owners.
    func testConfiguredControllerMustMatchPersistedBinding() async throws {
        try await fixture { directory in
            let controller = ControllerID()
            var first: AdmissionCoordinator? = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let epoch = await first!.status().epoch
            first = nil
            XCTAssertThrowsError(try AdmissionCoordinator(directory: directory, controllerID: ControllerID())) {
                XCTAssertEqual($0 as? AdmissionError, .wrongController)
            }
            let reopened = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let status = await reopened.status()
            XCTAssertEqual(status.epoch, epoch)
            let lease = try await reopened.connect(controllerID: controller)
            let accepted = try await reopened.submit(request(epoch, controller: controller), over: lease)
            XCTAssertEqual(accepted.record.disposition, .admitted)
        }
    }

    // Missing epoch validation on reconcile would write a tombstone into the current namespace.
    func testStaleEpochCannotSubmitOrReconcile() async throws {
        try await fixture { directory in
            let controller = ControllerID()
            let coordinator = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let lease = try await coordinator.connect(controllerID: controller)
            let old = request(StorageEpoch(), controller: controller)
            await assertError(.staleEpoch) { _ = try await coordinator.submit(old, over: lease) }
            await assertError(.staleEpoch) {
                _ = try await coordinator.reconcile(requestID: old.requestID, epoch: old.epoch, over: lease)
            }
            let epoch = await coordinator.status().epoch
            let current = request(epoch, controller: controller, id: old.requestID)
            let accepted = try await coordinator.submit(current, over: lease)
            XCTAssertEqual(accepted.record.disposition, .admitted)
        }
    }

    // Stop acknowledgement must leave the slot occupied; a late Stop must not stop a later run.
    func testStopAndSettlementRemainRunScoped() async throws {
        try await fixture { directory in
            let controller = ControllerID()
            let coordinator = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let lease = try await coordinator.connect(controllerID: controller)
            let epoch = await coordinator.status().epoch
            let first = request(epoch, controller: controller)
            let admitted = try await coordinator.submit(first, over: lease)
            XCTAssertEqual(admitted.record.disposition, .admitted)
            let reconciled = try await coordinator.reconcile(requestID: first.requestID, epoch: epoch, over: lease)
            XCTAssertEqual(reconciled, admitted.record)
            let stop = request(epoch, controller: controller, session: first.sessionID, run: first.runID, kind: .stopRun)
            let stopRecord = try await coordinator.submit(stop, over: lease)
            XCTAssertEqual(stopRecord.record.disposition, .stopRequested)
            let pending = try await coordinator.runStatus(for: first.runID)
            XCTAssertEqual(pending?.state, .stopRequested)
            XCTAssertNil(pending?.outcome)
            let busy = try await coordinator.submit(request(epoch, controller: controller), over: lease)
            XCTAssertEqual(busy.record.disposition, .rejectedBusy)
            try await coordinator.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            let later = request(epoch, controller: controller, session: first.sessionID)
            _ = try await coordinator.submit(later, over: lease)
            let lateStop = request(epoch, controller: controller, session: first.sessionID, run: first.runID, kind: .stopRun)
            let rejected = try await coordinator.submit(lateStop, over: lease)
            XCTAssertEqual(rejected.record.disposition, .rejectedRunUnavailable)
            let status = await coordinator.status()
            XCTAssertEqual(status.activeRun?.runID, later.runID)
            XCTAssertEqual(status.activeRun?.state, .active)
            let settled = try await coordinator.runStatus(for: first.runID)
            XCTAssertEqual(settled?.outcome, .completed)
        }
    }

    // Catches an old completion crossing reset even when the host correctly observed termination.
    func testOldEpochSettlementCannotSettleReusedRunID() async throws {
        try await fixture { directory in
            let controller = ControllerID()
            let coordinator = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let lease = try await coordinator.connect(controllerID: controller)
            let first = request(await coordinator.status().epoch, controller: controller)
            let admitted = try await coordinator.submit(first, over: lease)
            XCTAssertEqual(admitted.record.disposition, .admitted)
            _ = try await coordinator.connect(controllerID: controller)
            try await coordinator.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            let nextEpoch = try await coordinator.reset()
            XCTAssertNotEqual(nextEpoch, first.epoch)
            let current = try await coordinator.connect(controllerID: controller)
            let reused = request(nextEpoch, controller: controller, run: first.runID)
            let readmitted = try await coordinator.submit(reused, over: current)
            XCTAssertEqual(readmitted.record.disposition, .admitted)

            await assertError(.staleEpoch) {
                try await coordinator.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            }
            let stillActive = try await coordinator.runStatus(for: reused.runID)
            XCTAssertEqual(stillActive?.sessionID, reused.sessionID)
            XCTAssertEqual(stillActive?.state, .active)
            XCTAssertNil(stillActive?.outcome)
            let status = await coordinator.status()
            XCTAssertEqual(status.activeRun, stillActive)
            let busy = try await coordinator.submit(request(nextEpoch, controller: controller), over: current)
            XCTAssertEqual(busy.record.disposition, .rejectedBusy)

            try await coordinator.settle(runID: reused.runID, epoch: reused.epoch, outcome: .completed)
            let settled = try await coordinator.runStatus(for: reused.runID)
            XCTAssertEqual(settled?.outcome, .completed)
            let idle = await coordinator.status()
            XCTAssertNil(idle.activeRun)
        }
    }

    // Recovery and reset must fence old leases, and recovery cannot be inferred by this core.
    func testRecoveryAndResetInvalidateOldLeases() async throws {
        try await fixture { directory in
            let controller = ControllerID()
            var first: AdmissionCoordinator? = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let originalLease = try await first!.connect(controllerID: controller)
            let mutation = request(await first!.status().epoch, controller: controller)
            _ = try await first!.submit(mutation, over: originalLease)
            first = nil
            let reopened = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let recoveryLease = try await reopened.connect(controllerID: controller)
            let recoveredStatus = await reopened.status()
            XCTAssertTrue(recoveredStatus.recoveryRequired)
            let next = request(mutation.epoch, controller: controller)
            await assertError(.staleConnection) { _ = try await reopened.submit(next, over: originalLease) }
            let refused = try await reopened.submit(next, over: recoveryLease)
            XCTAssertEqual(refused.record.disposition, .rejectedBusy)
            await assertError(.recoveryRequired) { _ = try await reopened.reset() }
            let recoveryStop = request(mutation.epoch, controller: controller, session: mutation.sessionID,
                                       run: mutation.runID, kind: .stopRun)
            let stop = try await reopened.submit(recoveryStop, over: recoveryLease)
            XCTAssertEqual(stop.record.disposition, .stopRequested)
            try await reopened.confirmRecoveredProcessesAbsent()
            await assertError(.staleConnection) { _ = try await reopened.submit(next, over: recoveryLease) }
            let afterRecovery = try await reopened.connect(controllerID: controller)
            let recovered = try await reopened.runStatus(for: mutation.runID)
            XCTAssertEqual(recovered?.outcome, .interruptedUnknown)
            let newEpoch = try await reopened.reset()
            XCTAssertNotEqual(newEpoch, mutation.epoch)
            await assertError(.staleConnection) {
                _ = try await reopened.reconcile(requestID: next.requestID, epoch: newEpoch, over: afterRecovery)
            }
            let afterReset = try await reopened.connect(controllerID: controller)
            await assertError(.staleEpoch) { _ = try await reopened.submit(next, over: afterReset) }
            let fresh = request(newEpoch, controller: controller, id: next.requestID)
            let accepted = try await reopened.submit(fresh, over: afterReset)
            XCTAssertEqual(accepted.record.disposition, .admitted)
        }
    }

    // A no-op absence confirmation must preserve both idle and live connection authority.
    func testNoOpRecoveryPreservesLease() async throws {
        try await fixture { directory in
            let controller = ControllerID()
            let coordinator = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let lease = try await coordinator.connect(controllerID: controller)
            let start = request(await coordinator.status().epoch, controller: controller)
            try await coordinator.confirmRecoveredProcessesAbsent()
            _ = try await coordinator.submit(start, over: lease)
            try await coordinator.confirmRecoveredProcessesAbsent()
            let stop = request(start.epoch, controller: controller, session: start.sessionID,
                               run: start.runID, kind: .stopRun)
            let result = try await coordinator.submit(stop, over: lease)
            XCTAssertEqual(result.record.disposition, .stopRequested)
        }
    }

    // A second connection owner must fail before touching live state or channel authority.
    func testConcurrentOwnersAreRejectedWithoutDisturbingLease() async throws {
        try await fixture { directory in
            let controller = ControllerID()
            var owner: AdmissionCoordinator? = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let lease = try await owner!.connect(controllerID: controller)
            let start = request(await owner!.status().epoch, controller: controller)
            _ = try await owner!.submit(start, over: lease)
            for candidate in [controller, ControllerID()] {
                XCTAssertThrowsError(try AdmissionCoordinator(directory: directory, controllerID: candidate)) {
                    XCTAssertTrue($0 is JournalStorageError)
                    XCTAssertTrue(String(describing: $0).contains("already owned"))
                }
            }
            let stop = request(start.epoch, controller: controller, session: start.sessionID,
                               run: start.runID, kind: .stopRun)
            _ = try await owner!.submit(stop, over: lease)
            try await owner!.settle(runID: start.runID, epoch: start.epoch, outcome: .completed)
            owner = nil
            let reopened = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let status = await reopened.status()
            XCTAssertEqual(status.epoch, start.epoch)
            XCTAssertFalse(status.recoveryRequired)
            let settled = try await reopened.runStatus(for: start.runID)
            XCTAssertEqual(settled?.outcome, .completed)
        }
    }

    // Rejecting a wrong configured controller must leave recovery untouched, and release ownership.
    func testFailedControllerInitializationDoesNotMutateRecovery() async throws {
        try await fixture { directory in
            let controller = ControllerID()
            var owner: AdmissionCoordinator? = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let lease = try await owner!.connect(controllerID: controller)
            let start = request(await owner!.status().epoch, controller: controller)
            _ = try await owner!.submit(start, over: lease)
            owner = nil
            func recoveryValue() throws -> String? {
                let raw = try SQLiteDatabase(url: directory.appendingPathComponent("admission.sqlite3"))
                return try raw.query("SELECT recovery FROM journal").first?[0]
            }
            XCTAssertEqual(try recoveryValue(), "0")
            XCTAssertThrowsError(try AdmissionCoordinator(directory: directory, controllerID: ControllerID())) {
                XCTAssertEqual($0 as? AdmissionError, .wrongController)
            }
            XCTAssertEqual(try recoveryValue(), "0")
            let reopened = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let status = await reopened.status()
            XCTAssertEqual(status.epoch, start.epoch)
            XCTAssertTrue(status.recoveryRequired)
            XCTAssertEqual(status.activeRun?.runID, start.runID)
        }
    }

    // Only the first insertion is a new admission; reconnect/reopen never reauthorizes launch.
    func testSubmissionMarksAdmittedAndAbsentReplays() async throws {
        try await fixture { directory in
            let controller = ControllerID()
            var owner: AdmissionCoordinator? = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let lease = try await owner!.connect(controllerID: controller)
            let start = request(await owner!.status().epoch, controller: controller)
            let first = try await owner!.submit(start, over: lease)
            XCTAssertFalse(first.isReplay)
            XCTAssertEqual(first.record.disposition, .admitted)
            let duplicate = try await owner!.submit(start, over: lease)
            XCTAssertTrue(duplicate.isReplay)
            XCTAssertEqual(duplicate.record, first.record)
            let replacement = try await owner!.connect(controllerID: controller)
            let reconnected = try await owner!.submit(start, over: replacement)
            XCTAssertTrue(reconnected.isReplay)
            XCTAssertEqual(reconnected.record, first.record)
            let absent = request(start.epoch, controller: controller)
            let tombstone = try await owner!.reconcile(requestID: absent.requestID, epoch: absent.epoch, over: replacement)
            let refused = try await owner!.submit(absent, over: replacement)
            XCTAssertTrue(refused.isReplay)
            XCTAssertEqual(refused.record, tombstone)
            owner = nil
            let reopened = try AdmissionCoordinator(directory: directory, controllerID: controller)
            let current = try await reopened.connect(controllerID: controller)
            let persisted = try await reopened.submit(start, over: current)
            XCTAssertTrue(persisted.isReplay)
            XCTAssertEqual(persisted.record, first.record)
            let persistedAbsent = try await reopened.submit(absent, over: current)
            XCTAssertTrue(persistedAbsent.isReplay)
            XCTAssertEqual(persistedAbsent.record, tombstone)
        }
    }
}
