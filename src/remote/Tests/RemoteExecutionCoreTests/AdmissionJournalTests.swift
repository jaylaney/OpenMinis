import Foundation
import XCTest
@testable import RemoteExecutionCore

final class AdmissionJournalTests: XCTestCase {
    private func fixture(_ body: (URL) throws -> Void) throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("remote-journal-tests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }

    private func request(_ epoch: StorageEpoch, controller: ControllerID = ControllerID(),
                         id: RequestID = RequestID(), session: SessionID = SessionID(),
                         run: RunID = RunID(), kind: MutationKind = .startRun,
                         payload: Data = Data([0, 1, 255])) -> MutationRequest {
        MutationRequest(epoch: epoch, controllerID: controller, requestID: id,
                        sessionID: session, runID: run, kind: kind, payload: payload)
    }

    private func assertAdmissionError(_ expected: AdmissionError,
                                      _ body: () throws -> Void,
                                      file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) {
            XCTAssertEqual($0 as? AdmissionError, expected, file: file, line: line)
        }
    }

    // Catches loss of accepted IDs, metadata, or fingerprints across an actual close/reopen.
    func testAcceptedRequestSurvivesReopen() throws {
        try fixture { directory in
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory)
            let mutation = request(journal!.epoch)
            let accepted = try journal!.record(mutation)
            XCTAssertEqual(accepted.disposition, .admitted)
            XCTAssertEqual(accepted.sessionID, mutation.sessionID)
            XCTAssertEqual(accepted.runID, mutation.runID)
            XCTAssertNotNil(accepted.digest)
            journal = nil
            let reopened = try AdmissionJournal(directory: directory)
            XCTAssertEqual(reopened.epoch, mutation.epoch)
            XCTAssertEqual(try reopened.record(mutation), accepted)
            XCTAssertEqual(try reopened.lookupOrRejectAbsent(mutation.requestID, controllerID: mutation.controllerID), accepted)
        }
    }

    // Catches fingerprints omitting any identity field or payload, including after persistence.
    func testChangedPayloadOrMetadataConflicts() throws {
        try fixture { directory in
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory)
            let original = request(journal!.epoch)
            _ = try journal!.record(original)
            journal = nil
            let reopened = try AdmissionJournal(directory: directory)
            let variants = [
                request(original.epoch, controller: original.controllerID, id: original.requestID, session: original.sessionID, run: original.runID, payload: Data([9])),
                request(original.epoch, controller: original.controllerID, id: original.requestID, session: SessionID(), run: original.runID),
                request(original.epoch, controller: original.controllerID, id: original.requestID, session: original.sessionID, run: RunID()),
                request(original.epoch, controller: original.controllerID, id: original.requestID, session: original.sessionID, run: original.runID, kind: .stopRun)
            ]
            for variant in variants {
                assertAdmissionError(.payloadConflict) { _ = try reopened.record(variant) }
            }
            assertAdmissionError(.wrongController) {
                _ = try reopened.record(request(original.epoch, id: original.requestID))
            }
        }
    }

    // Catches busy rejections being recomputed when the active slot becomes available.
    func testBusyRejectionSurvivesIdleAndReopen() throws {
        try fixture { directory in
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory)
            let first = request(journal!.epoch)
            let busy = request(journal!.epoch, controller: first.controllerID)
            _ = try journal!.record(first)
            XCTAssertEqual(try journal!.record(busy).disposition, .rejectedBusy)
            try journal!.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            XCTAssertEqual(try journal!.record(busy).disposition, .rejectedBusy)
            journal = nil
            let reopened = try AdmissionJournal(directory: directory)
            XCTAssertEqual(try reopened.record(busy).disposition, .rejectedBusy)
            XCTAssertNil(try reopened.runStatus(for: busy.runID))
        }
    }

    // Catches Stop releasing the slot or selecting a later run by session alone.
    func testStopWaitsForSettlementAndDoesNotStopLaterRun() throws {
        try fixture { directory in
            let journal = try AdmissionJournal(directory: directory)
            let first = request(journal.epoch)
            _ = try journal.record(first)
            let stop = request(journal.epoch, controller: first.controllerID, session: first.sessionID, run: first.runID, kind: .stopRun)
            XCTAssertEqual(try journal.record(stop).disposition, .stopRequested)
            XCTAssertEqual(journal.status.activeRun?.state, .stopRequested)
            XCTAssertNil(journal.status.activeRun?.outcome)
            XCTAssertEqual(try journal.record(request(journal.epoch, controller: first.controllerID)).disposition, .rejectedBusy)
            assertAdmissionError(.invalidTransition) { _ = try journal.reset() }
            try journal.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            try journal.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            assertAdmissionError(.invalidTransition) { try journal.settle(runID: first.runID, epoch: first.epoch, outcome: .failed) }
            let later = request(journal.epoch, controller: first.controllerID, session: first.sessionID)
            XCTAssertEqual(try journal.record(later).disposition, .admitted)
            XCTAssertEqual(try journal.record(stop).disposition, .stopRequested)
            let lateStop = request(journal.epoch, controller: first.controllerID, session: first.sessionID, run: first.runID, kind: .stopRun)
            XCTAssertEqual(try journal.record(lateStop).disposition, .rejectedRunUnavailable)
            XCTAssertEqual(journal.status.activeRun?.runID, later.runID)
            XCTAssertEqual(journal.status.activeRun?.state, .active)
            XCTAssertEqual(try journal.runStatus(for: first.runID)?.outcome, .completed)
        }
    }

    // Catches restart silently accepting new work without host-confirmed process absence.
    func testReopenWithActiveRunRequiresRecovery() throws {
        try fixture { directory in
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory)
            let first = request(journal!.epoch)
            _ = try journal!.record(first)
            journal = nil
            let reopened = try AdmissionJournal(directory: directory)
            XCTAssertTrue(reopened.recoveryRequired)
            XCTAssertTrue(reopened.status.recoveryRequired)
            let next = request(reopened.epoch, controller: first.controllerID)
            assertAdmissionError(.recoveryRequired) { _ = try reopened.record(next) }
            assertAdmissionError(.recoveryRequired) { _ = try reopened.reset() }
            let recoveryStop = request(reopened.epoch, controller: first.controllerID, session: first.sessionID, run: first.runID, kind: .stopRun)
            XCTAssertEqual(try reopened.record(recoveryStop).disposition, .stopRequested)
            XCTAssertTrue(reopened.recoveryRequired)
            XCTAssertEqual(reopened.status.activeRun?.state, .stopRequested)
            assertAdmissionError(.wrongController) {
                _ = try reopened.lookupOrRejectAbsent(RequestID(), controllerID: ControllerID())
            }
            try reopened.confirmRecoveredProcessesAbsent()
            XCTAssertFalse(reopened.recoveryRequired)
            XCTAssertEqual(try reopened.runStatus(for: first.runID)?.outcome, .interruptedUnknown)
            XCTAssertEqual(try reopened.record(next).disposition, .admitted)
        }
    }

    // Catches recovery of another run breaking idempotent settlement of a completed run.
    func testRepeatedSettlementRemainsIdempotentWhileAnotherRunNeedsRecovery() throws {
        try fixture { directory in
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory)
            let first = request(journal!.epoch)
            _ = try journal!.record(first)
            try journal!.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            _ = try journal!.record(request(journal!.epoch, controller: first.controllerID))
            journal = nil
            let reopened = try AdmissionJournal(directory: directory)
            XCTAssertTrue(reopened.recoveryRequired)
            try reopened.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            assertAdmissionError(.invalidTransition) { try reopened.settle(runID: first.runID, epoch: first.epoch, outcome: .failed) }
            XCTAssertTrue(reopened.recoveryRequired)
        }
    }

    // Catches an absence result which permits a delayed request to run after idle or reopen.
    func testUnknownRequestBecomesPermanentRejection() throws {
        try fixture { directory in
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory)
            let mutation = request(journal!.epoch)
            let tombstone = try journal!.lookupOrRejectAbsent(mutation.requestID, controllerID: mutation.controllerID)
            XCTAssertEqual(tombstone.disposition, .rejectedAbsent)
            XCTAssertNil(tombstone.sessionID)
            XCTAssertNil(tombstone.runID)
            XCTAssertNil(tombstone.kind)
            XCTAssertNil(tombstone.digest)
            XCTAssertEqual(try journal!.record(mutation), tombstone)
            journal = nil
            let reopened = try AdmissionJournal(directory: directory)
            XCTAssertEqual(try reopened.record(mutation), tombstone)
            XCTAssertNil(reopened.status.activeRun)
        }
    }

    // Catches a delayed old-epoch completion settling a live run which reused its ID after reset.
    func testOldEpochSettlementCannotSettleReusedRunID() throws {
        try fixture { directory in
            let journal = try AdmissionJournal(directory: directory)
            let first = request(journal.epoch)
            XCTAssertEqual(try journal.record(first).disposition, .admitted)
            try journal.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            let nextEpoch = try journal.reset()
            XCTAssertNotEqual(nextEpoch, first.epoch)
            let reused = request(nextEpoch, controller: first.controllerID, run: first.runID)
            XCTAssertEqual(try journal.record(reused).disposition, .admitted)

            assertAdmissionError(.staleEpoch) {
                try journal.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            }
            let stillActive = try journal.runStatus(for: reused.runID)
            XCTAssertEqual(stillActive?.sessionID, reused.sessionID)
            XCTAssertEqual(stillActive?.state, .active)
            XCTAssertNil(stillActive?.outcome)
            XCTAssertEqual(journal.status.activeRun, stillActive)
            XCTAssertEqual(try journal.record(request(nextEpoch, controller: first.controllerID)).disposition, .rejectedBusy)

            try journal.settle(runID: reused.runID, epoch: reused.epoch, outcome: .completed)
            XCTAssertEqual(try journal.runStatus(for: reused.runID)?.outcome, .completed)
            XCTAssertNil(journal.status.activeRun)
        }
    }

    // Catches epoch reuse after reset or disk-state loss, permitting replay in a new namespace.
    func testResetAndFreshDirectoryRejectOldEpoch() throws {
        try fixture { directory in
            let journal = try AdmissionJournal(directory: directory)
            let old = request(journal.epoch)
            _ = try journal.lookupOrRejectAbsent(old.requestID, controllerID: old.controllerID)
            let nextEpoch = try journal.reset()
            XCTAssertNotEqual(nextEpoch, old.epoch)
            assertAdmissionError(.staleEpoch) { _ = try journal.record(old) }
            let updated = request(nextEpoch, controller: old.controllerID, id: old.requestID)
            XCTAssertEqual(try journal.record(updated).disposition, .admitted)
            try fixture { freshDirectory in
                let fresh = try AdmissionJournal(directory: freshDirectory)
                XCTAssertNotEqual(fresh.epoch, nextEpoch)
                assertAdmissionError(.staleEpoch) { _ = try fresh.record(updated) }
            }
        }
    }
}
