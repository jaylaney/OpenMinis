import Foundation
import XCTest
@testable import RemoteExecutionCore

final class AdmissionJournalTests: XCTestCase {
    private let controller = ControllerID()
    private func fixture(_ body: (URL) throws -> Void) throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("remote-journal-tests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }

    private func request(_ epoch: StorageEpoch, controller: ControllerID? = nil,
                         id: RequestID = RequestID(), session: SessionID = SessionID(),
                         run: RunID = RunID(), kind: MutationKind = .startRun,
                         payload: Data = Data([0, 1, 255])) -> MutationRequest {
        MutationRequest(epoch: epoch, controllerID: controller ?? self.controller, requestID: id,
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
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory, controllerID: controller)
            let mutation = request(try journal!.epoch)
            let submission = try journal!.record(mutation)
            XCTAssertFalse(submission.isReplay)
            let accepted = submission.record
            XCTAssertEqual(accepted.disposition, .admitted)
            XCTAssertTrue(try journal!.record(mutation).isReplay)
            XCTAssertEqual(accepted.sessionID, mutation.sessionID)
            XCTAssertEqual(accepted.runID, mutation.runID)
            XCTAssertNotNil(accepted.digest)
            journal = nil
            let reopened = try AdmissionJournal(directory: directory, controllerID: controller)
            XCTAssertEqual(try reopened.epoch, mutation.epoch)
            XCTAssertEqual(try reopened.record(mutation).record, accepted)
            XCTAssertEqual(try reopened.lookupOrRejectAbsent(mutation.requestID, epoch: mutation.epoch, controllerID: mutation.controllerID), accepted)
        }
    }

    // Catches stale reconciliation poisoning or exposing the replacement namespace.
    func testStaleReconciliationCannotCreateReplacementEpochTombstone() throws {
        try fixture { directory in
            let journal = try AdmissionJournal(directory: directory, controllerID: controller)
            let oldEpoch = try journal.epoch
            let replacementEpoch = try journal.reset()
            let id = RequestID()
            assertAdmissionError(.staleEpoch) {
                _ = try journal.lookupOrRejectAbsent(id, epoch: oldEpoch, controllerID: controller)
            }
            let replacement = request(replacementEpoch, id: id)
            let admitted = try journal.record(replacement)
            XCTAssertEqual(admitted.record.disposition, .admitted)
            XCTAssertFalse(admitted.isReplay)
        }
    }

    func testStaleReconciliationCannotReadReplacementEpochRecord() throws {
        try fixture { directory in
            let journal = try AdmissionJournal(directory: directory, controllerID: controller)
            let oldEpoch = try journal.epoch
            let replacementEpoch = try journal.reset()
            let replacement = request(replacementEpoch)
            let admitted = try journal.record(replacement)
            assertAdmissionError(.staleEpoch) {
                _ = try journal.lookupOrRejectAbsent(replacement.requestID, epoch: oldEpoch, controllerID: controller)
            }
            XCTAssertEqual(try journal.lookupOrRejectAbsent(replacement.requestID, epoch: replacementEpoch,
                                                           controllerID: controller), admitted.record)
            XCTAssertEqual(try journal.status.activeRun?.runID, replacement.runID)
        }
    }

    // Catches fingerprints omitting any identity field or payload, including after persistence.
    func testChangedPayloadOrMetadataConflicts() throws {
        try fixture { directory in
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory, controllerID: controller)
            let original = request(try journal!.epoch)
            _ = try journal!.record(original)
            journal = nil
            let reopened = try AdmissionJournal(directory: directory, controllerID: controller)
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
                _ = try reopened.record(request(original.epoch, controller: ControllerID(), id: original.requestID))
            }
        }
    }

    // Catches busy rejections being recomputed when the active slot becomes available.
    func testBusyRejectionSurvivesIdleAndReopen() throws {
        try fixture { directory in
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory, controllerID: controller)
            let first = request(try journal!.epoch)
            let busy = request(try journal!.epoch, controller: first.controllerID)
            _ = try journal!.record(first)
            XCTAssertEqual(try journal!.record(busy).record.disposition, .rejectedBusy)
            try journal!.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            XCTAssertEqual(try journal!.record(busy).record.disposition, .rejectedBusy)
            journal = nil
            let reopened = try AdmissionJournal(directory: directory, controllerID: controller)
            XCTAssertEqual(try reopened.record(busy).record.disposition, .rejectedBusy)
            XCTAssertNil(try reopened.runStatus(for: busy.runID, epoch: try reopened.epoch))
        }
    }

    // Catches Stop releasing the slot or selecting a later run by session alone.
    func testStopWaitsForSettlementAndDoesNotStopLaterRun() throws {
        try fixture { directory in
            let journal = try AdmissionJournal(directory: directory, controllerID: controller)
            let first = request(try journal.epoch)
            _ = try journal.record(first)
            let stop = request(try journal.epoch, controller: first.controllerID, session: first.sessionID, run: first.runID, kind: .stopRun)
            XCTAssertEqual(try journal.record(stop).record.disposition, .stopRequested)
            XCTAssertEqual(try journal.status.activeRun?.state, .stopRequested)
            XCTAssertNil(try journal.status.activeRun?.outcome)
            XCTAssertEqual(try journal.record(request(try journal.epoch, controller: first.controllerID)).record.disposition, .rejectedBusy)
            assertAdmissionError(.invalidTransition) { _ = try journal.reset() }
            try journal.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            try journal.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            assertAdmissionError(.invalidTransition) { try journal.settle(runID: first.runID, epoch: first.epoch, outcome: .failed) }
            let later = request(try journal.epoch, controller: first.controllerID, session: first.sessionID)
            XCTAssertEqual(try journal.record(later).record.disposition, .admitted)
            XCTAssertEqual(try journal.record(stop).record.disposition, .stopRequested)
            let lateStop = request(try journal.epoch, controller: first.controllerID, session: first.sessionID, run: first.runID, kind: .stopRun)
            XCTAssertEqual(try journal.record(lateStop).record.disposition, .rejectedRunUnavailable)
            XCTAssertEqual(try journal.status.activeRun?.runID, later.runID)
            XCTAssertEqual(try journal.status.activeRun?.state, .active)
            XCTAssertEqual(try journal.runStatus(for: first.runID, epoch: try journal.epoch)?.outcome, .completed)
        }
    }

    // Catches restart silently accepting new work without host-confirmed process absence.
    func testReopenWithActiveRunRequiresRecovery() throws {
        try fixture { directory in
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory, controllerID: controller)
            let first = request(try journal!.epoch)
            _ = try journal!.record(first)
            journal = nil
            let reopened = try AdmissionJournal(directory: directory, controllerID: controller)
            XCTAssertTrue(try reopened.recoveryRequired)
            XCTAssertTrue(try reopened.status.recoveryRequired)
            let next = request(try reopened.epoch, controller: first.controllerID)
            XCTAssertEqual(try reopened.record(next).record.disposition, .rejectedBusy)
            assertAdmissionError(.recoveryRequired) { _ = try reopened.reset() }
            let recoveryStop = request(try reopened.epoch, controller: first.controllerID, session: first.sessionID, run: first.runID, kind: .stopRun)
            XCTAssertEqual(try reopened.record(recoveryStop).record.disposition, .stopRequested)
            XCTAssertTrue(try reopened.recoveryRequired)
            XCTAssertEqual(try reopened.status.activeRun?.state, .stopRequested)
            assertAdmissionError(.wrongController) {
                _ = try reopened.lookupOrRejectAbsent(RequestID(), epoch: first.epoch, controllerID: ControllerID())
            }
            try reopened.confirmRecoveredProcessesAbsent()
            XCTAssertFalse(try reopened.recoveryRequired)
            XCTAssertEqual(try reopened.runStatus(for: first.runID, epoch: try reopened.epoch)?.outcome, .interruptedUnknown)
            XCTAssertEqual(try reopened.record(next).record.disposition, .rejectedBusy)
            XCTAssertEqual(try reopened.record(request(try reopened.epoch, controller: first.controllerID)).record.disposition, .admitted)
        }
    }

    // Catches recovery of another run breaking idempotent settlement of a completed run.
    func testRepeatedSettlementRemainsIdempotentWhileAnotherRunNeedsRecovery() throws {
        try fixture { directory in
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory, controllerID: controller)
            let first = request(try journal!.epoch)
            _ = try journal!.record(first)
            try journal!.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            _ = try journal!.record(request(try journal!.epoch, controller: first.controllerID))
            journal = nil
            let reopened = try AdmissionJournal(directory: directory, controllerID: controller)
            XCTAssertTrue(try reopened.recoveryRequired)
            try reopened.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            assertAdmissionError(.invalidTransition) { try reopened.settle(runID: first.runID, epoch: first.epoch, outcome: .failed) }
            XCTAssertTrue(try reopened.recoveryRequired)
        }
    }

    // Catches an absence result which permits a delayed request to run after idle or reopen.
    func testUnknownRequestBecomesPermanentRejection() throws {
        try fixture { directory in
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory, controllerID: controller)
            let mutation = request(try journal!.epoch)
            let tombstone = try journal!.lookupOrRejectAbsent(mutation.requestID, epoch: mutation.epoch, controllerID: mutation.controllerID)
            XCTAssertEqual(tombstone.disposition, .rejectedAbsent)
            XCTAssertNil(tombstone.sessionID)
            XCTAssertNil(tombstone.runID)
            XCTAssertNil(tombstone.kind)
            XCTAssertNil(tombstone.digest)
            XCTAssertEqual(try journal!.record(mutation).record, tombstone)
            journal = nil
            let reopened = try AdmissionJournal(directory: directory, controllerID: controller)
            XCTAssertEqual(try reopened.record(mutation).record, tombstone)
            XCTAssertNil(try reopened.status.activeRun)
        }
    }

    // Catches a delayed old-epoch completion settling a live run which reused its ID after reset.
    func testOldEpochSettlementCannotSettleReusedRunID() throws {
        try fixture { directory in
            let journal = try AdmissionJournal(directory: directory, controllerID: controller)
            let first = request(try journal.epoch)
            XCTAssertEqual(try journal.record(first).record.disposition, .admitted)
            try journal.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            let nextEpoch = try journal.reset()
            XCTAssertNotEqual(nextEpoch, first.epoch)
            let reused = request(nextEpoch, controller: first.controllerID, run: first.runID)
            XCTAssertEqual(try journal.record(reused).record.disposition, .admitted)

            assertAdmissionError(.staleEpoch) {
                try journal.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            }
            let stillActive = try journal.runStatus(for: reused.runID, epoch: try journal.epoch)
            XCTAssertEqual(stillActive?.sessionID, reused.sessionID)
            XCTAssertEqual(stillActive?.state, .active)
            XCTAssertNil(stillActive?.outcome)
            XCTAssertEqual(try journal.status.activeRun, stillActive)
            XCTAssertEqual(try journal.record(request(nextEpoch, controller: first.controllerID)).record.disposition, .rejectedBusy)

            try journal.settle(runID: reused.runID, epoch: reused.epoch, outcome: .completed)
            XCTAssertEqual(try journal.runStatus(for: reused.runID, epoch: try journal.epoch)?.outcome, .completed)
            XCTAssertNil(try journal.status.activeRun)
        }
    }

    // Catches epoch reuse after reset or disk-state loss, permitting replay in a new namespace.
    func testResetAndFreshDirectoryRejectOldEpoch() throws {
        try fixture { directory in
            let journal = try AdmissionJournal(directory: directory, controllerID: controller)
            let old = request(try journal.epoch)
            _ = try journal.lookupOrRejectAbsent(old.requestID, epoch: old.epoch, controllerID: old.controllerID)
            let nextEpoch = try journal.reset()
            XCTAssertNotEqual(nextEpoch, old.epoch)
            assertAdmissionError(.staleEpoch) { _ = try journal.record(old) }
            let updated = request(nextEpoch, controller: old.controllerID, id: old.requestID)
            XCTAssertEqual(try journal.record(updated).record.disposition, .admitted)
            try fixture { freshDirectory in
                let fresh = try AdmissionJournal(directory: freshDirectory, controllerID: controller)
                XCTAssertNotEqual(try fresh.epoch, nextEpoch)
                assertAdmissionError(.staleEpoch) { _ = try fresh.record(updated) }
            }
        }
    }

    func testRecoveryRefusalSurvivesRecoveryAndAnotherReopen() throws {
        try fixture { directory in
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory, controllerID: controller)
            let first = request(try journal!.epoch)
            _ = try journal!.record(first)
            journal = nil
            journal = try AdmissionJournal(directory: directory, controllerID: controller)
            let refused = request(first.epoch)
            let refusal = try journal!.record(refused)
            XCTAssertFalse(refusal.isReplay)
            XCTAssertEqual(refusal.record.disposition, .rejectedBusy)
            try journal!.confirmRecoveredProcessesAbsent()
            journal = nil
            let reopened = try AdmissionJournal(directory: directory, controllerID: controller)
            let replay = try reopened.record(refused)
            XCTAssertTrue(replay.isReplay)
            XCTAssertEqual(replay.record, refusal.record)
            XCTAssertNil(try reopened.runStatus(for: refused.runID, epoch: try reopened.epoch))
            let newSend = try reopened.record(request(first.epoch))
            XCTAssertFalse(newSend.isReplay)
            XCTAssertEqual(newSend.record.disposition, .admitted)
        }
    }

    func testTombstonedStopNeedsNewIDForSameTarget() throws {
        try fixture { directory in
            let journal = try AdmissionJournal(directory: directory, controllerID: controller)
            let start = request(try journal.epoch)
            _ = try journal.record(start)
            let oldStop = request(start.epoch, session: start.sessionID, run: start.runID, kind: .stopRun)
            _ = try journal.lookupOrRejectAbsent(oldStop.requestID, epoch: oldStop.epoch, controllerID: controller)
            let refused = try journal.record(oldStop)
            XCTAssertTrue(refused.isReplay)
            XCTAssertEqual(refused.record.disposition, .rejectedAbsent)
            XCTAssertEqual(try journal.status.activeRun?.state, .active)
            let retry = request(start.epoch, session: start.sessionID, run: start.runID, kind: .stopRun)
            let requested = try journal.record(retry)
            XCTAssertFalse(requested.isReplay)
            XCTAssertEqual(requested.record.disposition, .stopRequested)
            XCTAssertEqual(try journal.status.activeRun?.state, .stopRequested)
            XCTAssertNil(try journal.status.activeRun?.outcome)
        }
    }

    func testFailedSQLiteInitializationReleasesStableLock() throws {
        try fixture { directory in
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let databaseURL = directory.appendingPathComponent("admission.sqlite3")
            let lockURL = directory.appendingPathComponent("admission.lock")
            try Data("invalid SQLite database".utf8).write(to: databaseURL)
            XCTAssertThrowsError(try AdmissionJournal(directory: directory, controllerID: controller)) {
                XCTAssertTrue($0 is JournalStorageError)
            }
            let inode = try FileManager.default.attributesOfItem(atPath: lockURL.path)[.systemFileNumber] as? NSNumber
            XCTAssertNotNil(inode)
            // Repair only the synthetic invalid database, retaining the stable ownership file.
            try FileManager.default.removeItem(at: databaseURL)
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory, controllerID: controller)
            let epoch = try journal!.epoch
            journal = nil
            let reopened = try AdmissionJournal(directory: directory, controllerID: controller)
            XCTAssertEqual(try reopened.epoch, epoch)
            let reopenedInode = try FileManager.default.attributesOfItem(atPath: lockURL.path)[.systemFileNumber] as? NSNumber
            XCTAssertEqual(reopenedInode, inode)
        }
    }
    // Namespace validation must precede decoding even a malformed replacement row.
    func testOldEpochReadAndSettlementRejectBeforeMalformedReplacementDecode() throws {
        try fixture { directory in
            let journal = try AdmissionJournal(directory: directory, controllerID: controller)
            let first = request(try journal.epoch)
            _ = try journal.record(first)
            try journal.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            let nextEpoch = try journal.reset()
            let replacement = request(nextEpoch, run: first.runID)
            _ = try journal.record(replacement)
            // Deliberately corrupt only a disposable fixture, bypassing the kernel API.
            let raw = try SQLiteDatabase(url: JournalStateDirectory.prepare(directory).appendingPathComponent("admission.sqlite3"))
            try raw.execute("UPDATE runs SET session_id = 'not-a-uuid'")
            assertAdmissionError(.staleEpoch) {
                _ = try journal.runStatus(for: first.runID, epoch: first.epoch)
            }
            assertAdmissionError(.staleEpoch) {
                try journal.settle(runID: first.runID, epoch: first.epoch, outcome: .completed)
            }
            XCTAssertThrowsError(try journal.runStatus(for: replacement.runID, epoch: nextEpoch)) {
                XCTAssertEqual(($0 as? JournalStorageError)?.kind, .invalidState)
                XCTAssertFalse($0.localizedDescription.isEmpty)
            }
        }
    }

    // Removing the session check must not stop a correct RunID owned by another session.
    func testWrongSessionStopIsDurablyRejectedForCorrectActiveRun() throws {
        try fixture { directory in
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory, controllerID: controller)
            let start = request(try journal!.epoch)
            _ = try journal!.record(start)
            let before = try journal!.runStatus(for: start.runID, epoch: start.epoch)
            let stop = request(start.epoch, session: SessionID(), run: start.runID, kind: .stopRun)
            let rejection = try journal!.record(stop)
            XCTAssertEqual(rejection.record.disposition, .rejectedRunUnavailable)
            XCTAssertFalse(rejection.isReplay)
            XCTAssertEqual(try journal!.runStatus(for: start.runID, epoch: start.epoch), before)
            XCTAssertTrue(try journal!.record(stop).isReplay)
            journal = nil
            let reopened = try AdmissionJournal(directory: directory, controllerID: controller)
            let replay = try reopened.record(stop)
            XCTAssertTrue(replay.isReplay)
            XCTAssertEqual(replay.record, rejection.record)
            XCTAssertEqual(try reopened.runStatus(for: start.runID, epoch: start.epoch), before)
        }
    }

    // A fresh request ID must not turn a settled run identity back into active work.
    func testFreshStartCannotReuseSettledRunIDAcrossReopen() throws {
        try fixture { directory in
            var journal: AdmissionJournal? = try AdmissionJournal(directory: directory, controllerID: controller)
            let start = request(try journal!.epoch)
            _ = try journal!.record(start)
            try journal!.settle(runID: start.runID, epoch: start.epoch, outcome: .completed)
            let before = try journal!.runStatus(for: start.runID, epoch: start.epoch)
            let reused = request(start.epoch, run: start.runID)
            let rejection = try journal!.record(reused)
            XCTAssertFalse(rejection.isReplay)
            XCTAssertEqual(rejection.record.disposition, .rejectedRunUnavailable)
            XCTAssertEqual(try journal!.runStatus(for: start.runID, epoch: start.epoch), before)
            XCTAssertNil(try journal!.status.activeRun)
            journal = nil
            let reopened = try AdmissionJournal(directory: directory, controllerID: controller)
            let replay = try reopened.record(reused)
            XCTAssertTrue(replay.isReplay)
            XCTAssertEqual(replay.record, rejection.record)
            XCTAssertEqual(try reopened.runStatus(for: start.runID, epoch: start.epoch), before)
            XCTAssertNil(try reopened.status.activeRun)
        }
    }

}
