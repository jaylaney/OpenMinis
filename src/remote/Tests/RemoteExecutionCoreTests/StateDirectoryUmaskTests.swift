import Darwin
import Foundation
import XCTest
@testable import RemoteExecutionCore

@MainActor
final class StateDirectoryUmaskTests: XCTestCase {
    // Only exec'd fixture children change umask; the parent runner is untouched.
    func testRestrictiveUmasksCreateUsablePrivateLeafInIsolatedChildren() throws {
        for mask in ["0177", "0277", "0477", "0677", "0777"] {
            let root = URL(fileURLWithPath: "/private/tmp/openminis-remote-storage-policy-child-\(UUID())")
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
            defer { try? FileManager.default.removeItem(at: root) }
            let child = Process()
            child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
            child.arguments = ["-XCTest", "RemoteExecutionCoreTests.StateDirectoryUmaskTests/testUmaskChildFixture",
                               Bundle(for: StateDirectoryUmaskTests.self).bundlePath]
            var environment = ProcessInfo.processInfo.environment
            environment["OPENMINIS_STORAGE_TEST_MASK"] = mask
            environment["OPENMINIS_STORAGE_TEST_ROOT"] = root.path
            child.environment = environment
            let output = Pipe()
            child.standardOutput = output
            child.standardError = output
            try child.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            child.waitUntilExit()
            let transcript = String(decoding: data, as: UTF8.self)
            XCTAssertEqual(child.terminationStatus, 0, "umask \(mask): \(transcript)")
            XCTAssertTrue(transcript.contains("OPENMINIS_STORAGE_UMASK_FIXTURE_COMPLETED:\(mask)"),
                          "Selected child fixture did not finish: \(transcript)")
        }
    }

    func testUmaskChildFixture() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let rawMask = environment["OPENMINIS_STORAGE_TEST_MASK"],
              let mask = UInt16(rawMask, radix: 8),
              let path = environment["OPENMINIS_STORAGE_TEST_ROOT"] else {
            throw XCTSkip("Executed only in an isolated umask fixture child")
        }
        let root = URL(fileURLWithPath: path)
        let restrictive = root.appendingPathComponent("existing")
        XCTAssertEqual(mkdir(restrictive.path, 0o700), 0)
        XCTAssertEqual(chmod(restrictive.path, 0o500), 0)
        umask(mode_t(mask)) // Child-only, after exec; no Foundation-after-fork path.
        let leaf = try JournalStateDirectory.prepare(root.appendingPathComponent("state"))
        var info = stat()
        XCTAssertEqual(lstat(leaf.path, &info), 0)
        XCTAssertEqual(info.st_mode & 0o7777, 0o700)
        // Reopening and a directory descriptor require the normalized owner bits.
        _ = try JournalStateDirectory.prepare(leaf)
        let descriptor = open(leaf.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        if descriptor >= 0 { close(descriptor) }
        // Removing owner-bit normalization strands the lock or main file on reopen.
        let controller = ControllerID()
        let epoch: StorageEpoch
        let mutation: MutationRequest
        var lockInfo = stat()
        do {
            let owner = try AdmissionCoordinator(directory: leaf, controllerID: controller)
            epoch = try await owner.status().epoch
            let lease = try await owner.connect(controllerID: controller)
            mutation = MutationRequest(epoch: epoch, controllerID: controller, requestID: RequestID(),
                sessionID: SessionID(), runID: RunID(), kind: .startRun, payload: Data([1, 2, 3]))
            let admitted = try await owner.submit(mutation, over: lease)
            XCTAssertEqual(admitted.record.disposition, .admitted)
            try await owner.settle(runID: mutation.runID, epoch: epoch, outcome: .completed)
            XCTAssertEqual(lstat(leaf.appendingPathComponent("admission.lock").path, &lockInfo), 0)
            for name in ["admission.lock", "admission.sqlite3"] {
                XCTAssertEqual(lstat(leaf.appendingPathComponent(name).path, &info), 0)
                XCTAssertEqual(info.st_mode & 0o7777, 0o600)
            }
        }
        let reopened = try AdmissionCoordinator(directory: leaf, controllerID: controller)
        let reopenedStatus = try await reopened.status()
        XCTAssertEqual(reopenedStatus.epoch, epoch)
        XCTAssertFalse(reopenedStatus.recoveryRequired)
        XCTAssertNil(reopenedStatus.activeRun)
        let settled = try await reopened.runStatus(for: mutation.runID, epoch: epoch)
        XCTAssertEqual(settled?.outcome, .completed)
        let lease = try await reopened.connect(controllerID: controller)
        let replay = try await reopened.submit(mutation, over: lease)
        XCTAssertTrue(replay.isReplay)
        let next = MutationRequest(epoch: epoch, controllerID: controller, requestID: RequestID(),
            sessionID: SessionID(), runID: RunID(), kind: .startRun, payload: Data([4, 5, 6]))
        let nextAdmission = try await reopened.submit(next, over: lease)
        XCTAssertEqual(nextAdmission.record.disposition, .admitted)
        try await reopened.settle(runID: next.runID, epoch: epoch, outcome: .completed)
        XCTAssertEqual(lstat(leaf.appendingPathComponent("admission.lock").path, &info), 0)
        XCTAssertEqual(info.st_ino, lockInfo.st_ino)
        XCTAssertThrowsError(try JournalStateDirectory.prepare(restrictive))
        XCTAssertEqual(lstat(restrictive.path, &info), 0)
        XCTAssertEqual(info.st_mode & 0o7777, 0o500)
        print("OPENMINIS_STORAGE_UMASK_FIXTURE_COMPLETED:\(rawMask)")
    }
}
