import Darwin
import Foundation
import XCTest
@testable import RemoteExecutionCore

final class StateDirectoryUmaskTests: XCTestCase {
    // Only exec'd fixture children change umask; the parent runner is untouched.
    func testRestrictiveUmasksCreateUsablePrivateLeafInIsolatedChildren() throws {
        for mask in ["0177", "0777"] {
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

    func testUmaskChildFixture() throws {
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
        // Qualify the reported mask through the public owner as well. The 0777
        // case covers directory preparation only; file-mode hardening is deferred.
        if mask == 0o177 {
            let controller = ControllerID()
            do {
                let owner = try AdmissionCoordinator(directory: leaf, controllerID: controller)
                withExtendedLifetime(owner) {}
            }
            let reopened = try AdmissionCoordinator(directory: leaf, controllerID: controller)
            withExtendedLifetime(reopened) {}
        }
        XCTAssertThrowsError(try JournalStateDirectory.prepare(restrictive))
        XCTAssertEqual(lstat(restrictive.path, &info), 0)
        XCTAssertEqual(info.st_mode & 0o7777, 0o500)
        print("OPENMINIS_STORAGE_UMASK_FIXTURE_COMPLETED:\(rawMask)")
    }
}
