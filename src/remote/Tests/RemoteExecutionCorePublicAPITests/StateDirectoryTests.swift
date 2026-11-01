import Darwin
import Foundation
import XCTest
import RemoteExecutionCore

final class StateDirectoryTests: XCTestCase {
    private func fixture(_ body: (URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("remote-private-state-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        try body(root)
    }
    private func mode(_ url: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return try XCTUnwrap(attributes[.posixPermissions] as? NSNumber).intValue
    }
    private func assertUntouched(_ directory: URL, contents: [String], mode expectedMode: Int,
                                 file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), contents.sorted(), file: file, line: line)
        XCTAssertEqual(try mode(directory), expectedMode, file: file, line: line)
    }
    // A default-umask mkdir would disclose journal metadata to other users.
    func testNewStateLeafIsPrivate() throws {
        try fixture { root in
            let leaf = root.appendingPathComponent("state")
            let owner = try AdmissionCoordinator(directory: leaf, controllerID: ControllerID())
            XCTAssertEqual(try mode(leaf), 0o700)
            withExtendedLifetime(owner) {}
        }
    }
    // Validation must precede lock/database creation and must not silently chmod callers' data.
    func testPermissiveExistingLeafIsRejectedWithoutChanges() throws {
        try fixture { root in
            let leaf = root.appendingPathComponent("state")
            try FileManager.default.createDirectory(at: leaf, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
            let marker = leaf.appendingPathComponent("keep")
            try Data("preserve".utf8).write(to: marker)
            XCTAssertThrowsError(try AdmissionCoordinator(directory: leaf, controllerID: ControllerID()))
            try assertUntouched(leaf, contents: ["keep"], mode: 0o755)
            XCTAssertEqual(try Data(contentsOf: marker), Data("preserve".utf8))
        }
    }
    func testSymbolicLinkLeafIsRejectedWithoutTouchingTarget() throws {
        try fixture { root in
            let target = root.appendingPathComponent("target")
            let leaf = root.appendingPathComponent("state")
            try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createSymbolicLink(at: leaf, withDestinationURL: target)
            XCTAssertThrowsError(try AdmissionCoordinator(directory: leaf, controllerID: ControllerID()))
            try assertUntouched(target, contents: [], mode: 0o700)
            XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: leaf.path), target.path)
        }
    }
    func testPrivateExistingLeafIsAccepted() throws {
        try fixture { root in
            let owner = try AdmissionCoordinator(directory: root, controllerID: ControllerID())
            XCTAssertEqual(try mode(root), 0o700)
            withExtendedLifetime(owner) {}
        }
    }
    // POSIX mode 0700 alone does not establish privacy when an ACL grants access.
    func testExtendedAllowACLIsRejectedWithoutRemovingGrant() throws {
        try fixture { root in
            let leaf = root.appendingPathComponent("state")
            try FileManager.default.createDirectory(at: leaf, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let chmod = Process()
            chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
            chmod.arguments = ["+a", "everyone allow read,search", leaf.path]
            try chmod.run()
            chmod.waitUntilExit()
            XCTAssertEqual(chmod.terminationStatus, 0)
            XCTAssertEqual(try mode(leaf), 0o700)
            XCTAssertThrowsError(try AdmissionCoordinator(directory: leaf, controllerID: ControllerID()))
            try assertUntouched(leaf, contents: [], mode: 0o700)
            let acl = try XCTUnwrap(acl_get_file(leaf.path, ACL_TYPE_EXTENDED))
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            var entry: acl_entry_t?
            XCTAssertEqual(acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry), 0)
            var tag = ACL_UNDEFINED_TAG
            XCTAssertEqual(acl_get_tag_type(try XCTUnwrap(entry), &tag), 0)
            XCTAssertEqual(tag, ACL_EXTENDED_ALLOW)
        }
    }
    func testInheritedAllowACLIsRejectedBeforeOpeningStorage() throws {
        try fixture { root in
            let leaf = root.appendingPathComponent("state")
            try FileManager.default.createDirectory(at: leaf, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let chmod = Process()
            chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
            chmod.arguments = ["+ai", "everyone allow read,search", leaf.path]
            try chmod.run()
            chmod.waitUntilExit()
            XCTAssertEqual(chmod.terminationStatus, 0)
            XCTAssertThrowsError(try AdmissionCoordinator(directory: leaf, controllerID: ControllerID())) {
                XCTAssertEqual(($0 as? JournalStorageError)?.kind, .invalidDirectory)
            }
            try assertUntouched(leaf, contents: [], mode: 0o700)
            let acl = try XCTUnwrap(acl_get_file(leaf.path, ACL_TYPE_EXTENDED))
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            var entry: acl_entry_t?
            XCTAssertEqual(acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry), 0)
            var flags: acl_flagset_t?
            XCTAssertEqual(acl_get_flagset_np(UnsafeMutableRawPointer(try XCTUnwrap(entry)), &flags), 0)
            XCTAssertEqual(acl_get_flag_np(try XCTUnwrap(flags), ACL_ENTRY_INHERITED), 1)
        }
    }

    func testDenyOnlyACLIsAcceptedWithoutRemovingDeny() throws {
        try fixture { leaf in
            let chmod = Process()
            chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
            chmod.arguments = ["+a", "everyone deny chown", leaf.path]
            try chmod.run()
            chmod.waitUntilExit()
            XCTAssertEqual(chmod.terminationStatus, 0)
            let owner = try AdmissionCoordinator(directory: leaf, controllerID: ControllerID())
            let acl = try XCTUnwrap(acl_get_file(leaf.path, ACL_TYPE_EXTENDED))
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            var entry: acl_entry_t?
            XCTAssertEqual(acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry), 0)
            var tag = ACL_UNDEFINED_TAG
            XCTAssertEqual(acl_get_tag_type(try XCTUnwrap(entry), &tag), 0)
            XCTAssertEqual(tag, ACL_EXTENDED_DENY)
            withExtendedLifetime(owner) {}
        }
    }

    func testNonDirectoryAndOwnerInaccessibleLeavesAreRejectedWithoutChanges() throws {
        try fixture { root in
            let file = root.appendingPathComponent("file")
            try Data("preserve".utf8).write(to: file)
            XCTAssertThrowsError(try AdmissionCoordinator(directory: file, controllerID: ControllerID())) {
                XCTAssertEqual(($0 as? JournalStorageError)?.kind, .invalidDirectory)
            }
            XCTAssertEqual(try Data(contentsOf: file), Data("preserve".utf8))
            let leaf = root.appendingPathComponent("state")
            try FileManager.default.createDirectory(at: leaf, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o500])
            XCTAssertThrowsError(try AdmissionCoordinator(directory: leaf, controllerID: ControllerID())) {
                XCTAssertEqual(($0 as? JournalStorageError)?.kind, .invalidDirectory)
            }
            try assertUntouched(leaf, contents: [], mode: 0o500)
        }
    }

}
