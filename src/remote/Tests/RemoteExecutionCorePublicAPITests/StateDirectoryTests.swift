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

    func testNonDirectoryAndMissingOwnerModeBitsAreRejectedWithoutChanges() throws {
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

    // A trailing dot or dot parent must never hide a forbidden symlink leaf.
    func testDotComponentsCannotBypassSymlinkLeafValidation() throws {
        try fixture { root in
            let target = root.appendingPathComponent("target")
            let link = root.appendingPathComponent("link")
            try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
            for suffix in ["/.", "/../target", "/./child"] {
                let spelled = URL(fileURLWithPath: link.path + suffix)
                XCTAssertThrowsError(try AdmissionCoordinator(directory: spelled, controllerID: ControllerID()), suffix)
                try assertUntouched(target, contents: [], mode: 0o700)
            }
        }
    }

    // Resolving the trusted parent is allowed; resolving the untrusted leaf is not.
    func testTrustedParentAliasAndCanonicalParentShareOwnershipAndReopen() throws {
        try fixture { root in
            let parent = root.appendingPathComponent("parent")
            let alias = root.appendingPathComponent("alias")
            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
            try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: parent)
            let controller = ControllerID()
            var owner: AdmissionCoordinator? = try AdmissionCoordinator(directory: alias.appendingPathComponent("state"), controllerID: controller)
            XCTAssertThrowsError(try AdmissionCoordinator(directory: parent.appendingPathComponent("state"), controllerID: controller)) {
                XCTAssertEqual(($0 as? JournalStorageError)?.kind, .alreadyOwned)
            }
            withExtendedLifetime(owner) {}
            owner = nil
            let reopened = try AdmissionCoordinator(directory: parent.appendingPathComponent("state"), controllerID: controller)
            withExtendedLifetime(reopened) {}
        }
    }

    func testSymlinkStateArtifactsAreRejectedWithoutTouchingTargets() throws {
        for name in ["admission.lock", "admission.sqlite3", "admission.sqlite3-journal", "admission.sqlite3-wal", "admission.sqlite3-shm"] {
            try fixture { root in
                let leaf = root.appendingPathComponent("state")
                try FileManager.default.createDirectory(at: leaf, withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: 0o700])
                let target = root.appendingPathComponent("target")
                // Empty bytes would become a database if SQLite follows the main-file link.
                try Data().write(to: target)
                let artifact = leaf.appendingPathComponent(name)
                try FileManager.default.createSymbolicLink(at: artifact, withDestinationURL: target)
                XCTAssertThrowsError(try AdmissionCoordinator(directory: leaf, controllerID: ControllerID()), name)
                XCTAssertEqual(try Data(contentsOf: target), Data(), name)
                XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: artifact.path), target.path)
                try assertUntouched(leaf, contents: [name], mode: 0o700)
            }
        }
    }

    func testHardLinkedStateArtifactsAreRejectedWithoutChanges() throws {
        for name in ["admission.lock", "admission.sqlite3", "admission.sqlite3-journal", "admission.sqlite3-wal", "admission.sqlite3-shm"] {
            try fixture { root in
                let leaf = root.appendingPathComponent("state")
                try FileManager.default.createDirectory(at: leaf, withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: 0o700])
                let target = root.appendingPathComponent("target")
                try Data().write(to: target)
                try FileManager.default.linkItem(at: target, to: leaf.appendingPathComponent(name))
                XCTAssertThrowsError(try AdmissionCoordinator(directory: leaf, controllerID: ControllerID()), name)
                XCTAssertEqual(try Data(contentsOf: target), Data(), name)
                try assertUntouched(leaf, contents: [name], mode: 0o700)
            }
        }
    }

    func testNonregularStateArtifactsAreRejectedWithoutChanges() throws {
        for name in ["admission.lock", "admission.sqlite3", "admission.sqlite3-journal", "admission.sqlite3-wal", "admission.sqlite3-shm"] {
            try fixture { root in
                let artifact = root.appendingPathComponent(name)
                try FileManager.default.createDirectory(at: artifact, withIntermediateDirectories: false)
                XCTAssertThrowsError(try AdmissionCoordinator(directory: root, controllerID: ControllerID()), name)
                try assertUntouched(root, contents: [name], mode: 0o700)
            }
        }
    }

}
