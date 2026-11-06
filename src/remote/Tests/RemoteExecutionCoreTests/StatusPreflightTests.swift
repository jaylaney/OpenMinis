import CSQLite
import Darwin
import Foundation
import XCTest
@testable import RemoteExecutionCore

final class StatusPreflightTests: XCTestCase {
    // A writable/open-and-recover probe would alter rejected fixtures; accepting unsafe
    // metadata or ignoring companions would expose them to that SQLite behavior.
    func testFinderMetadataIsIgnoredSafely() throws {
        try fixture { directory in
            let lock = try JournalDirectoryLock(directory: directory)
            defer { withExtendedLifetime(lock) {} }
            let main = directory.appendingPathComponent("admission.sqlite3")
            try makeStatusStore(main)
            let metadata = directory.appendingPathComponent(".DS_Store")
            try Data([3, 9, 2]).write(to: metadata)
            XCTAssertEqual(chmod(metadata.path, 0o644), 0)
            let original = try snapshot(metadata)
            let probe = try StatusStorePreflight.inspectOwned(directory: directory)
            XCTAssertFalse(probe.isFresh)
            try StatusStorePreflight.recheck(probe)
            XCTAssertEqual(try snapshot(metadata), original)
            let metadataHandle = try FileHandle(forWritingTo: metadata)
            try metadataHandle.write(contentsOf: Data([55, 66, 77]))
            try metadataHandle.close()
            try StatusStorePreflight.recheck(probe)
            try FileManager.default.removeItem(at: metadata)
            try StatusStorePreflight.recheck(probe)
            try Data([8, 7]).write(to: metadata)
            try StatusStorePreflight.recheck(probe)
            try FileManager.default.removeItem(at: metadata)
            let canary = directory.deletingLastPathComponent().appendingPathComponent("canary-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: canary) }
            try Data([21, 22]).write(to: canary)
            let untouched = try snapshot(canary)
            XCTAssertEqual(symlink(canary.path, metadata.path), 0)
            XCTAssertThrowsError(try StatusStorePreflight.inspectOwned(directory: directory))
            XCTAssertThrowsError(try StatusStorePreflight.recheck(probe))
            XCTAssertEqual(try snapshot(canary), untouched)
            try FileManager.default.removeItem(at: metadata)
            XCTAssertEqual(link(canary.path, metadata.path), 0)
            XCTAssertThrowsError(try StatusStorePreflight.inspectOwned(directory: directory))
            try FileManager.default.removeItem(at: metadata)
            XCTAssertEqual(mkdir(metadata.path, 0o700), 0)
            XCTAssertThrowsError(try StatusStorePreflight.inspectOwned(directory: directory))
            try FileManager.default.removeItem(at: metadata)
            XCTAssertEqual(mkfifo(metadata.path, 0o600), 0)
            XCTAssertThrowsError(try StatusStorePreflight.inspectOwned(directory: directory))
        }
    }

    func testMetadataDoesNotHideRecoveryState() throws {
        for name in ["admission.sqlite3-journal", "admission.sqlite3-wal", "unknown"] {
            try fixture { directory in
                let lock = try JournalDirectoryLock(directory: directory)
                defer { withExtendedLifetime(lock) {} }
                try makeStatusStore(directory.appendingPathComponent("admission.sqlite3"))
                try Data([1, 4]).write(to: directory.appendingPathComponent(".DS_Store"))
                try Data([4, 1]).write(to: directory.appendingPathComponent(name))
                let original = try inventory(directory)
                XCTAssertThrowsError(try StatusStorePreflight.inspectOwned(directory: directory))
                XCTAssertEqual(try inventory(directory), original)
            }
        }
    }

    func testCompanionsAndForeignHeadersStayUntouched() throws {
        for name in ["admission.sqlite3-journal", "admission.sqlite3-wal", "admission.sqlite3-shm",
                     "admission.sqlite3-mj DEAD", "unknown"] {
            for bytes in [Data(), Data([0, 19, 88])] {
                try fixture { directory in
                    let lock = try JournalDirectoryLock(directory: directory)
                    defer { withExtendedLifetime(lock) {} }
                    try makeStatusStore(directory.appendingPathComponent("admission.sqlite3"))
                    let companion = directory.appendingPathComponent(name)
                    try bytes.write(to: companion)
                    XCTAssertEqual(chmod(companion.path, 0o644), 0)
                    let original = try inventory(directory)
                    XCTAssertThrowsError(try StatusStorePreflight.inspectOwned(directory: directory))
                    XCTAssertEqual(try inventory(directory), original)
                }
            }
        }
        for mutation in ["foreign", "unversioned", "truncated", "wal", "magic"] {
            try fixture { directory in
                let lock = try JournalDirectoryLock(directory: directory)
                defer { withExtendedLifetime(lock) {} }
                let main = directory.appendingPathComponent("admission.sqlite3")
                try makeStatusStore(main)
                var bytes = try Data(contentsOf: main)
                switch mutation {
                case "foreign": bytes.replaceSubrange(68..<72, with: [0, 0, 0, 3])
                case "unversioned": bytes.replaceSubrange(60..<64, with: [0, 0, 0, 0])
                case "truncated": bytes = bytes.prefix(71)
                case "wal": bytes[18] = 2; bytes[19] = 2
                default: bytes[0] = 0
                }
                try bytes.write(to: main)
                XCTAssertEqual(chmod(main.path, 0o644), 0)
                let original = try inventory(directory)
                XCTAssertThrowsError(try StatusStorePreflight.inspectOwned(directory: directory))
                XCTAssertEqual(try inventory(directory), original)
            }
        }
        try fixture { directory in
            let lock = try JournalDirectoryLock(directory: directory)
            defer { withExtendedLifetime(lock) {} }
            let outside = directory.deletingLastPathComponent().appendingPathComponent("canary-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: outside) }
            try Data([7, 6]).write(to: outside)
            let original = try snapshot(outside)
            XCTAssertEqual(symlink(outside.path, directory.appendingPathComponent("admission.sqlite3-journal").path), 0)
            XCTAssertThrowsError(try StatusStorePreflight.inspectOwned(directory: directory))
            XCTAssertEqual(try snapshot(outside), original)
        }
    }

    // Catches either profile replacing the stable lock or legacy adding its tables
    // to an OMST store after the prototype owner has released ownership.
    func testOwnershipAndLegacyGuard() throws {
        try fixture { directory in
            let main = directory.appendingPathComponent("admission.sqlite3")
            var lock: JournalDirectoryLock? = try JournalDirectoryLock(directory: directory)
            XCTAssertNotNil(lock)
            let stable = try snapshot(directory.appendingPathComponent("admission.lock"))
            let missing = try StatusStorePreflight.inspectOwned(directory: directory)
            XCTAssertTrue(missing.isFresh)
            try Data().write(to: main)
            let empty = try StatusStorePreflight.inspectOwned(directory: directory)
            XCTAssertTrue(empty.isFresh)
            XCTAssertThrowsError(try StatusStorePreflight.recheck(missing))
            XCTAssertThrowsError(try AdmissionJournal(directory: directory, controllerID: ControllerID())) {
                XCTAssertEqual(($0 as? JournalStorageError)?.kind, .alreadyOwned)
            }
            try makeStatusStore(main)
            let original = try inventory(directory)
            lock = nil
            XCTAssertThrowsError(try AdmissionJournal(directory: directory, controllerID: ControllerID()))
            XCTAssertEqual(try inventory(directory), original)
            XCTAssertEqual(try snapshot(directory.appendingPathComponent("admission.lock")), stable)
        }
        try fixture { directory in
            let controller = ControllerID()
            var legacy: AdmissionJournal? = try AdmissionJournal(directory: directory, controllerID: controller)
            XCTAssertNotNil(legacy)
            XCTAssertThrowsError(try JournalDirectoryLock(directory: directory)) {
                XCTAssertEqual(($0 as? JournalStorageError)?.kind, .alreadyOwned)
            }
            legacy = nil
            XCTAssertNoThrow(try AdmissionJournal(directory: directory, controllerID: controller))
        }
    }

    func testRecheckDetectsAuthoritativeChanges() throws {
        for mutation in ["content", "inode", "mode", "companion", "lock"] {
            try fixture { directory in
                let lock = try JournalDirectoryLock(directory: directory)
                defer { withExtendedLifetime(lock) {} }
                let main = directory.appendingPathComponent("admission.sqlite3")
                try makeStatusStore(main)
                let probe = try StatusStorePreflight.inspectOwned(directory: directory)
                switch mutation {
                case "content":
                    let handle = try FileHandle(forWritingTo: main)
                    try handle.seek(toOffset: 150)
                    try handle.write(contentsOf: Data([42]))
                    try handle.close()
                case "inode":
                    let bytes = try Data(contentsOf: main)
                    try FileManager.default.removeItem(at: main)
                    try bytes.write(to: main)
                case "mode": XCTAssertEqual(chmod(main.path, 0o400), 0)
                case "lock":
                    let handle = try FileHandle(forWritingTo: directory.appendingPathComponent("admission.lock"))
                    try handle.write(contentsOf: Data([1]))
                    try handle.close()
                default: try Data().write(to: directory.appendingPathComponent("admission.sqlite3-journal"))
                }
                XCTAssertThrowsError(try StatusStorePreflight.recheck(probe), mutation)
            }
        }
    }

    func testUnsafeMainAndPrivateLeafRefuse() throws {
        try fixture { directory in
            let lock = try JournalDirectoryLock(directory: directory)
            defer { withExtendedLifetime(lock) {} }
            let main = directory.appendingPathComponent("admission.sqlite3")
            let outside = directory.deletingLastPathComponent().appendingPathComponent("canary-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: outside) }
            try Data([7, 6]).write(to: outside)
            let original = try snapshot(outside)
            XCTAssertEqual(symlink(outside.path, main.path), 0)
            XCTAssertThrowsError(try StatusStorePreflight.inspectOwned(directory: directory))
            XCTAssertEqual(try snapshot(outside), original)
            try FileManager.default.removeItem(at: main)
            XCTAssertEqual(link(outside.path, main.path), 0)
            XCTAssertThrowsError(try StatusStorePreflight.inspectOwned(directory: directory))
        }
        try fixture { directory in
            XCTAssertEqual(chmod(directory.path, 0o755), 0)
            XCTAssertThrowsError(try JournalStateDirectory.prepare(directory))
            var info = stat()
            XCTAssertEqual(lstat(directory.path, &info), 0)
            XCTAssertEqual(info.st_mode & 0o777, 0o755)
        }
    }

    // On-disk ownership changes require root. Exercise the real shared validator
    // with the actual fixture stat and one changed UID; the integrated metadata
    // cases above prove metadata is routed through that validator.
    func testArtifactValidatorRejectsForeignEffectiveOwner() throws {
        try fixture { directory in
            let metadata = directory.appendingPathComponent(".DS_Store")
            try Data([1]).write(to: metadata)
            var info = stat()
            XCTAssertEqual(lstat(metadata.path, &info), 0)
            XCTAssertNoThrow(try JournalStateDirectory.validateArtifact(info))
            info.st_uid = geteuid() == 0 ? 1 : 0
            XCTAssertThrowsError(try JournalStateDirectory.validateArtifact(info))
        }
    }

    private struct Snapshot: Equatable {
        let bytes: Data
        let device: dev_t
        let inode: ino_t
        let mode: mode_t
        let owner: uid_t
        let links: nlink_t
    }

    private func snapshot(_ url: URL) throws -> Snapshot {
        var info = stat()
        guard lstat(url.path, &info) == 0 else { throw POSIXError(.EIO) }
        return Snapshot(bytes: try Data(contentsOf: url), device: info.st_dev, inode: info.st_ino,
                        mode: info.st_mode, owner: info.st_uid, links: info.st_nlink)
    }

    private func inventory(_ directory: URL) throws -> [String: Snapshot] {
        try Dictionary(uniqueKeysWithValues: FileManager.default.contentsOfDirectory(atPath: directory.path).map {
            ($0, try snapshot(directory.appendingPathComponent($0)))
        })
    }

    private func fixture(_ body: (URL) throws -> Void) throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("status-preflight-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(JournalStateDirectory.prepare(directory))
    }

    private func makeStatusStore(_ url: URL) throws {
        var db: OpaquePointer?
        XCTAssertEqual(sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOFOLLOW, nil), SQLITE_OK)
        guard let db else { throw POSIXError(.EIO) }
        defer { sqlite3_close(db) }
        // Frozen design DDL, deliberately independent of the future production factory.
        let ddl = """
        CREATE TABLE prototype_status (
            singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 1),
            host_id TEXT NOT NULL UNIQUE CHECK(typeof(host_id) = 'text' AND length(host_id) = 36),
            storage_epoch TEXT NOT NULL UNIQUE CHECK(typeof(storage_epoch) = 'text' AND length(storage_epoch) = 36),
            host_spki_sha256 TEXT NOT NULL CHECK(typeof(host_spki_sha256) = 'text' AND length(host_spki_sha256) = 64 AND host_spki_sha256 NOT GLOB '*[^0-9a-f]*'),
            controller_id TEXT NOT NULL UNIQUE CHECK(typeof(controller_id) = 'text' AND length(controller_id) = 36),
            controller_generation INTEGER NOT NULL CHECK(typeof(controller_generation) = 'integer' AND controller_generation >= 1),
            controller_state TEXT NOT NULL CHECK(controller_state IN ('unenrolled', 'enrolled', 'revoked')),
            controller_spki_der_hex TEXT CHECK(controller_spki_der_hex IS NULL OR (typeof(controller_spki_der_hex) = 'text' AND length(controller_spki_der_hex) = 182 AND controller_spki_der_hex NOT GLOB '*[^0-9a-f]*')),
            CHECK((controller_state = 'unenrolled' AND controller_spki_der_hex IS NULL) OR (controller_state IN ('enrolled', 'revoked') AND controller_spki_der_hex IS NOT NULL))
        )
        """
        XCTAssertEqual(sqlite3_exec(db, "PRAGMA application_id = 1330467668; PRAGMA user_version = 1; \(ddl)", nil, nil, nil), SQLITE_OK)
    }
}
