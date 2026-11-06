import CSQLite
import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import RemoteExecutionCore

final class StatusSchemaTests: XCTestCase {
    // Break: an existing-only local load creates a fresh leaf/policy or resolves
    // identity/randomness before proving that committed policy exists.
    func testExistingOnlyOpenRefusesFreshWithoutCreation() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("existing-only-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("state")
        let calls = Capture(0)
        let config = StatusOnlyHostConfiguration(directory: directory, clock: Clock(), random: RefusingRandom(),
            identityResolver: { _ in calls.change { $0 += 1 }; return Self.key }, onUnavailable: {}, allowsFreshStore: false)
        XCTAssertThrowsError(try StatusOnlyJournal.open(configuration: config, backupExclusion: Backup()))
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.path))
        _ = try JournalStateDirectory.prepare(directory)
        XCTAssertThrowsError(try StatusOnlyJournal.open(configuration: config, backupExclusion: Backup()))
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.appendingPathComponent("admission.sqlite3").path))
        let main = directory.appendingPathComponent("admission.sqlite3")
        try Data().write(to: main)
        XCTAssertThrowsError(try StatusOnlyJournal.open(configuration: config, backupExclusion: Backup()))
        XCTAssertEqual(try Data(contentsOf: main), Data())
        XCTAssertEqual(calls.value, 0)
    }

    // Break: existing-only reopen rejects valid enrolled policy or rewrites IDs/pin.
    func testExistingOnlyOpenLoadsEnrolledPolicy() throws {
        try fixture { directory in
            var journal: StatusOnlyJournal? = try StatusOnlyJournal.open(configuration: configuration(directory), backupExclusion: Backup())
            let enrolled = try XCTUnwrap(journal).confirm(key: Self.otherKey)
            journal = nil
            let config = StatusOnlyHostConfiguration(directory: directory, clock: Clock(), random: RefusingRandom(),
                identityResolver: { pin in XCTAssertEqual(pin, enrolled.hostPin); return Self.key }, onUnavailable: {}, allowsFreshStore: false)
            let reopened = try StatusOnlyJournal.open(configuration: config, backupExclusion: Backup())
            XCTAssertEqual(try reopened.readPolicy(), enrolled)
        }
    }
    private struct RefusingRandom: StatusRandomSource {
        func bytes(count: Int) throws -> Data { XCTFail("existing-only open requested random bytes"); throw POSIXError(.EIO) }
    }

    // Removing exact-schema or row validation must let one of these malformed
    // disposable stores through. The reference DDL is frozen independently here.
    func testExactReferenceSchemaAndData() throws {
        try fixture { directory in
            let key = Self.key
            try createStore(directory, key: key)
            let db = try StatusReadOnlyDatabase(url: directory.appendingPathComponent("admission.sqlite3"))
            let policy = try StatusSchema.validate(read: db.query)
            XCTAssertEqual(policy.hostID.uuidString.lowercased(), "11111111-1111-4111-8111-111111111111")
            XCTAssertEqual(policy.controllerGeneration, 1)
            XCTAssertEqual(policy.executionCapability, .unsupported)
            XCTAssertEqual(policy.controllerState, .unenrolled)
            XCTAssertNil(policy.controllerSPKI)
            XCTAssertEqual(policy.hostPin, Data(SHA256.hash(data: key)))
            for badIntegrity in [[], [["not ok"]], [["ok"], ["ok"]]] as [[[String?]]] {
                XCTAssertThrowsError(try StatusSchema.validate { sql in
                    sql == "PRAGMA integrity_check" ? badIntegrity : try db.query(sql)
                })
            }
            XCTAssertThrowsError(try StatusSchema.validate { sql in
                var rows = try db.query(sql)
                if sql.hasPrefix("PRAGMA index_list"), rows.count > 1 { rows.swapAt(0, 1) }
                return rows
            })
            XCTAssertThrowsError(try StatusSchema.validate { sql in
                var rows = try db.query(sql)
                if sql.hasPrefix("PRAGMA index_xinfo"), !rows.isEmpty { rows[0][2] = "controller_id" }
                return rows
            })
        }
        for extra in ["CREATE TABLE extra(x)", "CREATE VIEW extra AS SELECT 1", "CREATE INDEX extra ON prototype_status(host_id)", "CREATE TRIGGER extra AFTER UPDATE ON prototype_status BEGIN SELECT 1; END"] {
            try fixture { directory in
                try createStore(directory, key: Self.key, mutation: extra)
                let db = try StatusReadOnlyDatabase(url: directory.appendingPathComponent("admission.sqlite3"))
                XCTAssertThrowsError(try StatusSchema.validate(read: db.query), extra)
                try db.close()
                try assertRejectedUnchanged(directory)
            }
        }
        for mutation in [
            "DELETE FROM prototype_status",
            "UPDATE prototype_status SET singleton = 2",
            "UPDATE prototype_status SET host_id = '00000000-0000-0000-0000-000000000000'",
            "UPDATE prototype_status SET host_id = 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'",
            "UPDATE prototype_status SET storage_epoch = 'not-a-uuid-with-thirty-six-characters!'",
            "UPDATE prototype_status SET host_spki_sha256 = '\(String(repeating: "A", count: 64))'",
            "UPDATE prototype_status SET controller_generation = 0",
            "UPDATE prototype_status SET controller_state = 'enrolled'",
            "UPDATE prototype_status SET controller_state = 'enrolled', controller_spki_der_hex = '\(String(repeating: "00", count: 91))'",
            "UPDATE prototype_status SET host_id = host_id || char(0)",
            "INSERT INTO prototype_status SELECT 2, '22222222-2222-4222-8222-222222222222', '33333333-3333-4333-8333-333333333333', host_spki_sha256, '44444444-4444-4444-8444-444444444444', 1, 'unenrolled', NULL FROM prototype_status"
        ] {
            try fixture { directory in
                try createStore(directory, key: Self.key, mutation: "PRAGMA ignore_check_constraints = ON; \(mutation)")
                let db = try StatusReadOnlyDatabase(url: directory.appendingPathComponent("admission.sqlite3"))
                XCTAssertThrowsError(try StatusSchema.validate(read: db.query), mutation)
                try db.close()
                try assertRejectedUnchanged(directory)
            }
        }
    }

    // Resolver disagreement must fail before opening writable or applying backup
    // metadata; a successful reopen must preserve all durable identifiers.
    func testFreshAndExistingIdentity() throws {
        try fixture { directory in
            let calls = Capture<[Data?]>([])
            let config = configuration(directory) { pin in calls.change { $0.append(pin) }; return Self.key }
            var journal: StatusOnlyJournal? = try StatusOnlyJournal.open(configuration: config, backupExclusion: Backup())
            let original = try XCTUnwrap(journal).readPolicy()
            XCTAssertEqual(calls.value, [nil])
            XCTAssertEqual(original.controllerGeneration, 1)
            XCTAssertEqual(original.controllerState, .unenrolled)
            XCTAssertNotEqual(original.hostID, UUID(uuid: (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)))
            XCTAssertEqual(try inventory(directory).keys.sorted(), ["admission.lock", "admission.sqlite3"])
            journal = nil
            var reopened: StatusOnlyJournal? = try StatusOnlyJournal.open(configuration: config, backupExclusion: Backup())
            XCTAssertEqual(try reopened?.readPolicy(), original)
            XCTAssertEqual(calls.value, [nil, original.hostPin])
            reopened = nil
            let before = try inventory(directory)
            let resolvers: [@Sendable (Data?) throws -> Data] = [
                { _ in throw StatusHostError.invalidKey },
                { _ in Self.otherKey },
                { _ in Data(repeating: 0, count: 91) }
            ]
            for resolver in resolvers {
                let backup = Backup()
                XCTAssertThrowsError(try StatusOnlyJournal.open(configuration: configuration(directory, resolver: resolver), backupExclusion: backup))
                XCTAssertEqual(try inventory(directory), before)
                XCTAssertEqual(backup.calls.value, 0)
            }
        }
    }

    // A writable validator would accept UPDATE, create companions or alter bytes.
    // Changing bytes/inode inside identity resolution must be caught by recheck.
    func testValidatorNeverWrites() throws {
        try fixture { directory in
            try createStore(directory, key: Self.key)
            let lock = try JournalDirectoryLock(directory: directory)
            defer { withExtendedLifetime(lock) {} }
            let before = try inventory(directory)
            do {
                let read = try StatusReadOnlyDatabase(url: directory.appendingPathComponent("admission.sqlite3"))
                _ = try StatusSchema.validate(read: read.query)
                XCTAssertThrowsError(try read.query("UPDATE prototype_status SET controller_generation = 2"))
            }
            XCTAssertEqual(try inventory(directory), before)
        }
        for mutation in ["bytes", "inode", "companion"] {
            try fixture { directory in
                try createStore(directory, key: Self.key)
                let main = directory.appendingPathComponent("admission.sqlite3")
                let config = configuration(directory) { pin in
                    XCTAssertEqual(pin, Data(SHA256.hash(data: Self.key)))
                    if mutation == "companion" {
                        try Data().write(to: directory.appendingPathComponent("admission.sqlite3-journal"))
                    } else if mutation == "inode" {
                        let bytes = try Data(contentsOf: main)
                        try FileManager.default.removeItem(at: main)
                        try bytes.write(to: main)
                    } else {
                        let handle = try FileHandle(forWritingTo: main)
                        try handle.seek(toOffset: 150)
                        try handle.write(contentsOf: Data([42]))
                        try handle.close()
                    }
                    return Self.key
                }
                XCTAssertThrowsError(try StatusOnlyJournal.open(configuration: config, backupExclusion: Backup()))
            }
        }
    }

    // Publishing before backup apply/readback would return a usable journal despite
    // the injected failure. Refused schema must never reach metadata application.
    func testBackupExclusionBeforeReadiness() throws {
        try fixture { directory in
            let backup = Backup()
            let journal = try StatusOnlyJournal.open(configuration: configuration(directory), backupExclusion: backup)
            XCTAssertEqual(backup.calls.value, 1)
            XCTAssertNoThrow(try journal.checkHealth())
        }
        try fixture { directory in
            let backup = Backup(fails: true)
            XCTAssertThrowsError(try StatusOnlyJournal.open(configuration: configuration(directory), backupExclusion: backup))
            XCTAssertEqual(backup.calls.value, 1)
            let retry = try StatusOnlyJournal.open(configuration: configuration(directory), backupExclusion: Backup())
            XCTAssertEqual(try retry.readPolicy().controllerGeneration, 1)
        }
        try fixture { directory in
            try createStore(directory, key: Self.key, mutation: "CREATE TABLE foreign_table(x)")
            let before = try inventory(directory)
            let backup = Backup()
            XCTAssertThrowsError(try StatusOnlyJournal.open(configuration: configuration(directory), backupExclusion: backup))
            XCTAssertEqual(backup.calls.value, 0)
            XCTAssertEqual(try inventory(directory), before)
        }
    }

    // Confirmation/revocation must commit only permitted transitions and preserve
    // the assigned slot. Repeated revoke must not increment twice.
    func testPolicyTransitionsAndOverflow() throws {
        try fixture { directory in
            let journal = try StatusOnlyJournal.open(configuration: configuration(directory), backupExclusion: Backup())
            let original = try journal.readPolicy()
            XCTAssertThrowsError(try journal.revoke()) { XCTAssertEqual($0 as? StatusHostError, .notEnrolled) }
            XCTAssertEqual(try journal.readPolicy(), original)
            XCTAssertThrowsError(try journal.confirm(key: Data(repeating: 0, count: 91)))
            let enrolled = try journal.confirm(key: Self.otherKey)
            XCTAssertEqual(enrolled.controllerID, original.controllerID)
            XCTAssertEqual(enrolled.controllerGeneration, 1)
            XCTAssertEqual(enrolled.controllerState, .enrolled)
            XCTAssertEqual(enrolled.controllerSPKI, Self.otherKey)
            XCTAssertThrowsError(try journal.confirm(key: Self.key))
            let revoked = try journal.revoke()
            XCTAssertEqual(revoked.controllerGeneration, 2)
            XCTAssertEqual(revoked.controllerState, .revoked)
            XCTAssertEqual(revoked.controllerSPKI, Self.otherKey)
            XCTAssertEqual(try journal.revoke(), revoked)
            XCTAssertThrowsError(try journal.confirm(key: Self.key))
        }
        try fixture { directory in
            try createStore(directory, key: Self.key, mutation: "UPDATE prototype_status SET controller_state = 'enrolled', controller_spki_der_hex = '\(Self.hex(Self.otherKey))', controller_generation = 9223372036854775807")
            let journal = try StatusOnlyJournal.open(configuration: configuration(directory), backupExclusion: Backup())
            let before = try journal.readPolicy()
            XCTAssertThrowsError(try journal.revoke()) { XCTAssertEqual($0 as? StatusHostError, .generationOverflow) }
            XCTAssertEqual(try journal.readPolicy(), before)
        }
    }

    func testInvalidFreshIdentityAndRandomCannotCreateDatabase() throws {
        try fixture { directory in
            XCTAssertThrowsError(try StatusOnlyJournal.open(configuration: configuration(directory) { _ in Data() }, backupExclusion: Backup()))
            XCTAssertFalse(FileManager.default.fileExists(atPath: directory.appendingPathComponent("admission.sqlite3").path))
        }
        try fixture { directory in
            let config = StatusOnlyHostConfiguration(directory: directory, clock: Clock(), random: ZeroRandom(), identityResolver: { _ in Self.key }, onUnavailable: {})
            XCTAssertThrowsError(try StatusOnlyJournal.open(configuration: config, backupExclusion: Backup()))
            XCTAssertFalse(FileManager.default.fileExists(atPath: directory.appendingPathComponent("admission.sqlite3").path))
        }
    }

    // BUSY must retain SQLite's immediate refusal: a wait policy would exceed
    // this generous deadline, and a recovery/writable probe would alter inventory.
    func testBusyReaderRefusesWithoutWaitingOrChanges() throws {
        try fixture { directory in
            try createStore(directory, key: Self.key)
            let before = try inventory(directory)
            var opened: OpaquePointer?
            XCTAssertEqual(sqlite3_open_v2(directory.appendingPathComponent("admission.sqlite3").path, &opened, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, nil), SQLITE_OK)
            let other = try XCTUnwrap(opened)
            defer { sqlite3_exec(other, "ROLLBACK", nil, nil, nil); sqlite3_close_v2(other) }
            XCTAssertEqual(sqlite3_exec(other, "BEGIN EXCLUSIVE", nil, nil, nil), SQLITE_OK)
            let started = Date()
            XCTAssertThrowsError(try StatusOnlyJournal.open(configuration: configuration(directory), backupExclusion: Backup())) {
                XCTAssertEqual(($0 as? JournalStorageError)?.sqliteCode, SQLITE_BUSY)
            }
            XCTAssertLessThan(Date().timeIntervalSince(started), 1)
            XCTAssertEqual(try inventory(directory), before)
        }
    }

    private func assertRejectedUnchanged(_ directory: URL) throws {
        let before = try inventory(directory)
        let resolutions = Capture(0)
        let config = configuration(directory) { _ in resolutions.change { $0 += 1 }; return Self.key }
        let backup = Backup()
        XCTAssertThrowsError(try StatusOnlyJournal.open(configuration: config, backupExclusion: backup))
        XCTAssertEqual(resolutions.value, 0)
        XCTAssertEqual(backup.calls.value, 0)
        XCTAssertEqual(try inventory(directory), before)
    }

    private struct Clock: StatusClock { func nowNanoseconds() -> UInt64 { 0 } }
    private struct Random: StatusRandomSource { func bytes(count: Int) throws -> Data { Data((0..<count).map { _ in UInt8.random(in: 1...255) }) } }
    private struct ZeroRandom: StatusRandomSource { func bytes(count: Int) throws -> Data { Data(repeating: 0, count: count) } }
    private final class Capture<T>: @unchecked Sendable {
        private let lock = NSLock(); private var stored: T
        init(_ value: T) { stored = value }
        var value: T { lock.lock(); defer { lock.unlock() }; return stored }
        func change(_ body: (inout T) -> Void) { lock.lock(); defer { lock.unlock() }; body(&stored) }
    }
    private struct Backup: StatusBackupExclusion {
        let calls = Capture(0); var fails = false
        func applyAndVerify(_ directory: URL) throws {
            calls.change { $0 += 1 }
            if fails { throw POSIXError(.EIO) }
        }
    }
    private func configuration(_ directory: URL, resolver: @escaping @Sendable (Data?) throws -> Data = { _ in StatusSchemaTests.key }) -> StatusOnlyHostConfiguration {
        StatusOnlyHostConfiguration(directory: directory, clock: Clock(), random: Random(), identityResolver: resolver, onUnavailable: {})
    }
    private static var key: Data { try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32)).publicKey.derRepresentation }
    private static var otherKey: Data { try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 2, count: 32)).publicKey.derRepresentation }
    private static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    private struct Snapshot: Equatable {
        let bytes: Data; let inode: ino_t; let mode: mode_t
    }
    private func inventory(_ directory: URL) throws -> [String: Snapshot] {
        try Dictionary(uniqueKeysWithValues: FileManager.default.contentsOfDirectory(atPath: directory.path).map { name in
            let url = directory.appendingPathComponent(name); var info = stat()
            guard lstat(url.path, &info) == 0 else { throw POSIXError(.EIO) }
            return (name, Snapshot(bytes: try Data(contentsOf: url), inode: info.st_ino, mode: info.st_mode))
        })
    }
    private func fixture(_ body: (URL) throws -> Void) throws {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("status-schema-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: url) }
        try body(JournalStateDirectory.prepare(url))
    }
    private func createStore(_ directory: URL, key: Data, mutation: String = "") throws {
        // Establish the stable lock before taking inventory in refusal tests.
        let lock = try JournalDirectoryLock(directory: directory)
        defer { withExtendedLifetime(lock) {} }
        var opened: OpaquePointer?
        XCTAssertEqual(sqlite3_open_v2(directory.appendingPathComponent("admission.sqlite3").path, &opened, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOFOLLOW, nil), SQLITE_OK)
        let db = try XCTUnwrap(opened); defer { sqlite3_close_v2(db) }
        let sql = "PRAGMA application_id = 1330467668; PRAGMA user_version = 1; \(Self.frozenDDL); INSERT INTO prototype_status VALUES(1, '11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222', '\(Self.hex(Data(SHA256.hash(data: key))))', '33333333-3333-4333-8333-333333333333', 1, 'unenrolled', NULL); \(mutation)"
        var error: UnsafeMutablePointer<CChar>?
        let result = sqlite3_exec(db, sql, nil, nil, &error)
        defer { sqlite3_free(error) }
        XCTAssertEqual(result, SQLITE_OK, error.map { String(cString: $0) } ?? "")
        if result != SQLITE_OK { throw POSIXError(.EIO) }
    }
    private static let frozenDDL = """
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
}
