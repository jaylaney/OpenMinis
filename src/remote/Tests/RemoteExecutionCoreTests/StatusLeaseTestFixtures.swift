import CSQLite
import CryptoKit
import Dispatch
import Foundation
import XCTest
@testable import RemoteExecutionCore

final class StatusTestBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T
    init(_ value: T) { self.value = value }
    func get() -> T { lock.withLock { value } }
    func set(_ value: T) { lock.withLock { self.value = value } }
    func update(_ body: (inout T) -> Void) { lock.withLock { body(&value) } }
}
final class StatusTestClock: StatusClock, Sendable {
    let now = StatusTestBox<UInt64>(100)
    func nowNanoseconds() -> UInt64 { now.get() }
}
struct StatusTestRandom: StatusRandomSource {
    func bytes(count: Int) throws -> Data { Data(repeating: 7, count: count) }
}
struct StatusTestBackup: StatusBackupExclusion { func applyAndVerify(_ directory: URL) throws {} }

final class StatusLeaseNative: SQLiteNative, @unchecked Sendable {
    enum Fault: Sendable { case none, update, rollback, unknownCommit }
    let fault = StatusTestBox(Fault.none)
    let statements = StatusTestBox<[String]>([])
    let onStep = StatusTestBox<(@Sendable (String) -> Void)?>(nil)
    let diagnostic = StatusTestBox("injected update")
    func step(_ statement: OpaquePointer) -> Int32 {
        let sql = String(cString: sqlite3_sql(statement))
        statements.update { $0.append(sql) }
        onStep.get()?(sql)
        if sql.hasPrefix("UPDATE prototype_status SET controller_state = 'revoked'") {
            switch fault.get() {
            case .update, .rollback:
                diagnostic.set("injected update")
                if fault.get() == .update { fault.set(.none) }
                return SQLITE_IOERR
            default: break
            }
        }
        if sql == "ROLLBACK", fault.get() == .rollback {
            fault.set(.none)
            diagnostic.set("injected rollback")
            return SQLITE_IOERR
        }
        if sql == "COMMIT", fault.get() == .unknownCommit {
            fault.set(.none)
            let actual = sqlite3_step(statement)
            guard actual == SQLITE_DONE else { return actual }
            diagnostic.set("injected commit")
            return SQLITE_IOERR
        }
        return sqlite3_step(statement)
    }
    func failure(_ connection: OpaquePointer) -> JournalStorageError {
        JournalStorageError(kind: .sqlite, message: diagnostic.get(), sqliteCode: SQLITE_IOERR, sqliteExtendedCode: 266)
    }
}

struct StatusLeaseFixture {
    static let zero = UUID(uuid: (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0))
    static let hostKey = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32)).publicKey.derRepresentation
    static let controllerKey = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 2, count: 32)).publicKey.derRepresentation
    static let otherKey = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32)).publicKey.derRepresentation
    let directory: URL
    let clock: StatusTestClock
    let native: StatusLeaseNative
    let queue: DispatchQueue
    let unavailable: StatusTestBox<Int>
    let configuration: StatusOnlyHostConfiguration
    let handles: StatusOnlyHostHandles
    static func open(generation: UInt64? = nil) async throws -> Self {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("status-lease-\(UUID())")
        let clock = StatusTestClock()
        let native = StatusLeaseNative()
        let queue = DispatchQueue(label: "status-lease-fixture")
        let unavailable = StatusTestBox(0)
        let config = StatusOnlyHostConfiguration(directory: directory, clock: clock, random: StatusTestRandom(),
                                               identityResolver: { _ in hostKey }, onUnavailable: { unavailable.update { $0 += 1 } })
        if let generation {
            let initial = try await StatusOnlyHost.open(configuration: config, native: native, backupExclusion: StatusTestBackup(), queue: queue)
            await initial.host.close()
            // Closed disposable-store fixture: no raw handle reaches production.
            var db: OpaquePointer?
            guard sqlite3_open_v2(directory.appendingPathComponent("admission.sqlite3").path, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK,
                  let db else { throw POSIXError(.EIO) }
            defer { sqlite3_close_v2(db) }
            let key = controllerKey.map { String(format: "%02x", $0) }.joined()
            guard sqlite3_exec(db, "UPDATE prototype_status SET controller_state = 'enrolled', controller_spki_der_hex = '\(key)', controller_generation = \(generation)", nil, nil, nil) == SQLITE_OK else { throw POSIXError(.EIO) }
        }
        let handles = try await StatusOnlyHost.open(configuration: config, native: native, backupExclusion: StatusTestBackup(), queue: queue)
        return Self(directory: directory, clock: clock, native: native, queue: queue, unavailable: unavailable, configuration: config, handles: handles)
    }
    func remove() { try? FileManager.default.removeItem(at: directory) }
    func input(_ snapshot: StatusOnlySnapshot, mode: StatusHandshakeMode = .normal, connection: UUID = UUID(),
               key: Data = controllerKey, invitation: UUID = zero) -> StatusHandshakeInput {
        StatusHandshakeInput(connectionID: connection, acceptedAtNanoseconds: clock.now.get(), mode: mode,
                             hostID: snapshot.hostID, hostPin: Data(SHA256.hash(data: Self.hostKey)), controllerSPKI: key,
                             clientNonce: Data(repeating: 1, count: 32), invitationID: invitation)
    }
    func pending() async throws -> (StatusHandshakeContext, StatusAcceptedCandidate) {
        let window = try await handles.host.openEnrollment()
        let snapshot = try await handles.host.localStatus().snapshot
        let context = try await handles.host.beginHandshake(input(snapshot, mode: .enrollment, invitation: window.invitationID))
        let candidate = try await handles.host.acceptCandidate(contextID: context.contextID, claimDigest: Data(repeating: 1, count: 32))
        return (context, candidate)
    }
    func enroll() async throws {
        let (_, candidate) = try await pending()
        try await handles.host.confirmCandidate(candidateID: candidate.candidateID)
    }
    func authenticate() async throws -> StatusControllerLease {
        let snapshot = try await handles.host.localStatus().snapshot
        let context = try await handles.host.beginHandshake(input(snapshot))
        return try await handles.host.authenticate(contextID: context.contextID)
    }
    func policy() async throws -> StatusStoredPolicy {
        try await handles.host.owner.perform { try $0.requireJournal().readPolicy() }
    }
    func inventory() throws -> [String: Data] {
        try Dictionary(uniqueKeysWithValues: FileManager.default.contentsOfDirectory(atPath: directory.path).map {
            ($0, try Data(contentsOf: directory.appendingPathComponent($0)))
        })
    }
}

@MainActor
func expectStatusError(_ expected: StatusHostError, _ body: () async throws -> Void, file: StaticString = #filePath, line: UInt = #line) async {
    do { try await body(); XCTFail("Expected \(expected)", file: file, line: line) }
    catch { XCTAssertEqual(error as? StatusHostError, expected, file: file, line: line) }
}
