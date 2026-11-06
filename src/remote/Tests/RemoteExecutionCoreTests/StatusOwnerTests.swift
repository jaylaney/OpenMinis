import CSQLite
import CryptoKit
import Darwin
import Dispatch
import Foundation
import XCTest
@testable import RemoteExecutionCore

@MainActor
final class StatusOwnerTests: XCTestCase {
    // Moving initialization, reads or final connection release off the serial
    // owner queue breaks the sentinel. A queued close must wait for a blocked read.
    func testInitializationReadCloseShareQueue() async throws {
        let leaf = directory()
        defer { try? FileManager.default.removeItem(at: leaf) }
        let queue = DispatchQueue(label: "status-owner-fixture")
        let sentinel = OwnerSentinel()
        queue.setSpecific(key: sentinel.key, value: 42)
        let native = OwnerNative(sentinel: sentinel)
        let handles = try await StatusOnlyHost.open(configuration: configuration(leaf, resolver: { _ in
            sentinel.check("resolver")
            return Self.key
        }), native: native, backupExclusion: OwnerBackup(sentinel: sentinel), queue: queue)
        let snapshot = try await handles.host.localStatus()
        XCTAssertEqual(snapshot.controllerState, .unenrolled)
        XCTAssertEqual(snapshot.enrollment, .closed)
        XCTAssertEqual(snapshot.readiness, .available)
        XCTAssertEqual(snapshot.snapshot.executionCapability, .unsupported)
        native.blockNextRead.set(true)
        let read = Task { try await handles.host.localStatus() }
        await fulfillment(of: [native.entered], timeout: 5)
        let closed = OwnerBox(false)
        let closeStarted = XCTestExpectation(description: "concurrent close started")
        queue.async { sentinel.check("fifo") }
        let close = Task.detached {
            closeStarted.fulfill()
            await handles.host.close()
            closed.set(true)
        }
        await fulfillment(of: [closeStarted], timeout: 5)
        // This synchronously enqueued marker cannot split the blocked whole read.
        XCTAssertFalse(sentinel.events.get().contains("fifo"))
        XCTAssertFalse(closed.get())
        XCTAssertThrowsError(try JournalDirectoryLock(directory: leaf)) { error in
            XCTAssertEqual((error as? JournalStorageError)?.kind, .alreadyOwned)
        }
        native.release.signal()
        _ = try await read.value
        await close.value
        XCTAssertTrue(closed.get())
        let events = sentinel.events.get()
        let marker = try XCTUnwrap(events.firstIndex(of: "fifo"))
        let lastSQLite = try XCTUnwrap(events.lastIndex(of: "sqlite"))
        let releaseIndex = try XCTUnwrap(events.lastIndex(of: "close"))
        XCTAssertLessThan(lastSQLite, marker)
        XCTAssertLessThan(marker, releaseIndex)
        XCTAssertTrue(sentinel.events.get().contains("close"))
        XCTAssertTrue(sentinel.events.get().contains("backup"))
        XCTAssertTrue(sentinel.events.get().contains("resolver"))
        XCTAssertTrue(sentinel.violations.get().isEmpty, "\(sentinel.violations.get())")
        let lock = try JournalDirectoryLock(directory: leaf)
        withExtendedLifetime(lock) {}
        await expect(.closed) { _ = try await handles.host.localStatus() }
    }

    // Last-reference ARC teardown must not run SQLite close on the releasing
    // caller's UI executor, even when explicit close was omitted.
    func testLastReferenceReleaseClosesOnOwnerQueue() async throws {
        let leaf = directory()
        defer { try? FileManager.default.removeItem(at: leaf) }
        let queue = DispatchQueue(label: "status-owner-deinit-fixture")
        let sentinel = OwnerSentinel()
        queue.setSpecific(key: sentinel.key, value: 42)
        let native = OwnerNative(sentinel: sentinel)
        var handles: StatusOnlyHostHandles? = try await StatusOnlyHost.open(configuration: configuration(leaf), native: native,
                                                                          backupExclusion: OwnerBackup(sentinel: sentinel), queue: queue)
        let snapshot = try await handles!.host.localStatus()
        XCTAssertEqual(snapshot.controllerState, .unenrolled)
        // Drain the completed read submission so only the handles own the owner.
        queue.sync {}
        handles = nil
        // ARC enqueues cleanup synchronously before returning to this caller.
        queue.sync {}
        XCTAssertTrue(sentinel.events.get().contains("close"))
        XCTAssertTrue(sentinel.violations.get().isEmpty, "\(sentinel.violations.get())")
        let lock = try JournalDirectoryLock(directory: leaf)
        withExtendedLifetime(lock) {}
    }

    // Failed unpublished owners must release SQLite and ownership before throwing;
    // retry must acquire the same stable inode rather than recreate the lock.
    func testFailedOpenClosesAndAllowsExplicitRetry() async throws {
        let leaf = directory()
        defer { try? FileManager.default.removeItem(at: leaf) }
        let queue = DispatchQueue(label: "status-failed-open-fixture")
        let sentinel = OwnerSentinel()
        queue.setSpecific(key: sentinel.key, value: 42)
        let native = OwnerNative(sentinel: sentinel)
        let initial = try await StatusOnlyHost.open(configuration: configuration(leaf), native: native,
                                                   backupExclusion: OwnerBackup(sentinel: sentinel), queue: queue)
        let original = try await initial.host.localStatus()
        await initial.host.close()
        let inode = try lockInode(leaf)
        sentinel.events.set([])
        let unavailable = OwnerBox(0)
        let failing = configuration(leaf, onUnavailable: { unavailable.update { $0 += 1 } }) { _ in
            sentinel.check("resolver-failure")
            throw ResolverFailure()
        }
        do {
            _ = try await StatusOnlyHost.open(configuration: failing, native: native,
                                              backupExclusion: OwnerBackup(sentinel: sentinel), queue: queue)
            XCTFail("Expected resolver failure")
        } catch { XCTAssertTrue(error is ResolverFailure) }
        XCTAssertEqual(unavailable.get(), 0)
        XCTAssertTrue(sentinel.events.get().contains("close"), "read-only validator must close on failed resolution")
        XCTAssertTrue(sentinel.violations.get().isEmpty)
        let retried = try await StatusOnlyHost.open(configuration: configuration(leaf), native: native,
                                                   backupExclusion: OwnerBackup(sentinel: sentinel), queue: queue)
        let reopened = try await retried.host.localStatus()
        XCTAssertEqual(reopened, original)
        XCTAssertEqual(try lockInode(leaf), inode)
        await retried.host.close()
    }

    // An otherwise recoverable native read failure is terminal at the owner
    // boundary, is returned unchanged before stale lease checks, and holds lock.
    func testFailureRetainsLockAndOriginalError() async throws {
        let leaf = directory()
        defer { try? FileManager.default.removeItem(at: leaf) }
        let queue = DispatchQueue(label: "status-failure-fixture")
        let sentinel = OwnerSentinel()
        queue.setSpecific(key: sentinel.key, value: 42)
        let native = OwnerNative(sentinel: sentinel)
        let callbacks = OwnerBox(0)
        let handles = try await StatusOnlyHost.open(configuration: configuration(leaf, onUnavailable: {
            sentinel.check("unavailable")
            callbacks.update { $0 += 1 }
        }), native: native, backupExclusion: OwnerBackup(sentinel: sentinel), queue: queue)
        let initial = try await handles.host.localStatus()
        let foreign = StatusControllerLease(incarnation: UUID(), connectionToken: UUID(), connectionID: UUID(),
                                            storageEpoch: initial.snapshot.storageEpoch, controllerGeneration: 1)
        await expect(.staleLease) { _ = try await handles.controller.status(over: foreign) }
        XCTAssertEqual(callbacks.get(), 0)
        // Test-only bookkeeping fixture: no authentication/authority is minted.
        let bookkeeping = try await handles.host.owner.perform { state in
            state.currentLease = foreign
            return state
        }
        native.failNextRead.set(true)
        for operation in 0..<3 {
            do {
                if operation == 1 { _ = try await handles.controller.status(over: foreign) }
                else { _ = try await handles.host.localStatus() }
                XCTFail("Expected retained storage failure")
            } catch {
                let diagnostic = error as? JournalStorageError
                XCTAssertEqual(diagnostic?.message, "injected read")
                XCTAssertEqual(diagnostic?.sqliteCode, SQLITE_IOERR)
                XCTAssertEqual(diagnostic?.sqliteExtendedCode, 266)
            }
        }
        XCTAssertEqual(callbacks.get(), 1)
        queue.sync {
            XCTAssertNil(bookkeeping.incarnation)
            XCTAssertNil(bookkeeping.currentLease)
        }
        XCTAssertTrue(sentinel.events.get().contains("unavailable"))
        XCTAssertThrowsError(try JournalDirectoryLock(directory: leaf)) { error in
            XCTAssertEqual((error as? JournalStorageError)?.kind, .alreadyOwned)
        }
        await handles.host.close()
        await handles.host.close()
        await expect(.closed) { _ = try await handles.host.localStatus() }
        let retry = try await StatusOnlyHost.open(configuration: configuration(leaf), native: native,
                                                 backupExclusion: OwnerBackup(sentinel: sentinel), queue: queue)
        let current = try await retry.host.localStatus()
        XCTAssertEqual(current, initial)
        await expect(.staleLease) { _ = try await retry.controller.status(over: foreign) }
        await retry.host.close()
        XCTAssertTrue(sentinel.violations.get().isEmpty)
    }

    nonisolated private static let key = P256.Signing.PrivateKey().publicKey.derRepresentation
    private func directory() -> URL { FileManager.default.temporaryDirectory.appendingPathComponent("status-owner-\(UUID())") }
    private func configuration(_ directory: URL, onUnavailable: @escaping @Sendable () -> Void = {},
                               resolver: @escaping @Sendable (Data?) throws -> Data = { _ in StatusOwnerTests.key }) -> StatusOnlyHostConfiguration {
        StatusOnlyHostConfiguration(directory: directory, clock: OwnerClock(), random: OwnerRandom(),
                                    identityResolver: resolver, onUnavailable: onUnavailable)
    }
    private func lockInode(_ directory: URL) throws -> UInt64 {
        let values = try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent("admission.lock").path)
        return try XCTUnwrap(values[.systemFileNumber] as? NSNumber).uint64Value
    }
    private func expect(_ expected: StatusHostError, _ body: () async throws -> Void) async {
        do { try await body(); XCTFail("Expected \(expected)") }
        catch { XCTAssertEqual(error as? StatusHostError, expected) }
    }
}

private struct OwnerClock: StatusClock { func nowNanoseconds() -> UInt64 { 1 } }
private struct OwnerRandom: StatusRandomSource { func bytes(count: Int) throws -> Data { Data(repeating: 7, count: count) } }
private struct ResolverFailure: Error {}
private final class OwnerBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T
    init(_ value: T) { self.value = value }
    func get() -> T { lock.withLock { value } }
    func set(_ value: T) { lock.withLock { self.value = value } }
    func update(_ body: (inout T) -> Void) { lock.withLock { body(&value) } }
}
private final class OwnerSentinel: @unchecked Sendable {
    let key = DispatchSpecificKey<Int>()
    let events = OwnerBox<[String]>([])
    let violations = OwnerBox<[String]>([])
    func check(_ event: String) {
        if DispatchQueue.getSpecific(key: key) != 42 || Thread.isMainThread { violations.update { $0.append(event) } }
        events.update { $0.append(event) }
    }
}
private struct OwnerBackup: StatusBackupExclusion {
    let sentinel: OwnerSentinel
    func applyAndVerify(_ directory: URL) throws { sentinel.check("backup") }
}
private final class OwnerNative: SQLiteNative, @unchecked Sendable {
    let sentinel: OwnerSentinel
    let blockNextRead = OwnerBox(false)
    let failNextRead = OwnerBox(false)
    let entered = XCTestExpectation(description: "blocked owner read")
    let release = DispatchSemaphore(value: 0)
    let original = JournalStorageError(kind: .sqlite, message: "injected read", sqliteCode: SQLITE_IOERR, sqliteExtendedCode: 266)
    init(sentinel: OwnerSentinel) { self.sentinel = sentinel }
    func step(_ statement: OpaquePointer) -> Int32 {
        sentinel.check("sqlite")
        let connection = sqlite3_db_handle(statement)!
        sqlite3_trace_v2(connection, UInt32(SQLITE_TRACE_CLOSE), { _, context, _, _ in
            Unmanaged<OwnerSentinel>.fromOpaque(context!).takeUnretainedValue().check("close")
            return 0
        }, Unmanaged.passUnretained(sentinel).toOpaque())
        if blockNextRead.get() {
            blockNextRead.set(false)
            entered.fulfill()
            release.wait()
        }
        if failNextRead.get() { failNextRead.set(false); return SQLITE_IOERR }
        return sqlite3_step(statement)
    }
    func failure(_ connection: OpaquePointer) -> JournalStorageError { original }
}
