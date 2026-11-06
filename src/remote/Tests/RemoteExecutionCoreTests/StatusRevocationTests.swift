import CSQLite
import Dispatch
import Foundation
import XCTest
@testable import RemoteExecutionCore

@MainActor
final class StatusRevocationTests: XCTestCase {
    // Catches a BEGIN/write on unenrolled revoke, live pending confirmation,
    // or quarantining a healthy owner on this ordinary refusal.
    func testUnenrolledRevokeCancelsPendingWithoutWrite() async throws {
        let fixture = try await StatusLeaseFixture.open()
        defer { fixture.remove() }
        let host = fixture.handles.host
        let (context, candidate) = try await fixture.pending()
        let beforePolicy = try await fixture.policy()
        let beforeBytes = try fixture.inventory()
        fixture.native.statements.set([])
        await expectStatusError(.notEnrolled) { try await host.revokeController() }
        XCTAssertFalse(fixture.native.statements.get().contains { $0.hasPrefix("BEGIN") || $0.hasPrefix("UPDATE") || $0 == "COMMIT" || $0 == "ROLLBACK" })
        XCTAssertEqual(try fixture.inventory(), beforeBytes)
        let afterPolicy = try await fixture.policy()
        XCTAssertEqual(afterPolicy, beforePolicy)
        XCTAssertNil(afterPolicy.controllerSPKI)
        let status = try await host.localStatus()
        XCTAssertEqual(status.enrollment, .closed)
        XCTAssertEqual(fixture.unavailable.get(), 0)
        await expectStatusError(.invalidCandidate) { try await host.confirmCandidate(candidateID: candidate.candidateID) }
        await expectStatusError(.invalidContext) { _ = try await host.authenticate(contextID: context.contextID) }
        // Open windows and unconsumed contexts are also cancelled without writes.
        let window = try await host.openEnrollment()
        let unconsumed = try await host.beginHandshake(fixture.input(status.snapshot, mode: .enrollment, invitation: window.invitationID))
        await expectStatusError(.notEnrolled) { try await host.revokeController() }
        await expectStatusError(.invalidContext) { try await host.recordProofFailure(contextID: unconsumed.contextID) }
        let next = try await host.openEnrollment()
        XCTAssertEqual(next.hostID, status.snapshot.hostID)
        await host.close()
    }

    // Catches key clearing, double generation increments, lease/context survival,
    // revoked enrollment, and a signed-Int64 overflow that wraps or fences owner.
    func testRevocationCommitAndFaults() async throws {
        let fixture = try await StatusLeaseFixture.open()
        defer { fixture.remove() }
        try await fixture.enroll()
        let lease = try await fixture.authenticate()
        let before = try await fixture.policy()
        let pending = try await fixture.handles.host.beginHandshake(fixture.input(before.snapshot))
        try await fixture.handles.host.revokeController()
        let revoked = try await fixture.policy()
        XCTAssertEqual(revoked.controllerState, .revoked)
        XCTAssertEqual(revoked.controllerSPKI, StatusLeaseFixture.controllerKey)
        XCTAssertEqual(revoked.controllerGeneration, 2)
        XCTAssertEqual(revoked.storageEpoch, before.storageEpoch)
        XCTAssertEqual(revoked.controllerID, before.controllerID)
        let bytes = try fixture.inventory()
        try await fixture.handles.host.revokeController()
        let repeated = try await fixture.policy()
        XCTAssertEqual(repeated, revoked)
        XCTAssertEqual(try fixture.inventory(), bytes)
        await expectStatusError(.staleLease) { _ = try await fixture.handles.controller.status(over: lease) }
        await expectStatusError(.invalidContext) { _ = try await fixture.handles.host.authenticate(contextID: pending.contextID) }
        await expectStatusError(.alreadyEnrolled) { _ = try await fixture.handles.host.openEnrollment() }
        await expectStatusError(.notEnrolled) { _ = try await fixture.handles.host.beginHandshake(fixture.input(before.snapshot)) }
        await fixture.handles.host.close()
        let reopened = try await StatusOnlyHost.open(configuration: fixture.configuration)
        let saved = try await reopened.host.localStatus()
        XCTAssertEqual(saved.controllerState, .revoked)
        XCTAssertEqual(saved.snapshot.controllerGeneration, 2)
        await reopened.host.close()

        let overflow = try await StatusLeaseFixture.open(generation: UInt64(Int64.max))
        defer { overflow.remove() }
        let oldLease = try await overflow.authenticate()
        let original = try await overflow.policy()
        let originalBytes = try overflow.inventory()
        await expectStatusError(.generationOverflow) { try await overflow.handles.host.revokeController() }
        let preserved = try await overflow.policy()
        XCTAssertEqual(preserved, original)
        XCTAssertEqual(try overflow.inventory(), originalBytes)
        XCTAssertEqual(overflow.unavailable.get(), 0)
        await expectStatusError(.staleLease) { _ = try await overflow.handles.controller.status(over: oldLease) }
        _ = try await overflow.authenticate()
        await overflow.handles.host.close()
    }

    // A status caller overlapping the blocked revocation must see the invalidated
    // lease. The caller signal does not establish arrival on the owner queue.
    func testOverlappingStatusCallerCannotReviveRevokedLease() async throws {
        let fixture = try await StatusLeaseFixture.open()
        defer { fixture.remove() }
        try await fixture.enroll()
        let lease = try await fixture.authenticate()
        let entered = XCTestExpectation(description: "revocation write blocked")
        let release = DispatchSemaphore(value: 0)
        fixture.native.onStep.set { sql in
            if sql.hasPrefix("UPDATE prototype_status SET controller_state = 'revoked'") {
                fixture.native.onStep.set(nil)
                entered.fulfill()
                release.wait()
            }
        }
        let revocation = Task { try await fixture.handles.host.revokeController() }
        await fulfillment(of: [entered], timeout: 5)
        let readStarted = XCTestExpectation(description: "status caller overlaps blocked revocation")
        let read = Task { @MainActor in
            readStarted.fulfill()
            return try await fixture.handles.controller.status(over: lease)
        }
        await fulfillment(of: [readStarted], timeout: 5)
        release.signal()
        try await revocation.value
        await expectStatusError(.staleLease) { _ = try await read.value }
        let status = try await fixture.handles.host.localStatus()
        XCTAssertEqual(status.controllerState, .revoked)
        XCTAssertEqual(status.snapshot.controllerGeneration, 2)
        await fixture.handles.host.close()
    }

    // Every storage fault, including a successful rollback, must fence authority,
    // retain the original/composite error and retain lock until explicit close.
    func testRevocationStorageFaultsFenceOwner() async throws {
        for fault in [StatusLeaseNative.Fault.update, .rollback, .unknownCommit] {
            let fixture = try await StatusLeaseFixture.open()
            defer { fixture.remove() }
            try await fixture.enroll()
            let lease = try await fixture.authenticate()
            fixture.native.fault.set(fault)
            let first = await capture { try await fixture.handles.host.revokeController() }
            XCTAssertEqual(fixture.unavailable.get(), 1)
            let later = await capture { _ = try await fixture.handles.controller.status(over: lease) }
            XCTAssertEqual(describe(first), describe(later))
            let local = await capture { _ = try await fixture.handles.host.localStatus() }
            XCTAssertEqual(describe(first), describe(local))
            let retry = await capture { try await fixture.handles.host.revokeController() }
            XCTAssertEqual(describe(first), describe(retry))
            XCTAssertEqual(fixture.unavailable.get(), 1)
            switch fault {
            case .update: XCTAssertEqual((first as? JournalStorageError)?.message, "injected update")
            case .rollback:
                let composite = try XCTUnwrap(first as? JournalTransactionError)
                XCTAssertEqual((composite.originalError as? JournalStorageError)?.message, "injected update")
                XCTAssertEqual((composite.rollbackError as? JournalStorageError)?.message, "injected rollback")
            case .unknownCommit:
                let unknown = try XCTUnwrap(first as? JournalCommitOutcomeUnknownError)
                XCTAssertEqual((unknown.originalError as? JournalStorageError)?.message, "injected commit")
            case .none: XCTFail("Unexpected fault")
            }
            XCTAssertThrowsError(try JournalDirectoryLock(directory: fixture.directory)) {
                XCTAssertEqual(($0 as? JournalStorageError)?.kind, .alreadyOwned)
            }
            await fixture.handles.host.close()
            let reopened = try await StatusOnlyHost.open(configuration: fixture.configuration)
            let durable = try await reopened.host.localStatus()
            XCTAssertEqual(durable.controllerState, fault == .unknownCommit ? .revoked : .enrolled)
            XCTAssertEqual(durable.snapshot.controllerGeneration, fault == .unknownCommit ? 2 : 1)
            await reopened.host.close()
        }
    }
    private func capture(_ body: () async throws -> Void) async -> any Error {
        do { try await body(); XCTFail("Expected retained failure"); return StatusHostError.closed }
        catch { return error }
    }
    private func describe(_ error: any Error) -> String { String(reflecting: error) }
}
