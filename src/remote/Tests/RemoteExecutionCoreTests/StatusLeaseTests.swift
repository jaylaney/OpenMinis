import Foundation
import XCTest
@testable import RemoteExecutionCore

@MainActor
final class StatusLeaseTests: XCTestCase {
    // Catches replacing authority before context validation or accepting replay,
    // expired/foreign contexts, and leases bound to a different owner or token.
    func testVerifiedReconnectRechecksAndReplaces() async throws {
        let fixture = try await StatusLeaseFixture.open()
        defer { fixture.remove() }
        let host = fixture.handles.host
        let (_, pending) = try await fixture.pending()
        let snapshot = try await host.localStatus().snapshot
        let windowContext = try await host.owner.perform { state in
            let policy = try state.requireJournal().readPolicy()
            return StatusFixedHandshake(input: fixture.input(snapshot, mode: .enrollment),
                                        deadlineNanoseconds: 10_000_000_100, policy: policy)
        }
        try await host.confirmCandidate(candidateID: pending.candidateID)
        let first = try await fixture.authenticate()
        await expectStatusError(.invalidContext) { _ = try await host.authenticate(contextID: UUID()) }
        let wrongModeID = try await host.owner.perform { state in
            let id = UUID()
            state.handshakeContexts[id] = windowContext
            return id
        }
        await expectStatusError(.invalidHandshake) { _ = try await host.authenticate(contextID: wrongModeID) }
        await expectStatusError(.invalidContext) { _ = try await host.authenticate(contextID: wrongModeID) }
        let validAfterRefusal = try await fixture.handles.controller.status(over: first)
        XCTAssertEqual(validAfterRefusal.executionCapability, .unsupported)
        let expired = try await host.beginHandshake(fixture.input(snapshot))
        fixture.queue.async { fixture.clock.now.set(10_000_000_100) }
        await expectStatusError(.deadlineExpired) { _ = try await host.authenticate(contextID: expired.contextID) }
        await expectStatusError(.invalidContext) { _ = try await host.authenticate(contextID: expired.contextID) }
        _ = try await fixture.handles.controller.status(over: first)
        let fresh = try await host.beginHandshake(fixture.input(snapshot))
        let second = try await host.authenticate(contextID: fresh.contextID)
        XCTAssertNotEqual(first.connectionToken, second.connectionToken)
        await expectStatusError(.invalidContext) { _ = try await host.authenticate(contextID: fresh.contextID) }
        await expectStatusError(.staleLease) { _ = try await fixture.handles.controller.status(over: first) }
        let variants = [
            StatusControllerLease(incarnation: UUID(), connectionToken: second.connectionToken, connectionID: second.connectionID, storageEpoch: second.storageEpoch, controllerGeneration: second.controllerGeneration),
            StatusControllerLease(incarnation: second.incarnation, connectionToken: UUID(), connectionID: second.connectionID, storageEpoch: second.storageEpoch, controllerGeneration: second.controllerGeneration),
            StatusControllerLease(incarnation: second.incarnation, connectionToken: second.connectionToken, connectionID: UUID(), storageEpoch: second.storageEpoch, controllerGeneration: second.controllerGeneration),
            StatusControllerLease(incarnation: second.incarnation, connectionToken: second.connectionToken, connectionID: second.connectionID, storageEpoch: UUID(), controllerGeneration: second.controllerGeneration),
            StatusControllerLease(incarnation: second.incarnation, connectionToken: second.connectionToken, connectionID: second.connectionID, storageEpoch: second.storageEpoch, controllerGeneration: 2)
        ]
        for lease in variants {
            await expectStatusError(.staleLease) { _ = try await fixture.handles.controller.status(over: lease) }
        }
        let other = try await StatusLeaseFixture.open()
        defer { other.remove() }
        await expectStatusError(.staleLease) { _ = try await other.handles.controller.status(over: second) }
        await other.handles.host.close()
        _ = try await fixture.handles.controller.status(over: second)
        await host.disconnect(connectionID: second.connectionID)
        await expectStatusError(.staleLease) { _ = try await fixture.handles.controller.status(over: second) }
        await host.close()
    }

    // Catches omitting the final policy/key check after proof verification,
    // including an old Challenge's epoch/generation after policy changes.
    func testAuthenticationRechecksFixedPolicyAndKey() async throws {
        let fixture = try await StatusLeaseFixture.open()
        defer { fixture.remove() }
        try await fixture.enroll()
        let lease = try await fixture.authenticate()
        let policy = try await fixture.policy()
        let oldPolicies = [
            StatusStoredPolicy(hostID: policy.hostID, storageEpoch: UUID(), controllerID: policy.controllerID,
                               controllerGeneration: 1, controllerState: .enrolled, controllerSPKI: policy.controllerSPKI, hostPin: policy.hostPin),
            StatusStoredPolicy(hostID: policy.hostID, storageEpoch: policy.storageEpoch, controllerID: policy.controllerID,
                               controllerGeneration: 2, controllerState: .enrolled, controllerSPKI: policy.controllerSPKI, hostPin: policy.hostPin),
            StatusStoredPolicy(hostID: policy.hostID, storageEpoch: policy.storageEpoch, controllerID: policy.controllerID,
                               controllerGeneration: 1, controllerState: .enrolled, controllerSPKI: StatusLeaseFixture.otherKey, hostPin: policy.hostPin)
        ]
        for oldPolicy in oldPolicies {
            let id = try await fixture.handles.host.owner.perform { state in
                let id = UUID()
                state.handshakeContexts[id] = StatusFixedHandshake(input: fixture.input(policy.snapshot),
                                                                 deadlineNanoseconds: 10_000_000_100, policy: oldPolicy)
                return id
            }
            await expectStatusError(.invalidContext) { _ = try await fixture.handles.host.authenticate(contextID: id) }
            _ = try await fixture.handles.controller.status(over: lease)
        }
        let badKeyID = try await fixture.handles.host.owner.perform { state in
            let id = UUID()
            state.handshakeContexts[id] = StatusFixedHandshake(input: fixture.input(policy.snapshot, key: StatusLeaseFixture.otherKey),
                                                             deadlineNanoseconds: 10_000_000_100, policy: policy)
            return id
        }
        await expectStatusError(.invalidKey) { _ = try await fixture.handles.host.authenticate(contextID: badKeyID) }
        _ = try await fixture.handles.controller.status(over: lease)
        XCTAssertEqual(fixture.unavailable.get(), 0)
        await fixture.handles.host.close()
    }

    // Catches checking expiry only before a slow committed-policy read.
    func testDeadlineRecheckedAfterPolicyRead() async throws {
        let fixture = try await StatusLeaseFixture.open()
        defer { fixture.remove() }
        try await fixture.enroll()
        let lease = try await fixture.authenticate()
        let policy = try await fixture.policy()
        let context = try await fixture.handles.host.beginHandshake(fixture.input(policy.snapshot))
        fixture.native.onStep.set { sql in
            if sql.contains("FROM prototype_status") { fixture.clock.now.set(10_000_000_100) }
        }
        await expectStatusError(.deadlineExpired) { _ = try await fixture.handles.host.authenticate(contextID: context.contextID) }
        fixture.native.onStep.set(nil)
        await expectStatusError(.invalidContext) { _ = try await fixture.handles.host.authenticate(contextID: context.contextID) }
        _ = try await fixture.handles.controller.status(over: lease)
        await fixture.handles.host.close()
    }

    // Catches status writes, cached policy fallback, and leases surviving reopen.
    func testStatusReadsCommittedPolicyOnly() async throws {
        let fixture = try await StatusLeaseFixture.open()
        defer { fixture.remove() }
        try await fixture.enroll()
        let lease = try await fixture.authenticate()
        let before = try fixture.inventory()
        fixture.native.statements.set([])
        let status = try await fixture.handles.controller.status(over: lease)
        XCTAssertEqual(status.storageEpoch, lease.storageEpoch)
        XCTAssertEqual(status.controllerGeneration, 1)
        XCTAssertEqual(status.executionCapability, .unsupported)
        XCTAssertEqual(try fixture.inventory(), before)
        XCTAssertFalse(fixture.native.statements.get().contains { $0.hasPrefix("BEGIN") || $0.hasPrefix("UPDATE") || $0 == "COMMIT" })
        XCTAssertTrue(fixture.native.statements.get().contains { $0.contains("FROM prototype_status") })
        await fixture.handles.host.close()
        let reopened = try await StatusOnlyHost.open(configuration: fixture.configuration)
        await expectStatusError(.staleLease) { _ = try await reopened.controller.status(over: lease) }
        let local = try await reopened.host.localStatus()
        XCTAssertEqual(local.snapshot, status)
        await reopened.host.close()
    }
}
