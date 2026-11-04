import CryptoKit
import Dispatch
import Foundation
import XCTest
@testable import RemoteExecutionCore

@MainActor
final class StatusEnrollmentTests: XCTestCase {
    // Catches generating SAS before fixation or letting a competing proof replace it.
    func testOneClaimPostFixationNonce() async throws {
        let fixture = try await fixture()
        defer { fixture.remove() }
        let host = fixture.handles.host
        let window = try await host.openEnrollment()
        let first = try await host.beginHandshake(input(window))
        let second = try await host.beginHandshake(input(window, key: Self.otherKey))
        let digest = Data(repeating: 0x31, count: 32)
        let observations = EnrollmentBox<[Bool]>([])
        let state = try await host.owner.perform { $0 }
        fixture.random.observe.set { count in
            if count == 32 {
                observations.update { $0.append(state.fixedEnrollmentClaim?.claimDigest == digest && state.enrollmentWindow == nil && state.handshakeContexts[first.contextID] == nil) }
            }
        }
        let candidate = try await host.acceptCandidate(contextID: first.contextID, claimDigest: digest)
        fixture.random.observe.set(nil)
        XCTAssertEqual(observations.get(), [true])
        XCTAssertEqual(candidate.claimDigest, digest)
        XCTAssertEqual(candidate.sasNonce.count, 32)
        await expect(.enrollmentClosed) { _ = try await host.acceptCandidate(contextID: second.contextID, claimDigest: Data(repeating: 9, count: 32)) }
        await expect(.invalidContext) { _ = try await host.acceptCandidate(contextID: first.contextID, claimDigest: digest) }
        let pending = try await host.localStatus()
        XCTAssertEqual(pending.enrollment, .candidate)
        let arbitrary = StatusControllerLease(incarnation: UUID(), connectionToken: UUID(), connectionID: UUID(), storageEpoch: pending.snapshot.storageEpoch, controllerGeneration: 1)
        await expect(.staleLease) { _ = try await fixture.handles.controller.status(over: arbitrary) }
        let returned = try await host.confirmCandidate(candidateID: candidate.candidateID)
        let committed = try await host.localStatus()
        XCTAssertEqual(returned, committed.snapshot)
        XCTAssertEqual(committed.controllerState, .enrolled)
        XCTAssertEqual(committed.enrollment, .closed)
        XCTAssertEqual(committed.snapshot.controllerID, pending.snapshot.controllerID)
        XCTAssertEqual(committed.snapshot.controllerGeneration, 1)
        let saved = try await host.owner.perform { try $0.requireJournal().readPolicy().controllerSPKI }
        XCTAssertEqual(saved, Self.key)
        await expect(.alreadyEnrolled) { _ = try await host.openEnrollment() }
        await expect(.invalidCandidate) { try await host.confirmCandidate(candidateID: candidate.candidateID) }
        await host.close()
    }

    // Catches validating only a pin, consuming a valid invitation on wrong host,
    // context replay, or replacing a live lease before normal authentication.
    func testWrongHostAndSingleUseContext() async throws {
        let fixture = try await fixture()
        defer { fixture.remove() }
        let host = fixture.handles.host
        let window = try await host.openEnrollment()
        let originalLease = try await host.owner.perform { state in
            let policy = try state.requireJournal().readPolicy()
            let lease = StatusControllerLease(incarnation: state.incarnation!, connectionToken: UUID(), connectionID: UUID(), storageEpoch: policy.storageEpoch, controllerGeneration: 1)
            state.currentLease = lease
            return lease
        }
        for mode in [StatusHandshakeMode.enrollment, .normal] {
            await expect(.identityMismatch) { _ = try await host.beginHandshake(self.input(window, mode: mode, hostID: UUID())) }
            await expect(.identityMismatch) { _ = try await host.beginHandshake(self.input(window, mode: mode, pin: Data(repeating: 7, count: 32))) }
        }
        let preserved = try await host.owner.perform { $0.currentLease }
        XCTAssertEqual(preserved, originalLease)
        let observed1 = try await host.localStatus().enrollment
        XCTAssertEqual(observed1, .open)
        let context = try await host.beginHandshake(input(window))
        XCTAssertEqual(context.controllerID, Self.zero)
        XCTAssertEqual(context.generation, 0)
        XCTAssertEqual(context.invitationSecret, window.secret)
        try await host.recordProofFailure(contextID: context.contextID)
        await expect(.invalidContext) { try await host.recordProofFailure(contextID: context.contextID) }
        await expect(.invalidContext) { _ = try await host.acceptCandidate(contextID: context.contextID, claimDigest: Data(repeating: 1, count: 32)) }
        let valid = try await host.beginHandshake(input(window))
        let candidate = try await host.acceptCandidate(contextID: valid.contextID, claimDigest: Data(repeating: 1, count: 32))
        try await host.confirmCandidate(candidateID: candidate.candidateID)
        let snapshot = try await host.localStatus()
        let normal = try await host.beginHandshake(input(window, mode: .normal, invitationID: Self.zero))
        XCTAssertEqual(normal.controllerID, snapshot.snapshot.controllerID)
        XCTAssertEqual(normal.generation, 1)
        XCTAssertNil(normal.invitationSecret)
        try await host.recordProofFailure(contextID: normal.contextID)
        await expect(.invalidContext) { try await host.recordProofFailure(contextID: normal.contextID) }
        await expect(.invalidHandshake) { _ = try await host.beginHandshake(self.input(window, mode: .normal)) }
        await expect(.invalidKey) { _ = try await host.beginHandshake(self.input(window, mode: .normal, key: Self.otherKey, invitationID: Self.zero)) }
        await host.close()
    }

    // Catches off-by-one deadlines, resetting failure counts, normal failures
    // counting as enrollment failures, and wrapping monotonic arithmetic.
    func testWindowFailureAndDeadlineLimits() async throws {
        let fixture = try await fixture()
        defer { fixture.remove() }
        let host = fixture.handles.host
        let window = try await host.openEnrollment()
        XCTAssertEqual(window.deadlineNanoseconds, 120_000_000_100)
        for index in 0..<5 {
            let context = try await host.beginHandshake(input(window))
            try await host.recordProofFailure(contextID: context.contextID)
            let observed2 = try await host.localStatus().enrollment
            XCTAssertEqual(observed2, index == 4 ? .closed : .open)
        }
        await expect(.enrollmentClosed) { _ = try await host.beginHandshake(self.input(window)) }
        let expiring = try await host.openEnrollment()
        fixture.clock.now.set(expiring.deadlineNanoseconds)
        let observed3 = try await host.localStatus().enrollment
        XCTAssertEqual(observed3, .closed)
        await expect(.enrollmentClosed) { _ = try await host.beginHandshake(self.input(expiring, accepted: expiring.deadlineNanoseconds)) }
        fixture.clock.now.set(UInt64.max - 5)
        await expect(.deadlineOverflow) { _ = try await host.openEnrollment() }
        fixture.clock.now.set(100)
        let fresh = try await host.openEnrollment()
        fixture.clock.now.set(UInt64.max - 5)
        await expect(.deadlineOverflow) { _ = try await host.beginHandshake(self.input(fresh, accepted: UInt64.max - 5)) }
        await host.close()
    }

    // Catches extending proof lifetime at dispatch, confirmation after disconnect,
    // restarting confirmation lifetime at candidate acceptance, or undoing commit.
    func testDelayedProofAndConfirmDisconnectOrder() async throws {
        let fixture = try await fixture()
        defer { fixture.remove() }
        let host = fixture.handles.host
        let window = try await host.openEnrollment()
        let context = try await host.beginHandshake(input(window))
        // A queued clock barrier advances time before the proof job dispatches.
        fixture.queue.async { fixture.clock.now.set(10_000_000_100) }
        await expect(.deadlineExpired) { _ = try await host.acceptCandidate(contextID: context.contextID, claimDigest: Data(repeating: 1, count: 32)) }
        await expect(.invalidContext) { try await host.recordProofFailure(contextID: context.contextID) }
        await expect(.deadlineExpired) { _ = try await host.beginHandshake(self.input(window)) }
        fixture.clock.now.set(110_000_000_100)
        let late = try await host.beginHandshake(input(window, accepted: 110_000_000_100))
        let candidate = try await host.acceptCandidate(contextID: late.contextID, claimDigest: Data(repeating: 1, count: 32))
        fixture.clock.now.set(window.deadlineNanoseconds)
        await expect(.invalidCandidate) { try await host.confirmCandidate(candidateID: candidate.candidateID) }
        let next = try await host.openEnrollment()
        let connection = UUID()
        let other = try await host.beginHandshake(input(next, connection: connection, accepted: fixture.clock.now.get()))
        let disconnected = try await host.acceptCandidate(contextID: other.contextID, claimDigest: Data(repeating: 2, count: 32))
        await host.disconnect(connectionID: connection)
        await expect(.invalidCandidate) { try await host.confirmCandidate(candidateID: disconnected.candidateID) }
        let observed4 = try await host.localStatus().controllerState
        XCTAssertEqual(observed4, .unenrolled)
        let finalWindow = try await host.openEnrollment()
        let finalConnection = UUID()
        let finalContext = try await host.beginHandshake(input(finalWindow, connection: finalConnection, accepted: fixture.clock.now.get()))
        let final = try await host.acceptCandidate(contextID: finalContext.contextID, claimDigest: Data(repeating: 3, count: 32))
        try await host.confirmCandidate(candidateID: final.candidateID)
        await host.disconnect(connectionID: finalConnection)
        let observed5 = try await host.localStatus().controllerState
        XCTAssertEqual(observed5, .enrolled)
        await host.close()
        let reopened = try await StatusOnlyHost.open(configuration: fixture.configuration)
        let observed6 = try await reopened.host.localStatus().controllerState
        XCTAssertEqual(observed6, .enrolled)
        let observed7 = try await reopened.host.localStatus().enrollment
        XCTAssertEqual(observed7, .closed)
        await expect(.invalidContext) { try await reopened.host.recordProofFailure(contextID: finalContext.contextID) }
        await reopened.host.close()
    }

    // Catches rejection reopening a consumed invitation, revoked re-enrollment,
    // and leaving pending authority reachable after a terminal random failure.
    func testRejectRevokedAndTerminalFailureClearMemory() async throws {
        let fixture = try await fixture()
        defer { fixture.remove() }
        let host = fixture.handles.host
        let window = try await host.openEnrollment()
        let context = try await host.beginHandshake(input(window))
        let candidate = try await host.acceptCandidate(contextID: context.contextID, claimDigest: Data(repeating: 4, count: 32))
        try await host.rejectCandidate(candidateID: candidate.candidateID)
        await expect(.invalidCandidate) { try await host.confirmCandidate(candidateID: candidate.candidateID) }
        await expect(.enrollmentClosed) { _ = try await host.beginHandshake(self.input(window)) }
        let next = try await host.openEnrollment()
        let fixed = try await host.beginHandshake(input(next))
        let bookkeeping = try await host.owner.perform { $0 }
        fixture.random.failure.set(true)
        for _ in 0..<2 {
            do {
                _ = try await host.acceptCandidate(contextID: fixed.contextID, claimDigest: Data(repeating: 5, count: 32))
                XCTFail("Expected original random failure")
            } catch { XCTAssertTrue(error is EnrollmentRandomFailure) }
        }
        XCTAssertEqual(fixture.unavailable.get(), 1)
        fixture.queue.sync {
            XCTAssertNil(bookkeeping.incarnation)
            XCTAssertNil(bookkeeping.enrollmentWindow)
            XCTAssertNil(bookkeeping.fixedEnrollmentClaim)
            XCTAssertNil(bookkeeping.enrollmentCandidate)
            XCTAssertTrue(bookkeeping.handshakeContexts.isEmpty)
        }
        await host.close()
        fixture.random.failure.set(false)
        let reopened = try await StatusOnlyHost.open(configuration: fixture.configuration)
        let reopenedStatus = try await reopened.host.localStatus()
        XCTAssertEqual(reopenedStatus.enrollment, .closed)
        // Internal durable-policy fixture only: production revocation belongs to Task 5.
        try await reopened.host.owner.perform { state in
            _ = try state.requireJournal().confirm(key: Self.key)
            _ = try state.requireJournal().revoke()
        }
        await expect(.alreadyEnrolled) { _ = try await reopened.host.openEnrollment() }
        await expect(.notEnrolled) { _ = try await reopened.host.beginHandshake(self.input(window, mode: .normal, invitationID: Self.zero)) }
        await reopened.host.close()
    }

    // Catches validating malformed Hello/digest data too late, invalidating the
    // whole owner on ordinary key errors, and accepting proof after disconnect.
    func testMalformedInputsAndPendingDisconnect() async throws {
        let fixture = try await fixture()
        defer { fixture.remove() }
        let host = fixture.handles.host
        let window = try await host.openEnrollment()
        let connection = UUID()
        let malformed = StatusHandshakeInput(connectionID: connection, acceptedAtNanoseconds: 100, mode: .enrollment,
                                             hostID: window.hostID, hostPin: window.hostPin, controllerSPKI: Self.key,
                                             clientNonce: Data(), invitationID: window.invitationID)
        await expect(.invalidHandshake) { _ = try await host.beginHandshake(malformed) }
        await expect(.invalidKey) { _ = try await host.beginHandshake(self.input(window, key: Data())) }
        await expect(.invalidHandshake) { _ = try await host.beginHandshake(self.input(window, accepted: 101)) }
        let context = try await host.beginHandshake(input(window, connection: connection))
        await expect(.invalidHandshake) { _ = try await host.beginHandshake(self.input(window, connection: connection)) }
        await host.disconnect(connectionID: connection)
        await expect(.invalidContext) { _ = try await host.acceptCandidate(contextID: context.contextID, claimDigest: Data(repeating: 1, count: 32)) }
        let fresh = try await host.beginHandshake(input(window))
        await expect(.invalidHandshake) { _ = try await host.acceptCandidate(contextID: fresh.contextID, claimDigest: Data()) }
        await expect(.invalidContext) { try await host.recordProofFailure(contextID: fresh.contextID) }
        XCTAssertEqual(fixture.unavailable.get(), 0)
        let status = try await host.localStatus()
        XCTAssertEqual(status.enrollment, .open)
        await host.close()
    }

    nonisolated private static let key = P256.Signing.PrivateKey().publicKey.derRepresentation
    nonisolated private static let otherKey = P256.Signing.PrivateKey().publicKey.derRepresentation
    nonisolated private static let zero = UUID(uuid: (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0))
    private func input(_ window: StatusEnrollmentWindow, mode: StatusHandshakeMode = .enrollment,
                       connection: UUID = UUID(), accepted: UInt64 = 100, hostID: UUID? = nil,
                       pin: Data? = nil, key: Data = StatusEnrollmentTests.key, invitationID: UUID? = nil) -> StatusHandshakeInput {
        StatusHandshakeInput(connectionID: connection, acceptedAtNanoseconds: accepted, mode: mode,
                             hostID: hostID ?? window.hostID, hostPin: pin ?? window.hostPin,
                             controllerSPKI: key, clientNonce: Data(repeating: 5, count: 32), invitationID: invitationID ?? window.invitationID)
    }
    private func expect(_ expected: StatusHostError, _ body: () async throws -> Void) async {
        do { try await body(); XCTFail("Expected \(expected)") }
        catch { XCTAssertEqual(error as? StatusHostError, expected) }
    }
    private func fixture() async throws -> EnrollmentFixture {
        let leaf = FileManager.default.temporaryDirectory.appendingPathComponent("status-enrollment-\(UUID())")
        let clock = EnrollmentClock()
        let random = EnrollmentRandom()
        let queue = DispatchQueue(label: "status-enrollment-fixture")
        let unavailable = EnrollmentBox(0)
        let config = StatusOnlyHostConfiguration(directory: leaf, clock: clock, random: random,
                                                 identityResolver: { _ in Self.key }, onUnavailable: { unavailable.update { $0 += 1 } })
        return EnrollmentFixture(directory: leaf, clock: clock, random: random, queue: queue, unavailable: unavailable, configuration: config,
                                 handles: try await StatusOnlyHost.open(configuration: config, native: SystemSQLiteNative(),
                                                                        backupExclusion: EnrollmentBackup(), queue: queue))
    }
}

private struct EnrollmentFixture {
    let directory: URL
    let clock: EnrollmentClock
    let random: EnrollmentRandom
    let queue: DispatchQueue
    let unavailable: EnrollmentBox<Int>
    let configuration: StatusOnlyHostConfiguration
    let handles: StatusOnlyHostHandles
    func remove() { try? FileManager.default.removeItem(at: directory) }
}
private final class EnrollmentBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T
    init(_ value: T) { self.value = value }
    func get() -> T { lock.withLock { value } }
    func set(_ value: T) { lock.withLock { self.value = value } }
    func update(_ body: (inout T) -> Void) { lock.withLock { body(&value) } }
}
private final class EnrollmentClock: StatusClock, Sendable {
    let now = EnrollmentBox<UInt64>(100)
    func nowNanoseconds() -> UInt64 { now.get() }
}
private final class EnrollmentRandom: StatusRandomSource, Sendable {
    let observe = EnrollmentBox<(@Sendable (Int) -> Void)?>(nil)
    let sequence = EnrollmentBox<UInt8>(0)
    let failure = EnrollmentBox(false)
    func bytes(count: Int) throws -> Data {
        if failure.get() { throw EnrollmentRandomFailure() }
        observe.get()?(count)
        sequence.update { $0 &+= 1 }
        return Data(repeating: sequence.get(), count: count)
    }
}

private struct EnrollmentRandomFailure: Error {}
private struct EnrollmentBackup: StatusBackupExclusion { func applyAndVerify(_ directory: URL) throws {} }
