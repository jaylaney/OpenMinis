#if os(macOS)
import XCTest
import Foundation
import CryptoKit
import Security
import CSQLite
@testable import RemoteExecutionCore
@testable import RemotePrototypeTransport
import RemotePrototypeWire
@testable import RemotePrototypeHost

final class HostBridgeTests: XCTestCase, @unchecked Sendable {
    // Resetting a fence or accepting a delayed listener callback revives old hosting.
    func testDirectUnenrolledRevokeLeavesFenceDisabled() async throws {
        let f = try await HostFixture.open()
        defer { f.remove() }
        do { try await f.service.revokeController(); XCTFail("unenrolled revoke succeeded") }
        catch { XCTAssertEqual(error as? StatusHostError, .notEnrolled) }
        let late = BridgeChannel()
        f.listener.accept(late.channel)
        XCTAssertTrue(late.cancelled)
        let state = await f.service.presentation()
        XCTAssertFalse(state.isEnabled)
        try await f.service.enable(configuration: f.configuration, endpoint: f.endpoint)
        let fresh = BridgeChannel()
        f.listener.accept(fresh.channel)
        XCTAssertFalse(fresh.cancelled)
        await f.service.disable()
    }

    // Accepting an invalid proof would consume enrollment; failing normal proof
    // must not replace the existing working lease or close its channel.
    func testProofVerifiedBeforeOwnerAndRechecked() async throws {
        let f = try await HostFixture.open()
        defer { f.remove() }
        let invitation = try await f.service.openEnrollment()
        let bad = try await f.handshake(invitation: invitation)
        bad.feed(try WireFrame.proof(Proof(signature: Data(count: 64), secretProof: Data(count: 32))).encode())
        await bad.waitForCancel()
        let openStatus = try await f.service.localStatus()
        XCTAssertEqual(openStatus.enrollment, .open)
        let good = try await f.handshake(invitation: invitation)
        try await f.prove(good, invitation: invitation)
        await good.waitForSend(2)
        await good.waitForRead(3)
        let presentation = await f.service.presentation()
        let candidate = try XCTUnwrap(presentation.candidate)
        try await f.service.confirmCandidate(candidateID: candidate.candidateID)
        let old = try await f.normal(invitation)
        let badNormal = try await f.handshake(invitation: invitation, normal: true)
        badNormal.feed(try WireFrame.proof(Proof(signature: Data(count: 64), secretProof: Data(count: 32))).encode())
        await badNormal.waitForCancel()
        XCTAssertFalse(old.cancelled)
        old.feed(try WireFrame.statusRequest.encode())
        await old.waitForSend(3)
        if case .statusResponse = try old.frame(2) {} else { XCTFail("working lease lost") }
        let delayed = try await f.handshake(invitation: invitation, normal: true)
        // Explicit owner queue barrier: enqueue before the valid proof is released.
        let blocked = XCTestExpectation(description: "owner queue blocked")
        let release = DispatchSemaphore(value: 0)
        f.queue.async { blocked.fulfill(); release.wait() }
        await fulfillment(of: [blocked], timeout: 5)
        try await f.prove(delayed, invitation: invitation, normal: true)
        f.clock.now.set(f.clock.now.get() + 10_000_000_000)
        release.signal()
        await delayed.waitForCancel()
        XCTAssertEqual(delayed.sent.count, 1)
        XCTAssertFalse(old.cancelled)
        await f.service.disable()
    }

    // Only type 0x10 after verified normal authentication may return a snapshot.
    func testStatusOnlyAllowlist() async throws {
        let f = try await HostFixture.open(); defer { f.remove() }
        let invitation = try await f.service.openEnrollment()
        let enrollment = try await f.handshake(invitation: invitation)
        enrollment.feed(try WireFrame.statusRequest.encode())
        await enrollment.waitForCancel()
        XCTAssertEqual(enrollment.sent.count, 1)
        for opcode: UInt8 in [0x20, 0x30, 0x40, 0xff] {
            let c = BridgeChannel(); f.listener.accept(c.channel)
            c.feed(Data([0,0,0,1,opcode]))
            await c.waitForCancel(); XCTAssertEqual(c.sent.count, 0)
        }
        await f.service.disable()
    }

    // The durable exact key survives a lost commit send and must reconnect normally.
    func testLostCommitAckUsesNormalAuth() async throws {
        let f = try await HostFixture.open(); defer { f.remove() }
        let invitation = try await f.service.openEnrollment()
        let c = try await f.handshake(invitation: invitation)
        try await f.prove(c, invitation: invitation)
        await c.waitForRead(3)
        let presentation = await f.service.presentation()
        let candidate = try XCTUnwrap(presentation.candidate)
        c.failNextSend.set(true)
        do { try await f.service.confirmCandidate(candidateID: candidate.candidateID); XCTFail("lost send succeeded") } catch {}
        let enrolledStatus = try await f.service.localStatus()
        XCTAssertEqual(enrolledStatus.controllerState, .enrolled)
        let normal = try await f.normal(invitation)
        normal.feed(try WireFrame.statusRequest.encode())
        await normal.waitForSend(3)
        if case .statusResponse(let response) = try normal.frame(2) { XCTAssertEqual(response.executionSupported, 0) }
        else { XCTFail("normal authentication failed") }
        let replay = try await f.handshake(invitation: invitation, expectChallenge: false)
        await replay.waitForCancel(); XCTAssertEqual(replay.sent.count, 0)
        await f.service.disable()
    }

    // Cancellation must happen before the queued durable revoke is allowed to run;
    // an unknown commit result cannot publish success or revive a late read.
    func testRevokeFailureAndLateDelivery() async throws {
        let f = try await HostFixture.open(); defer { f.remove() }
        let invitation = try await f.service.openEnrollment()
        let c = try await f.handshake(invitation: invitation)
        try await f.prove(c, invitation: invitation); await c.waitForRead(3)
        let presentation = await f.service.presentation()
        let candidate = try XCTUnwrap(presentation.candidate)
        try await f.service.confirmCandidate(candidateID: candidate.candidateID)
        let normal = try await f.normal(invitation)
        let blocked = XCTestExpectation(description: "status read inside owner blocked before revoke")
        let release = DispatchSemaphore(value: 0)
        f.native.onStep.set { sql in
            if sql.hasPrefix("SELECT") {
                f.native.onStep.set(nil)
                blocked.fulfill(); release.wait()
            }
        }
        normal.feed(try WireFrame.statusRequest.encode())
        await fulfillment(of: [blocked], timeout: 5)
        f.native.unknownCommit.set(true)
        let revoke = Task { try await f.service.revokeController() }
        await normal.waitForCancel()
        let late = BridgeChannel(); f.listener.accept(late.channel)
        XCTAssertTrue(late.cancelled)
        XCTAssertEqual(normal.sent.count, 2)
        release.signal()
        do { try await revoke.value; XCTFail("unknown commit succeeded") } catch {}
        let disabled = await f.service.presentation()
        XCTAssertFalse(disabled.isEnabled)
        await f.service.disable()
    }

    // A failed CandidateAccepted send still consumes the invitation; keeping its
    // text visible would offer a replay the owner can never accept.
    func testFailedCandidateSendClearsConsumedInvitation() async throws {
        let f = try await HostFixture.open(); defer { f.remove() }
        let invitation = try await f.service.openEnrollment()
        let c = try await f.handshake(invitation: invitation)
        c.failNextSend.set(true)
        try await f.prove(c, invitation: invitation)
        await c.waitForCancel()
        let state = await f.service.presentation()
        XCTAssertNil(state.invitation)
        XCTAssertNil(state.candidate)
        await f.service.disable()
    }

    // Core expiry must also remove local secret presentation without a peer.
    func testExpiredWindowPresentationClearsSecrets() async throws {
        let f = try await HostFixture.open(); defer { f.remove() }
        _ = try await f.service.openEnrollment()
        f.clock.now.set(f.clock.now.get() + 120_000_000_000)
        let state = await f.service.presentation()
        XCTAssertNil(state.invitation)
        XCTAssertNil(state.candidate)
        await f.service.disable()
    }

    // A listener retained outside its old enable must close late accepts even
    // after that runtime deallocates, and cannot alter a new listener's state.
    func testSupersededListenerCallbacksCannotRevive() async throws {
        let f = try await HostFixture.open(); defer { f.remove() }
        let oldAccept = try XCTUnwrap(f.listener.acceptBlock.get())
        let oldAvailability = try XCTUnwrap(f.listener.availability.get())
        await f.service.disable()
        try await f.service.enable(configuration: f.configuration, endpoint: f.endpoint)
        oldAvailability(false)
        let late = BridgeChannel()
        oldAccept(late.channel)
        XCTAssertTrue(late.cancelled)
        let state = await f.service.presentation()
        XCTAssertTrue(state.isEnabled)
        XCTAssertTrue(state.isListening)
        await f.service.disable()
    }

    // A second cancellation caller cannot return while a racing first caller
    // has only latched the bit but has not yet closed its resources.
    func testEveryDisableCallerSynchronouslyCancels() async throws {
        let fence = ServiceFence()
        let first = BridgeBox(true), closed = BridgeBox(false)
        let entered = XCTestExpectation(description: "first cancellation paused")
        let finished = XCTestExpectation(description: "first cancellation finished")
        let release = DispatchSemaphore(value: 0)
        fence.onDisable {
            if first.swap(false) { entered.fulfill(); release.wait() }
            closed.set(true)
        }
        DispatchQueue.global().async { fence.disable(); finished.fulfill() }
        await fulfillment(of: [entered], timeout: 5)
        fence.disable()
        XCTAssertTrue(closed.get())
        XCTAssertTrue(fence.isDisabled)
        release.signal()
        await fulfillment(of: [finished], timeout: 5)
    }

    // Revoking while enable is queued must latch that incarnation even before
    // owner publication, rather than allowing the late open to enable hosting.
    func testRevokeDuringQueuedEnableCannotPublishHosting() async throws {
        let gate = BridgeAsyncGate()
        let f = try await HostFixture.open(gate: gate); defer { f.remove() }
        await f.service.disable()
        await gate.hold()
        let enable = Task { try await f.service.enable(configuration: f.configuration, endpoint: f.endpoint) }
        await gate.waitForArrival()
        do { try await f.service.revokeController(); XCTFail("unpublished revoke succeeded") } catch {}
        await gate.release()
        do { try await enable.value; XCTFail("revoked enable published") } catch {}
        let state = await f.service.presentation()
        XCTAssertFalse(state.isEnabled)
        XCTAssertFalse(state.isListening)
        await f.service.disable()
    }

    // Publishing the comparison before CandidateAccepted finishes would permit
    // a second overlapping EnrollmentCommitted send on the bounded pump.
    func testCandidatePublicationWaitsForSendCompletion() async throws {
        let f = try await HostFixture.open(); defer { f.remove() }
        let invitation = try await f.service.openEnrollment()
        let c = try await f.handshake(invitation: invitation)
        c.holdNextSend.set(true)
        try await f.prove(c, invitation: invitation)
        await c.waitForSend(2)
        let waiting = await f.service.presentation()
        XCTAssertNil(waiting.candidate)
        do { try await f.service.confirmCandidate(candidateID: UUID()); XCTFail("premature confirm") }
        catch { XCTAssertEqual(error as? StatusHostError, .invalidCandidate) }
        c.releaseSend()
        await c.waitForRead(3)
        let ready = await f.service.presentation()
        XCTAssertEqual(ready.candidate?.comparisonCode.count, 8)
        await f.service.disable()
    }

    // Owner lease replacement must synchronously cancel the old channel before
    // Authenticated can be delivered on the new channel.
    func testNormalReplacementClosesOldBeforeAuthenticatedDelivery() async throws {
        let f = try await HostFixture.open(); defer { f.remove() }
        let invitation = try await f.service.openEnrollment()
        let enrollment = try await f.handshake(invitation: invitation)
        try await f.prove(enrollment, invitation: invitation); await enrollment.waitForRead(3)
        let presentation = await f.service.presentation()
        try await f.service.confirmCandidate(candidateID: XCTUnwrap(presentation.candidate).candidateID)
        let old = try await f.normal(invitation)
        let replacement = try await f.handshake(invitation: invitation, normal: true)
        replacement.holdNextSend.set(true)
        try await f.prove(replacement, invitation: invitation, normal: true)
        await replacement.waitForSend(2)
        XCTAssertTrue(old.cancelled)
        if case .authenticated = try replacement.frame(1) {} else { XCTFail("missing authentication") }
        replacement.releaseSend(); await replacement.waitForRead(3)
        await f.service.disable()
    }

    // The synchronous owner-unavailable callback must cancel before an awaited
    // read returns its retained failure, without releasing the ownership lock.
    func testStorageReadFailureDisablesAndRetainsOwner() async throws {
        let f = try await HostFixture.open(); defer { f.remove() }
        let c = BridgeChannel(); f.listener.accept(c.channel)
        await c.waitForRead(1)
        f.native.failNextRead.set(true)
        var first: String?
        do { _ = try await f.service.localStatus(); XCTFail("injected read succeeded") }
        catch { first = String(reflecting: error) }
        XCTAssertTrue(c.cancelled)
        let late = BridgeChannel(); f.listener.accept(late.channel); XCTAssertTrue(late.cancelled)
        do { _ = try await f.service.localStatus(); XCTFail("retained read succeeded") }
        catch { XCTAssertEqual(String(reflecting: error), first) }
        XCTAssertThrowsError(try JournalDirectoryLock(directory: f.directory))
        let state = await f.service.presentation()
        XCTAssertFalse(state.isEnabled)
        XCTAssertFalse(String(reflecting: state).contains("secret-storage-error"))
        await f.service.disable()
        _ = try JournalDirectoryLock(directory: f.directory)
    }

    // Disabled presentation is cancellation state and must be available while
    // the owner is blocked; it must never submit another status read to Core.
    func testDisabledPresentationDoesNotWaitForBlockedOwner() async throws {
        let f = try await HostFixture.open(); defer { f.remove() }
        let channel = BridgeChannel(); f.listener.accept(channel.channel)
        await channel.waitForRead(1)
        let entered = XCTestExpectation(description: "owner blocked")
        let release = DispatchSemaphore(value: 0)
        f.queue.async { entered.fulfill(); release.wait() }
        await fulfillment(of: [entered], timeout: 5)
        let revoke = Task { try await f.service.revokeController() }
        await channel.waitForCancel()
        let presented = XCTestExpectation(description: "disabled presentation available before owner release")
        let presentation = Task { let state = await f.service.presentation(); presented.fulfill(); return state }
        await fulfillment(of: [presented], timeout: 1)
        release.signal()
        _ = try? await revoke.value
        let state = await presentation.value
        XCTAssertFalse(state.isEnabled)
        await f.service.disable()
    }

    // A local status completion from a disabled incarnation cannot be used as
    // the current model's readiness snapshot after an awaited queue operation.
    func testDisableDiscardsLateLocalStatus() async throws {
        let f = try await HostFixture.open(); defer { f.remove() }
        let channel = BridgeChannel(); f.listener.accept(channel.channel)
        await channel.waitForRead(1)
        let entered = XCTestExpectation(description: "local status executing on owner")
        let release = DispatchSemaphore(value: 0)
        f.native.onStep.set { sql in
            if sql.hasPrefix("SELECT") { f.native.onStep.set(nil); entered.fulfill(); release.wait() }
        }
        let read = Task { try await f.service.localStatus() }
        await fulfillment(of: [entered], timeout: 5)
        let disable = Task { await f.service.disable() }
        await channel.waitForCancel()
        release.signal()
        do { _ = try await read.value; XCTFail("late disabled status published") }
        catch { XCTAssertEqual(error as? HostBridgeError, .disabled) }
        await disable.value
    }

    // Concurrent owner mint calls must not allow actor continuation ordering to
    // publish an older lease after a newer one. Busy overlap is refused locally
    // before Core, keeping the active authenticated channel intact.
    func testConcurrentProofCannotOvertakeOwnerTransition() async throws {
        let f = try await HostFixture.open(); defer { f.remove() }
        let invitation = try await f.service.openEnrollment()
        let enrollment = try await f.handshake(invitation: invitation)
        try await f.prove(enrollment, invitation: invitation); await enrollment.waitForRead(3)
        let presentation = await f.service.presentation()
        try await f.service.confirmCandidate(candidateID: XCTUnwrap(presentation.candidate).candidateID)
        let old = try await f.normal(invitation)
        let first = try await f.handshake(invitation: invitation, normal: true)
        let second = try await f.handshake(invitation: invitation, normal: true)
        let entered = XCTestExpectation(description: "first verified proof authenticating on owner")
        let refused = XCTestExpectation(description: "overlapping proof closed before owner release")
        let release = DispatchSemaphore(value: 0)
        f.native.onStep.set { sql in
            if sql.hasPrefix("SELECT") { f.native.onStep.set(nil); entered.fulfill(); release.wait() }
        }
        try await f.prove(first, invitation: invitation, normal: true)
        await fulfillment(of: [entered], timeout: 5)
        try await f.prove(second, invitation: invitation, normal: true)
        let observed = Task { await second.waitForCancel(); refused.fulfill() }
        await fulfillment(of: [refused], timeout: 1)
        XCTAssertFalse(old.cancelled)
        XCTAssertEqual(second.sent.count, 1)
        release.signal()
        await f.service.disable()
        await observed.value
    }

    // A late send continuation from expired W1 must neither clear W2 nor
    // publish W1's candidate after a successful fresh local enrollment open.
    func testExpiredCandidateCompletionPreservesUsableNewInvitation() async throws {
        let f = try await HostFixture.open(random: BridgeChangingRandom()); defer { f.remove() }
        let first = try await f.service.openEnrollment()
        let old = try await f.handshake(invitation: first)
        old.holdNextSend.set(true)
        try await f.prove(old, invitation: first)
        await old.waitForSend(2) // actual Core acceptance, before send completion
        f.clock.now.set(f.clock.now.get() + 120_000_000_000)
        let expired = try await f.service.localStatus()
        XCTAssertEqual(expired.enrollment, .closed)
        let fresh = try await f.service.openEnrollment()
        XCTAssertNotEqual(fresh.invitationID, first.invitationID)
        old.releaseSend()
        await old.waitForReadOrCancel(3) // proof dispatch finished or was refused
        let state = await f.service.presentation()
        XCTAssertEqual(state.invitation?.invitationID, fresh.invitationID)
        XCTAssertNil(state.candidate)
        let next = try await f.handshake(invitation: fresh)
        try await f.prove(next, invitation: fresh)
        await next.waitForReadOrCancel(3)
        XCTAssertEqual(next.sent.count, 2)
        if next.sent.count == 2 {
            if case .candidateAccepted = try next.frame(1) {} else { XCTFail("new invitation did not accept real proof") }
        }
        let accepted = await f.service.presentation()
        XCTAssertNotNil(accepted.candidate)
        await f.service.disable()
    }

    // Availability is sampled at return, after the held Core refresh, so a
    // known address loss cannot return an obsolete listening=true snapshot.
    func testPresentationResamplesAvailabilityAfterHeldCoreRead() async throws {
        let f = try await HostFixture.open(); defer { f.remove() }
        let entered = XCTestExpectation(description: "presentation Core read held")
        let release = DispatchSemaphore(value: 0)
        f.native.onStep.set { sql in
            if sql.hasPrefix("SELECT") { f.native.onStep.set(nil); entered.fulfill(); release.wait() }
        }
        let refresh = Task { await f.service.presentation() }
        await fulfillment(of: [entered], timeout: 5)
        f.listener.availability.get()?(false)
        release.signal()
        let state = await refresh.value
        XCTAssertTrue(state.isEnabled)
        XCTAssertFalse(state.isListening)
        await f.service.disable()
    }

    // Reflecting trusted presentation must not dump invitation/code or key bytes.
    func testDiagnosticRedaction() async throws {
        let f = try await HostFixture.open(); defer { f.remove() }
        let invitation = try await f.service.openEnrollment()
        let c = try await f.handshake(invitation: invitation)
        try await f.prove(c, invitation: invitation); await c.waitForRead(3)
        let state = await f.service.presentation()
        let code = try XCTUnwrap(state.candidate?.comparisonCode)
        let text = String(reflecting: state) + String(describing: state.candidate!)
        for secret in [try invitation.encode(), invitation.secret.base64EncodedString(), code,
                       f.spki.base64EncodedString(), Data(repeating: 9, count: 32).base64EncodedString()] {
            XCTAssertFalse(text.contains(secret))
        }
        await f.service.disable()
    }
}
#endif
