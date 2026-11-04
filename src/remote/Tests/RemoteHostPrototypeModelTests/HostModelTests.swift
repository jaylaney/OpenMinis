import XCTest
import RemotePrototypeWire
@testable import RemotePrototypeHost
import RemotePrototypeTransport
import Combine
import RemoteExecutionCore
import CryptoKit
@testable import RemoteHostPrototypeModel

@MainActor final class HostModelTests: XCTestCase {
    // Break: offline enrolled policy cannot be revoked, or refresh opens owners.
    func testExplicitLocalLoadAllowsOfflineRevokeAndClose() async throws {
        let service = FakeHostService()
        service.state = "enrolled"
        let model = HostModel(service: service, directory: URL(fileURLWithPath: "/unused"))
        await model.refresh()
        XCTAssertEqual(service.localLoadCount, 0)
        XCTAssertFalse(model.canRevoke)
        await model.loadLocalPolicy()
        XCTAssertEqual(service.localLoadCount, 1)
        XCTAssertFalse(model.isEnabled)
        XCTAssertTrue(model.hasOpenOwner)
        XCTAssertTrue(model.canClose)
        XCTAssertTrue(model.canRevoke)
        await model.revoke()
        XCTAssertEqual(model.controllerState, "revoked")
        XCTAssertTrue(model.canClose)
        await model.disable()
        XCTAssertFalse(model.hasOpenOwner)
        XCTAssertFalse(model.canClose)
    }
    // Break: nonclosed owner phase with no displayed secret permits a second open.
    func testEnrollmentGateUsesOwnerPhaseIncludingHeldCandidateSend() async throws {
        let service = FakeHostService()
        let ticks = PresentationTicks()
        let model = HostModel(service: service, directory: URL(fileURLWithPath: "/unused"), presentationRefreshWait: { await ticks.wait() })
        await model.enable(endpoint: try endpoint())
        XCTAssertTrue(model.canEnroll)
        await model.openEnrollment()
        XCTAssertFalse(model.canEnroll)
        await model.openEnrollment()
        XCTAssertEqual(service.openEnrollmentCount, 1)
        service.invitation = nil
        service.enrollmentOverride = .candidate
        await model.refresh()
        XCTAssertNil(model.candidate)
        XCTAssertFalse(model.canEnroll)
        await settlePresentationTasks()
        XCTAssertEqual(ticks.pendingCount, 1)
        let before = service.presentationCount
        ticks.fireNext()
        await settlePresentationTasks()
        XCTAssertEqual(service.presentationCount, before + 1)
        await model.openEnrollment()
        XCTAssertEqual(service.openEnrollmentCount, 1)
        service.candidate = HostCandidatePresentation(candidateID: UUID(), comparisonCode: "12345678")
        await model.refresh()
        XCTAssertNotNil(model.candidate)
        XCTAssertFalse(model.canEnroll)
        service.candidate = nil
        service.enrollmentOverride = .closed
        await model.refresh()
        XCTAssertTrue(model.canEnroll)
        await model.disable()
        ticks.fireAll()
    }
    // Break: a known commit is lost when its following readiness refresh fails.
    func testCommittedNoticeSurvivesReadinessFailure() async throws {
        let service = FakeHostService()
        let model = HostModel(service: service, directory: URL(fileURLWithPath: "/unused"))
        await model.enable(endpoint: try endpoint())
        service.candidate = HostCandidatePresentation(candidateID: UUID(), comparisonCode: "12345678")
        await model.refresh()
        service.failReadinessAfterConfirm = true
        await model.confirm()
        XCTAssertNotNil(model.committedNotice)
        XCTAssertNotNil(model.errorMessage)
        XCTAssertTrue(model.canClose)
        XCTAssertFalse(model.isEnabled)
        await model.disable()
    }

    // Break: without an availability callback, Enable failure never refreshes
    // its retained resource state, hiding Close and the original readiness error.
    func testEnableErrorRefreshesRetainedOwnerAndReadiness() async throws {
        let service = FakeHostService()
        service.enableError = FixtureError.unavailable
        service.statusError = FixtureError.unavailable
        let model = HostModel(service: service, directory: URL(fileURLWithPath: "/unused"))
        await model.enable(endpoint: try endpoint())
        XCTAssertFalse(model.isEnabled)
        XCTAssertFalse(model.isListening)
        XCTAssertFalse(model.isBusy)
        XCTAssertTrue(model.hasOpenOwner)
        XCTAssertTrue(model.canClose)
        XCTAssertTrue(model.errorMessage?.contains("Hosting readiness unavailable") == true)
        XCTAssertFalse(model.canEnroll)
        XCTAssertFalse(model.canRevoke)
        await model.disable()
        XCTAssertFalse(model.hasOpenOwner)
        XCTAssertFalse(model.canClose)
    }

    // Preserve operation guards when an Enable-error resource read completes
    // after explicit Close. Its stale retained-owner snapshot cannot restore UI.
    func testCloseDiscardsHeldEnableErrorResourceRefresh() async throws {
        let service = FakeHostService()
        service.enableError = FixtureError.unavailable
        service.statusError = FixtureError.unavailable
        service.holdNextPresentation = true
        let model = HostModel(service: service, directory: URL(fileURLWithPath: "/unused"))
        let enabling = Task { await model.enable(endpoint: try endpoint()) }
        await service.waitForHeldPresentation()
        await model.disable()
        service.releasePresentation()
        try await enabling.value
        XCTAssertFalse(model.isEnabled)
        XCTAssertFalse(model.isBusy)
        XCTAssertFalse(model.hasOpenOwner)
        XCTAssertFalse(model.canClose)
        XCTAssertNil(model.errorMessage)
    }

    // Break: launch/window lifecycle implicitly enables or stops hosting.
    func testLaunchDisabledAndWindowCloseKeepsHosting() async throws {
        let service = FakeHostService()
        let model = HostModel(service: service, directory: URL(fileURLWithPath: "/unused"))
        XCTAssertFalse(model.isEnabled)
        XCTAssertEqual(model.commandsAvailability, "Commands unavailable")
        await model.enable(endpoint: try endpoint())
        XCTAssertTrue(model.isEnabled)
        model.windowClosed()
        XCTAssertTrue(model.isEnabled)
        await model.disable()
        XCTAssertFalse(model.isEnabled)
        await model.enable(endpoint: try endpoint())
        await model.quit()
        XCTAssertFalse(model.isEnabled)
    }
    // Break: an unenrolled local slot exposes Revoke, or stale presentation re-enables UI.
    func testUnenrolledRevokeControlDisabled() async throws {
        let service = FakeHostService()
        let model = HostModel(service: service, directory: URL(fileURLWithPath: "/unused"))
        XCTAssertFalse(model.canRevoke)
        await model.enable(endpoint: try endpoint())
        XCTAssertFalse(model.canRevoke)
        service.state = "enrolled"
        await model.refresh()
        XCTAssertTrue(model.canRevoke)
        await model.revoke()
        XCTAssertFalse(model.canRevoke)
        XCTAssertFalse(model.isEnabled)
    }
    func testAvailabilityLossClearsSecretsAndStaleRefreshIsIgnored() async throws {
        let service = FakeHostService()
        let model = HostModel(service: service, directory: URL(fileURLWithPath: "/unused"))
        await model.enable(endpoint: try endpoint())
        await model.openEnrollment()
        XCTAssertNotNil(model.invitationText)
        service.listening = false
        await model.refresh()
        XCTAssertFalse(model.isListening)
        XCTAssertNotNil(model.errorMessage)
        service.listening = true
        await model.refresh()
        XCTAssertTrue(model.isListening)
        XCTAssertNil(model.errorMessage)
        service.holdNextPresentation = true
        let refresh = Task { await model.refresh() }
        await service.waitForHeldPresentation()
        await model.disable()
        service.releasePresentation()
        await refresh.value
        XCTAssertFalse(model.isEnabled)
        XCTAssertNil(model.invitationText)
        XCTAssertEqual(model.commandsAvailability, "Commands unavailable")
    }
    func testReadinessFailureIsVisibleAndClearsPresentation() async throws {
        for showCandidate in [false, true] {
            let service = FakeHostService()
            let model = HostModel(service: service, directory: URL(fileURLWithPath: "/unused"))
            await model.enable(endpoint: try endpoint())
            await model.openEnrollment()
            if showCandidate {
                service.invitation = nil
                service.candidate = HostCandidatePresentation(candidateID: UUID(), comparisonCode: "12345678")
            }
            await model.refresh()
            XCTAssertTrue(model.isEnabled)
            XCTAssertTrue(model.isListening)
            XCTAssertEqual(model.invitationText != nil, !showCandidate)
            XCTAssertEqual(model.candidate != nil, showCandidate)
            // Presentation stays enabled/listening with a secret; the following state read fails.
            service.statusError = FixtureError.unavailable
            await model.refresh()
            XCTAssertFalse(model.isEnabled)
            XCTAssertFalse(model.isListening)
            XCTAssertNil(model.invitationText)
            XCTAssertNil(model.candidate)
            XCTAssertNotNil(model.errorMessage)
            XCTAssertFalse(model.canEnroll)
            XCTAssertFalse(model.canRevoke)
            XCTAssertTrue(model.hasOpenOwner)
            XCTAssertTrue(model.canClose)
            XCTAssertEqual(model.commandsAvailability, "Commands unavailable")
        }
    }
    func testFreshInstallationSelection() async throws {
        let root = URL(fileURLWithPath: "/injected/Application Support", isDirectory: true)
        XCTAssertNil(try PrototypeInstallationSelection.parse(arguments: []))
        XCTAssertEqual(PrototypeInstallationSelection.resolve(applicationSupport: root, installationID: nil).path,
                       "/injected/Application Support/OpenMinisPrototype/installations/default")
        let text = "12345678-1234-4234-8234-123456789abc"
        let id = try XCTUnwrap(PrototypeInstallationSelection.parse(arguments: ["--prototype-installation", text]))
        XCTAssertEqual(PrototypeInstallationSelection.resolve(applicationSupport: root, installationID: id).lastPathComponent, text)
        for args in [["--prototype-installation"], ["--prototype-installation", text, "--prototype-installation", text],
                     ["--prototype-installation", text.uppercased()], ["--prototype-installation", "00000000-0000-0000-0000-000000000000"],
                     ["--prototype-installation", "../escape"], ["--prototype-installation=\(text)"]] {
            XCTAssertThrowsError(try PrototypeInstallationSelection.parse(arguments: args), "\(args)")
        }
        // Exercise the selected directories with the real owner, using no Keychain.
        let fixtureRoot = FileManager.default.temporaryDirectory.appendingPathComponent("task12-installations-\(UUID())")
        try FileManager.default.createDirectory(at: fixtureRoot, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: fixtureRoot) }
        let selectedOld = PrototypeInstallationSelection.resolve(applicationSupport: fixtureRoot, installationID: nil)
        let selectedNew = PrototypeInstallationSelection.resolve(applicationSupport: fixtureRoot, installationID: id)
        let launch = try HostModel.production(applicationSupport: fixtureRoot, arguments: [])
        XCTAssertFalse(launch.isEnabled)
        XCTAssertFalse(FileManager.default.fileExists(atPath: selectedOld.deletingLastPathComponent().path))
        try PrototypeInstallationSelection.provisionParents(of: selectedOld)
        XCTAssertFalse(FileManager.default.fileExists(atPath: selectedOld.path))
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: selectedOld.deletingLastPathComponent().path)[.posixPermissions] as? NSNumber, NSNumber(value: 0o700))
        let key = P256.Signing.PrivateKey()
        let spki = key.publicKey.derRepresentation
        let keyBefore = key.rawRepresentation
        func config(_ directory: URL) -> StatusOnlyHostConfiguration {
            StatusOnlyHostConfiguration(directory: directory, clock: FixtureClock(), random: FixtureRandom(), identityResolver: { pin in
                if let pin, pin != Data(SHA256.hash(data: spki)) { throw StatusHostError.identityMismatch }
                return spki
            }, onUnavailable: {})
        }
        let old = try await StatusOnlyHost.open(configuration: config(selectedOld))
        let window = try await old.host.openEnrollment()
        let context = try await old.host.beginHandshake(StatusHandshakeInput(connectionID: UUID(), acceptedAtNanoseconds: 1, mode: .enrollment,
            hostID: window.hostID, hostPin: window.hostPin, controllerSPKI: P256.Signing.PrivateKey().publicKey.derRepresentation,
            clientNonce: Data(repeating: 3, count: 32), invitationID: window.invitationID))
        let candidate = try await old.host.acceptCandidate(contextID: context.contextID, claimDigest: Data(repeating: 4, count: 32))
        try await old.host.confirmCandidate(candidateID: candidate.candidateID)
        try await old.host.revokeController()
        let oldSnapshot = try await old.host.localStatus()
        await old.host.close()
        let oldBytes = try Data(contentsOf: selectedOld.appendingPathComponent("admission.sqlite3"))
        let oldLock = try FileManager.default.attributesOfItem(atPath: selectedOld.appendingPathComponent("admission.lock").path)[.systemFileNumber] as? NSNumber
        let fresh = try await StatusOnlyHost.open(configuration: config(selectedNew))
        let freshSnapshot = try await fresh.host.localStatus()
        XCTAssertNotEqual(freshSnapshot.snapshot.hostID, oldSnapshot.snapshot.hostID)
        XCTAssertNotEqual(freshSnapshot.snapshot.storageEpoch, oldSnapshot.snapshot.storageEpoch)
        XCTAssertEqual(freshSnapshot.controllerState, .unenrolled)
        let freshWindow = try await fresh.host.openEnrollment()
        XCTAssertEqual(freshWindow.hostPin, window.hostPin)
        await fresh.host.close()
        XCTAssertEqual(try Data(contentsOf: selectedOld.appendingPathComponent("admission.sqlite3")), oldBytes)
        XCTAssertEqual(key.rawRepresentation, keyBefore)
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: selectedOld.appendingPathComponent("admission.lock").path)[.systemFileNumber] as? NSNumber, oldLock)
        let reopened = try await StatusOnlyHost.open(configuration: config(selectedOld))
        let unchanged = try await reopened.host.localStatus()
        XCTAssertEqual(unchanged.controllerState, .revoked)
        XCTAssertEqual(unchanged.snapshot, oldSnapshot.snapshot)
        await reopened.host.close()
    }
    // Break: idle presentation never asks Core to observe an expired window.
    func testIdleInvitationExpiresAutomaticallyFromOwner() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("idle-enrollment-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let clock = MutableEnrollmentClock()
        let service = OwnerHostService(clock: clock)
        let ticks = PresentationTicks()
        let model = HostModel(service: service, directory: directory, presentationRefreshWait: { await ticks.wait() })
        await model.enable(endpoint: try endpoint())
        await model.openEnrollment()
        XCTAssertNotNil(model.invitationText)
        let cleared = expectation(description: "Owner expiry removes the idle invitation")
        let observation = model.$invitationText.dropFirst().filter { $0 == nil }.prefix(1).sink { _ in cleared.fulfill() }
        // Advance the actual owner clock; no model refresh or owner read follows.
        clock.advanceToExpiry()
        await settlePresentationTasks()
        ticks.fireNext()
        await fulfillment(of: [cleared], timeout: 2)
        XCTAssertTrue(model.invitationText == nil)
        XCTAssertTrue(model.isEnabled)
        XCTAssertTrue(model.isListening)
        observation.cancel()
        await model.disable()
        ticks.fireAll()
    }
    // Break: each presentation read adds a poller, or slow polling overlaps itself.
    func testPresentationPollingIsBoundedAndStopsWhenSecretsDisappear() async throws {
        let service = FakeHostService()
        let ticks = PresentationTicks()
        let model = HostModel(service: service, directory: URL(fileURLWithPath: "/unused"), presentationRefreshWait: { await ticks.wait() })
        await model.enable(endpoint: try endpoint())
        await settlePresentationTasks()
        XCTAssertEqual(ticks.pendingCount, 0)
        await model.openEnrollment()
        await settlePresentationTasks()
        for _ in 0..<5 { await model.refresh() }
        XCTAssertEqual(ticks.requestCount, 1)
        XCTAssertEqual(ticks.pendingCount, 1)
        service.holdNextPresentation = true
        let before = service.presentationCount
        ticks.fireNext()
        await settlePresentationTasks()
        XCTAssertTrue(service.held != nil)
        service.holdNextPresentation = false
        for _ in 0..<5 { ticks.fireNext() }
        await settlePresentationTasks()
        XCTAssertEqual(service.presentationCount, before + 1)
        XCTAssertEqual(ticks.pendingCount, 0)
        service.releasePresentation()
        await settlePresentationTasks()
        XCTAssertEqual(ticks.pendingCount, 1)
        XCTAssertNotNil(model.invitationText)
        // The owner/service presentation, rather than a model deadline, removes it.
        service.invitation = nil
        ticks.fireNext()
        await settlePresentationTasks()
        XCTAssertTrue(model.invitationText == nil)
        XCTAssertTrue(model.isEnabled)
        XCTAssertEqual(ticks.pendingCount, 0)
        let after = service.presentationCount
        ticks.fireAll()
        await settlePresentationTasks()
        XCTAssertEqual(service.presentationCount, after)
        await model.disable()
    }

    // Break: a cancelled timer wakes into disabled hosting or a later incarnation.
    func testLatePresentationWakeCannotReadAfterDisableOrReplaceNewWindow() async throws {
        let service = FakeHostService()
        let ticks = PresentationTicks()
        let model = HostModel(service: service, directory: URL(fileURLWithPath: "/unused"), presentationRefreshWait: { await ticks.wait() })
        await model.enable(endpoint: try endpoint())
        await model.openEnrollment()
        await settlePresentationTasks()
        await model.disable()
        let disabledReads = service.presentationCount
        ticks.fireNext()
        await settlePresentationTasks()
        XCTAssertEqual(service.presentationCount, disabledReads)
        XCTAssertFalse(model.isEnabled)
        XCTAssertTrue(model.invitationText == nil)
        await model.enable(endpoint: try endpoint())
        await model.openEnrollment()
        await settlePresentationTasks()
        await model.disable()
        await model.enable(endpoint: try endpoint())
        await model.openEnrollment()
        await settlePresentationTasks()
        let newest = try XCTUnwrap(model.invitationText)
        let replacementReads = service.presentationCount
        XCTAssertEqual(ticks.pendingCount, 2) // one deliberately late cancelled wait
        ticks.fireNext()
        await settlePresentationTasks()
        XCTAssertEqual(service.presentationCount, replacementReads)
        XCTAssertTrue(model.invitationText == newest)
        XCTAssertEqual(ticks.pendingCount, 1)
        ticks.fireNext()
        await settlePresentationTasks()
        XCTAssertTrue(model.invitationText == newest)
        XCTAssertTrue(model.isEnabled)
        XCTAssertEqual(ticks.pendingCount, 1)
        await model.disable()
        ticks.fireAll()
        await settlePresentationTasks()
    }

    // Break: an old in-flight automatic read clears a replacement window or timer.
    func testLateAutomaticPresentationCannotClearReplacementWindow() async throws {
        let service = FakeHostService()
        let ticks = PresentationTicks()
        let model = HostModel(service: service, directory: URL(fileURLWithPath: "/unused"), presentationRefreshWait: { await ticks.wait() })
        await model.enable(endpoint: try endpoint())
        await model.openEnrollment()
        await settlePresentationTasks()
        service.invitation = nil
        service.holdNextPresentation = true
        ticks.fireNext()
        await settlePresentationTasks()
        XCTAssertTrue(service.held != nil)
        service.holdNextPresentation = false
        await model.disable()
        await model.enable(endpoint: try endpoint())
        await model.openEnrollment()
        await settlePresentationTasks()
        let newest = try XCTUnwrap(model.invitationText)
        service.releasePresentation()
        await settlePresentationTasks()
        XCTAssertTrue(model.invitationText == newest)
        XCTAssertTrue(model.isEnabled)
        XCTAssertEqual(ticks.pendingCount, 1)
        ticks.fireNext()
        await settlePresentationTasks()
        XCTAssertTrue(model.invitationText == newest)
        XCTAssertEqual(ticks.pendingCount, 1)
        await model.disable()
        ticks.fireAll()
        await settlePresentationTasks()
    }

    // Break: the model-owned polling task keeps its model alive across idle waits.
    func testIdlePresentationWaitDoesNotRetainModel() async throws {
        let service = FakeHostService()
        let ticks = PresentationTicks()
        var model: HostModel? = HostModel(service: service, directory: URL(fileURLWithPath: "/unused"), presentationRefreshWait: { await ticks.wait() })
        let remainingModel = { [weak model] in model }
        await model?.enable(endpoint: try endpoint())
        await model?.openEnrollment()
        await settlePresentationTasks()
        XCTAssertEqual(ticks.pendingCount, 1)
        let before = service.presentationCount
        model = nil
        XCTAssertNil(remainingModel())
        ticks.fireAll()
        await settlePresentationTasks()
        XCTAssertEqual(service.presentationCount, before)
        XCTAssertEqual(ticks.pendingCount, 0)
        await service.disable()
    }

    private func settlePresentationTasks() async {
        // Fake reads and ticks remain on MainActor; no policy time or real timer passes.
        for _ in 0..<100 { await Task.yield() }
    }
    private func endpoint() throws -> StatusEndpoint { try StatusEndpoint(ipv4: "100.64.0.1", port: 49152) }
}

@MainActor private final class FakeHostService: HostModelService {
    var enabled = false
    var owned = false
    var localLoadCount = 0
    var openEnrollmentCount = 0
    var enrollmentOverride: StatusEnrollmentState?
    var failReadinessAfterConfirm = false
    var enableError: Error?
    var listening = true
    var state = "unenrolled"
    var statusError: Error?
    var invitation: Invitation?
    var candidate: HostCandidatePresentation?
    var holdNextPresentation = false
    var held: CheckedContinuation<HostPresentation, Never>?
    var observed: CheckedContinuation<Void, Never>?
    private var heldValue: HostPresentation?
    private(set) var presentationCount = 0
    func openLocalPolicy(directory: URL) async throws { localLoadCount += 1; owned = true }
    func enable(directory: URL, endpoint: StatusEndpoint) async throws {
        owned = true
        if let enableError { enabled = false; listening = false; throw enableError }
        enabled = true; listening = true
    }
    func disable() async { owned = false; enabled = false; invitation = nil; candidate = nil }
    func revoke() async throws { state = "revoked"; enabled = false }
    func controllerState() async throws -> String { if let statusError { throw statusError }; return state }
    func openEnrollment() async throws {
        openEnrollmentCount += 1
        invitation = try Invitation(endpoint: StatusEndpoint(ipv4: "100.64.0.1", port: 49152), hostID: UUID(), hostPin: Data(repeating: 1, count: 32), invitationID: UUID(), secret: Data(repeating: 2, count: 32))
    }
    func confirm(candidateID: UUID) async throws -> HostConfirmationOutcome {
        state = "enrolled"; candidate = nil
        if failReadinessAfterConfirm { statusError = FixtureError.unavailable }
        return .committed(acknowledgementSent: false)
    }
    func reject(candidateID: UUID) async throws {}
    func presentation() async -> HostPresentation {
        presentationCount += 1
        let value = HostPresentation(isEnabled: enabled, isListening: enabled && listening, invitation: invitation, candidate: candidate,
            hasOpenOwner: owned, enrollment: enrollmentOverride ?? (candidate != nil ? .candidate : invitation != nil ? .open : .closed))
        if holdNextPresentation {
            holdNextPresentation = false
            heldValue = value
            return await withCheckedContinuation { held = $0; observed?.resume(); observed = nil }
        }
        return value
    }
    func waitForHeldPresentation() async { if held != nil { return }; await withCheckedContinuation { observed = $0 } }
    func releasePresentation() {
        if let heldValue { held?.resume(returning: heldValue) }
        held = nil; heldValue = nil
    }
}

private struct FixtureClock: StatusClock { func nowNanoseconds() -> UInt64 { 1 } }
private struct FixtureRandom: StatusRandomSource {
    func bytes(count: Int) throws -> Data { Data((0..<count).map { _ in UInt8.random(in: 0...255) }) }
}

private enum FixtureError: Error { case unavailable }

// The tick only schedules a presentation read; it has no policy time or deadline.
@MainActor private final class PresentationTicks {
    private var waits: [CheckedContinuation<Void, Never>] = []
    private(set) var requestCount = 0
    var pendingCount: Int { waits.count }
    func wait() async {
        requestCount += 1
        // Deliberately allow a cancelled waiter to wake late for incarnation tests.
        await withCheckedContinuation { waits.append($0) }
    }
    func fireNext() { if !waits.isEmpty { waits.removeFirst().resume() } }
    func fireAll() { while !waits.isEmpty { fireNext() } }
}

private final class MutableEnrollmentClock: StatusClock, @unchecked Sendable {
    private let lock = NSLock()
    private var now: UInt64 = 1
    func nowNanoseconds() -> UInt64 { lock.withLock { now } }
    func advanceToExpiry() { lock.withLock { now = 120_000_000_001 } }
}

// Real Core and dispatcher; only listener, Keychain and signing IO are omitted.
@MainActor private final class OwnerHostService: HostModelService {
    let clock: MutableEnrollmentClock
    private var handles: StatusOnlyHostHandles?
    private var dispatcher: HostRPCDispatcher?
    private var fence: ServiceFence?
    init(clock: MutableEnrollmentClock) { self.clock = clock }
    func openLocalPolicy(directory: URL) async throws { throw FixtureError.unavailable }
    func enable(directory: URL, endpoint: StatusEndpoint) async throws {
        let spki = P256.Signing.PrivateKey().publicKey.derRepresentation
        let handles = try await StatusOnlyHost.open(configuration: StatusOnlyHostConfiguration(directory: directory,
            clock: clock, random: FixtureRandom(), identityResolver: { _ in spki }, onUnavailable: {}))
        let fence = ServiceFence()
        self.handles = handles; self.fence = fence
        dispatcher = HostRPCDispatcher(handles: handles, fence: fence, pump: ConnectionPump(role: .host), endpoint: endpoint, onChange: {})
    }
    func disable() async {
        fence?.disable()
        if let dispatcher { await dispatcher.clear() }
        if let handles { await handles.host.close() }
        dispatcher = nil; handles = nil; fence = nil
    }
    func revoke() async throws { try await handles?.host.revokeController() }
    func controllerState() async throws -> String { try await handles?.host.localStatus().controllerState.rawValue ?? "unknown" }
    func openEnrollment() async throws { _ = try await dispatcher?.openEnrollment() }
    func confirm(candidateID: UUID) async throws -> HostConfirmationOutcome {
        guard let dispatcher else { throw FixtureError.unavailable }
        return try await dispatcher.confirmCandidate(candidateID: candidateID)
    }
    func reject(candidateID: UUID) async throws { try await dispatcher?.rejectCandidate(candidateID: candidateID) }
    func presentation() async -> HostPresentation {
        await dispatcher?.presentation(listening: true) ?? HostPresentation(isEnabled: false, isListening: false, invitation: nil, candidate: nil)
    }
}
