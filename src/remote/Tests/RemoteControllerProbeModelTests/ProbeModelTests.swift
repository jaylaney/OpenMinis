import XCTest
import CryptoKit
import Security
import RemotePrototypeWire
import RemotePrototypeTransport
@testable import RemoteControllerProbeModel

@MainActor final class ProbeModelTests: XCTestCase {
    // Break: synthesized descriptions expose the local comparison code or claim bytes.
    func testComparisonDescriptionsRedactSecrets() {
        let comparison = ProbeComparison(connectionID: UUID(), claimDigest: Data(repeating: 0xab, count: 32), code: "27182818")
        for text in [String(describing: comparison), String(reflecting: comparison)] {
            for secret in ["27182818", "abababab", "q6urq6ur", "171, 171"] {
                XCTAssertFalse(text.contains(secret))
            }
        }
    }
    // Break: generating a proof or receiving a foreign acceptance leaks a SAS before own acceptance.
    func testNoSASBeforeOwnAcceptedDigest() async throws {
        let fixture = try Fixture()
        defer { fixture.model.disconnect() }
        try fixture.model.enterInvitation(fixture.invitation.encode())
        XCTAssertNil(fixture.model.comparison)
        await fixture.model.connect()
        let channel = try XCTUnwrap(fixture.factory.channels.first)
        XCTAssertNil(fixture.model.comparison)
        let digest = try await fixture.sendChallenge(channel)
        XCTAssertNil(fixture.model.comparison)
        _ = try await channel.deliver(.candidateAccepted(try CandidateAccepted(claimDigest: digest, sasNonce: Data(repeating: 9, count: 32))))
        XCTAssertEqual(fixture.model.comparison?.claimDigest, digest)
        XCTAssertEqual(fixture.model.comparison?.connectionID, channel.connectionID)
        XCTAssertEqual(fixture.model.comparison?.code.count, 8)
        XCTAssertNil(fixture.pins.record)
        XCTAssertEqual(fixture.model.commandsAvailability, "Commands unavailable")
    }
    func testNoCodeForOtherClaimOrDisconnectedCandidate() async throws {
        let f = try Fixture()
        defer { f.model.disconnect() }
        try f.model.enterInvitation(f.invitation.encode())
        await f.model.connect()
        let channel = try XCTUnwrap(f.factory.channels.first)
        _ = try await f.sendChallenge(channel)
        await XCTAssertAsyncThrows { _ = try await channel.deliver(.candidateAccepted(try CandidateAccepted(claimDigest: Data(repeating: 0xff, count: 32), sasNonce: Data(repeating: 9, count: 32)))) }
        XCTAssertNil(f.model.comparison)
        XCTAssertNil(f.model.connectionID)
        await f.model.reconnect()
        let next = try XCTUnwrap(f.factory.channels.last)
        let digest = try await f.sendChallenge(next, normal: true)
        XCTAssertEqual(digest.count, 32)
        f.model.suspended()
        await XCTAssertAsyncThrows { _ = try await next.deliver(.authenticated(try Authenticated(controllerID: UUID(), generation: 1))) }
        XCTAssertNil(f.model.comparison)
        XCTAssertNotNil(f.model.errorMessage)
        let accepted = try Fixture()
        defer { accepted.model.disconnect() }
        try accepted.model.enterInvitation(accepted.invitation.encode())
        await accepted.model.connect()
        let acceptedChannel = try XCTUnwrap(accepted.factory.channels.first)
        let acceptedDigest = try await accepted.sendChallenge(acceptedChannel)
        _ = try await acceptedChannel.deliver(.candidateAccepted(try CandidateAccepted(claimDigest: acceptedDigest, sasNonce: Data(repeating: 9, count: 32))))
        XCTAssertNotNil(accepted.model.comparison)
        accepted.model.suspended()
        XCTAssertNil(accepted.model.comparison)
        XCTAssertNil(accepted.model.connectionID)
        XCTAssertNotNil(accepted.model.errorMessage)
    }
    // Break: callbacks publish after an explicit connection replacement.
    func testOldConnectionCannotUpdateScreen() async throws {
        let f = try Fixture(saved: true)
        defer { f.model.disconnect() }
        await f.model.connect()
        let old = try XCTUnwrap(f.factory.channels.first)
        _ = try await f.sendChallenge(old, normal: true)
        await f.model.reconnect()
        let current = try XCTUnwrap(f.factory.channels.last)
        await XCTAssertAsyncThrows { _ = try await old.deliver(.authenticated(try Authenticated(controllerID: UUID(), generation: 1))) }
        XCTAssertEqual(f.model.connectionID, current.connectionID)
        XCTAssertNil(f.model.storageEpoch)
        _ = try await f.sendChallenge(current, normal: true)
        _ = try await current.deliver(.authenticated(try Authenticated(controllerID: current.controllerID, generation: 1)))
        let epoch = UUID()
        _ = try await current.deliver(.statusResponse(try StatusResponse(storageEpoch: epoch)))
        XCTAssertEqual(f.model.storageEpoch, epoch)
    }
    // Break: Forget awaits deletion or lets delayed auth restore the pin/key.
    func testForgetFencesDelayedAuthentication() async throws {
        let f = try Fixture(saved: true)
        defer { f.model.disconnect() }
        await f.model.connect()
        let old = try XCTUnwrap(f.factory.channels.first)
        _ = try await f.sendChallenge(old, normal: true)
        var observedFenced = false
        f.pins.onDelete = { observedFenced = f.model.connectionID == nil && old.cancelled && f.model.comparison == nil }
        try f.model.forgetPairing()
        XCTAssertTrue(observedFenced)
        XCTAssertNil(f.pins.record)
        await XCTAssertAsyncThrows { _ = try await old.deliver(.authenticated(try Authenticated(controllerID: UUID(), generation: 1))) }
        XCTAssertNil(f.pins.record)
        XCTAssertEqual(f.identity.point, f.originalPoint)
        XCTAssertEqual(f.factory.channels.count, 1)
        f.pins.record = try f.record()
        f.pins.deleteError = TestError.failed
        XCTAssertThrowsError(try f.model.forgetPairing())
        XCTAssertNotNil(f.pins.record)
        XCTAssertNotNil(f.model.errorMessage)
        XCTAssertNil(f.model.connectionID)
    }
    // Break: lost ACK discards the tentative pin/key, or normal auth replays enrollment.
    func testLostAckKeepsTentativePinAndSameKey() async throws {
        let f = try Fixture()
        defer { f.model.disconnect() }
        try f.model.enterInvitation(f.invitation.encode())
        await f.model.connect()
        let first = try XCTUnwrap(f.factory.channels.first)
        let digest = try await f.sendChallenge(first)
        _ = try await first.deliver(.candidateAccepted(try CandidateAccepted(claimDigest: digest, sasNonce: Data(repeating: 9, count: 32))))
        f.model.disconnect(reason: "Connection lost before acknowledgment")
        XCTAssertNil(f.pins.record)
        try f.model.editEndpoint(ipv4: "100.64.0.2", port: 49153)
        await f.model.reconnect()
        let second = try XCTUnwrap(f.factory.channels.last)
        guard case .hello(let hello) = try XCTUnwrap(second.sent.first) else { return XCTFail("Missing hello") }
        XCTAssertEqual(hello.mode, .normal)
        XCTAssertEqual(hello.hostID, f.invitation.hostID)
        XCTAssertEqual(hello.hostPin, f.invitation.hostPin)
        XCTAssertEqual(hello.controllerPoint, f.originalPoint)
        XCTAssertEqual(f.factory.endpoints.last?.ipv4, "100.64.0.2")
        _ = try await f.sendChallenge(second, normal: true)
        _ = try await second.deliver(.authenticated(try Authenticated(controllerID: second.controllerID, generation: 1)))
        XCTAssertEqual(f.pins.record?.hostID, f.invitation.hostID)
        XCTAssertEqual(f.pins.record?.endpoint.ipv4, "100.64.0.2")
        XCTAssertEqual(f.identity.point, f.originalPoint)
        XCTAssertEqual(f.model.commandsAvailability, "Commands unavailable")
    }
    func testNormalAuthenticationMatchesChallengeAndCommitIsSingleUse() async throws {
        let normal = try Fixture(saved: true)
        defer { normal.model.disconnect() }
        await normal.model.connect()
        let channel = try XCTUnwrap(normal.factory.channels.first)
        _ = try await normal.sendChallenge(channel, normal: true)
        await XCTAssertAsyncThrows { _ = try await channel.deliver(.authenticated(try Authenticated(controllerID: UUID(), generation: 1))) }
        XCTAssertNil(normal.model.connectionID)
        let enrollment = try Fixture()
        defer { enrollment.model.disconnect() }
        try enrollment.model.enterInvitation(enrollment.invitation.encode())
        await enrollment.model.connect()
        let candidate = try XCTUnwrap(enrollment.factory.channels.first)
        let digest = try await enrollment.sendChallenge(candidate)
        _ = try await candidate.deliver(.candidateAccepted(try CandidateAccepted(claimDigest: digest, sasNonce: Data(repeating: 9, count: 32))))
        let commit = WireFrame.enrollmentCommitted(try EnrollmentCommitted(claimDigest: digest, controllerID: UUID(), generation: 1))
        _ = try await candidate.deliver(commit)
        XCTAssertNil(enrollment.pins.record)
        await XCTAssertAsyncThrows { _ = try await candidate.deliver(commit) }
    }
    func testPinReadFailureCannotBeTreatedAsFreshPairing() async throws {
        let identity = try MemoryIdentity(), pins = MemoryPins(), factory = MemoryFactory()
        pins.loadError = TestError.failed
        let model = ProbeModel(identity: identity, pins: pins, channels: factory, nonce: { Data(repeating: 6, count: 32) })
        let invitation = try Invitation(endpoint: StatusEndpoint(ipv4: "100.64.0.1", port: 49152), hostID: UUID(), hostPin: Data(repeating: 3, count: 32), invitationID: UUID(), secret: Data(repeating: 4, count: 32))
        XCTAssertThrowsError(try model.enterInvitation(invitation.encode()))
        XCTAssertFalse(model.hasPairing)
        await model.connect()
        XCTAssertTrue(factory.endpoints.isEmpty)
        XCTAssertEqual(identity.pointRequests, 0)
        XCTAssertNotNil(model.errorMessage)
    }
    func testForgetCancelsPendingConnectAndDiscardsLateReadyChannel() async throws {
        let f = try Fixture(saved: true)
        defer { f.model.disconnect() }
        f.factory.holdConnect = true
        let connect = Task { await f.model.connect() }
        await f.factory.waitForPendingConnect()
        try f.model.forgetPairing()
        XCTAssertTrue(f.factory.connectCancelled.value)
        let late = MemoryChannel()
        f.factory.pending?.resume(returning: late); f.factory.pending = nil
        await connect.value
        XCTAssertTrue(late.cancelled)
        XCTAssertNil(f.model.connectionID)
        XCTAssertNil(f.pins.record)
    }
    // Break: the production adapter creates/replaces a missing key for a saved pairing.
    func testProductionStoreSavedPairingWithMissingKeyDoesNotCreate() async throws {
        let backend = MemoryProbeStoreBackend()
        backend.record = try PairedHostRecord(hostID: UUID(), hostPin: Data(repeating: 5, count: 32), endpoint: StatusEndpoint(ipv4: "100.64.0.1", port: 49152))
        let saved = backend.record
        let adapter = ProductionProbeStore(backend: backend)
        let factory = MemoryFactory()
        let model = ProbeModel(identity: adapter, pins: adapter, channels: factory, nonce: { Data(repeating: 6, count: 32) })
        defer { model.disconnect() }
        await model.connect()
        await model.reconnect()
        XCTAssertNil(backend.key)
        XCTAssertEqual(backend.creations, 0)
        XCTAssertTrue(factory.endpoints.isEmpty)
        XCTAssertNil(model.connectionID)
        XCTAssertNil(model.comparison)
        XCTAssertTrue(model.errorMessage?.contains("missingIdentity") == true)
        XCTAssertEqual(backend.record, saved)
    }
    // Break: fresh explicit enrollment works, but lost-ACK normal retry can mint a replacement.
    func testProductionStoreFreshEnrollmentAndLostAckUseSameLoadedKey() async throws {
        let backend = MemoryProbeStoreBackend(), factory = MemoryFactory()
        let adapter = ProductionProbeStore(backend: backend)
        let model = ProbeModel(identity: adapter, pins: adapter, channels: factory, nonce: { Data(repeating: 6, count: 32) })
        defer { model.disconnect() }
        let invitation = try Invitation(endpoint: StatusEndpoint(ipv4: "100.64.0.1", port: 49152), hostID: UUID(), hostPin: Data(repeating: 3, count: 32), invitationID: UUID(), secret: Data(repeating: 4, count: 32))
        try model.enterInvitation(invitation.encode())
        await model.connect()
        guard case .hello(let first) = try XCTUnwrap(factory.channels.first?.sent.first) else { return XCTFail("Missing enrollment hello") }
        XCTAssertEqual(first.mode, .enrollment)
        let firstChannel = try XCTUnwrap(factory.channels.first)
        let firstDigest = try await verifiedProductionProof(channel: firstChannel, hello: first, secret: invitation.secret)
        _ = try await firstChannel.deliver(.candidateAccepted(try CandidateAccepted(claimDigest: firstDigest, sasNonce: Data(repeating: 9, count: 32))))
        XCTAssertNotNil(model.comparison)
        XCTAssertEqual(backend.creations, 1)
        XCTAssertNil(backend.record)
        model.disconnect(reason: "Lost enrollment ACK")
        await model.reconnect()
        guard case .hello(let retry) = try XCTUnwrap(factory.channels.last?.sent.first) else { return XCTFail("Missing normal hello") }
        XCTAssertEqual(retry.mode, .normal)
        XCTAssertEqual(retry.controllerPoint, first.controllerPoint)
        _ = try await verifiedProductionProof(channel: XCTUnwrap(factory.channels.last), hello: retry, secret: nil)
        XCTAssertEqual(backend.creations, 1)
        let count = factory.endpoints.count
        model.disconnect()
        backend.key = nil
        await model.reconnect()
        XCTAssertNil(backend.key)
        XCTAssertEqual(backend.creations, 1)
        XCTAssertEqual(factory.endpoints.count, count)
        XCTAssertNil(model.connectionID)
        XCTAssertTrue(model.errorMessage?.contains("missingIdentity") == true)
    }
    // Break: an unprepared proof path creates a key before rejecting the transcript.
    func testProductionStoreProofCannotCreateIdentity() throws {
        let backend = MemoryProbeStoreBackend()
        let adapter = ProductionProbeStore(backend: backend)
        let point = try MemoryIdentity().point
        let hello = try Hello(mode: .normal, hostID: UUID(), hostPin: Data(repeating: 3, count: 32), controllerPoint: point, clientNonce: Data(repeating: 6, count: 32), invitationID: .zero)
        let transcript = try AuthTranscript(hello: hello, challenge: Challenge(serverNonce: Data(repeating: 7, count: 32), controllerID: UUID(), generation: 1))
        XCTAssertThrowsError(try adapter.proof(transcript: transcript, exporter: Data(repeating: 8, count: 32), secret: nil))
        XCTAssertNil(backend.key)
        XCTAssertEqual(backend.creations, 0)
    }
    private func verifiedProductionProof(channel: MemoryChannel, hello: Hello, secret: Data?) async throws -> Data {
        let challenge = try Challenge(serverNonce: Data(repeating: 7, count: 32), controllerID: secret == nil ? UUID() : .zero, generation: secret == nil ? 1 : 0)
        guard case .proof(let proof) = try await channel.deliver(.challenge(challenge)) else { throw TestError.failed }
        let transcript = try AuthTranscript(hello: hello, challenge: challenge)
        let exporter = Data(repeating: 8, count: 32)
        try PeerAuthentication.verify(transcript: transcript, exporter: exporter, proof: proof, invitationSecret: secret)
        return try transcript.claimDigest(exporter: exporter, signature: proof.signature, secretProof: proof.secretProof)
    }
    func testExistingPinNeverOverwrittenAndConnectFailureExplicit() async throws {
        let f = try Fixture(saved: true)
        defer { f.model.disconnect() }
        let previous = f.pins.record
        XCTAssertThrowsError(try f.model.enterInvitation(f.invitation.encode()))
        XCTAssertEqual(f.pins.record, previous)
        f.factory.failure = TestError.failed
        await f.model.connect()
        XCTAssertNil(f.model.connectionID)
        XCTAssertNotNil(f.model.errorMessage)
        XCTAssertEqual(f.factory.endpoints.count, 1)
        XCTAssertEqual(f.pins.record, previous)
    }
}

@MainActor private struct Fixture {
    let identity: MemoryIdentity
    let originalPoint: Data
    let pins: MemoryPins
    let factory: MemoryFactory
    let invitation: Invitation
    let model: ProbeModel
    init(saved: Bool = false) throws {
        identity = try MemoryIdentity(); originalPoint = identity.point
        pins = MemoryPins(); factory = MemoryFactory()
        invitation = try Invitation(endpoint: StatusEndpoint(ipv4: "100.64.0.1", port: 49152), hostID: UUID(), hostPin: Data(repeating: 3, count: 32), invitationID: UUID(), secret: Data(repeating: 4, count: 32))
        if saved { pins.record = try PairedHostRecord(hostID: UUID(), hostPin: Data(repeating: 5, count: 32), endpoint: invitation.endpoint) }
        model = ProbeModel(identity: identity, pins: pins, channels: factory, nonce: { Data(repeating: 6, count: 32) })
    }
    func record() throws -> PairedHostRecord { try PairedHostRecord(hostID: invitation.hostID, hostPin: invitation.hostPin, endpoint: invitation.endpoint) }
    func sendChallenge(_ channel: MemoryChannel, normal: Bool = false) async throws -> Data {
        guard case .hello(let hello) = try XCTUnwrap(channel.sent.first) else { throw TestError.failed }
        channel.controllerID = normal ? UUID() : .zero
        let challenge = try Challenge(serverNonce: Data(repeating: 7, count: 32), controllerID: channel.controllerID, generation: normal ? 1 : 0)
        let result = try await channel.deliver(.challenge(challenge))
        guard case .proof(let proof) = result else { throw TestError.failed }
        let transcript = try AuthTranscript(hello: hello, challenge: challenge)
        try PeerAuthentication.verify(transcript: transcript, exporter: Data(repeating: 8, count: 32), proof: proof, invitationSecret: normal ? nil : invitation.secret)
        return try transcript.claimDigest(exporter: Data(repeating: 8, count: 32), signature: proof.signature, secretProof: proof.secretProof)
    }
}
private enum TestError: Error { case failed }
@MainActor private final class MemoryIdentity: ProbeIdentity {
    let key: SecKey
    let point: Data
    var pointRequests = 0
    init() throws {
        key = SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256, kSecAttrIsPermanent: false] as CFDictionary, nil)!
        point = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(key)!, nil)! as Data
    }
    func prepareIdentity(allowCreation: Bool) throws -> Data { pointRequests += 1; return point }
    func proof(transcript: AuthTranscript, exporter: Data, secret: Data?) throws -> Proof { try PeerAuthentication.makeProof(transcript: transcript, exporter: exporter, key: key, invitationSecret: secret) }
}
@MainActor private final class MemoryPins: ProbePinStore {
    var record: PairedHostRecord?
    var loadError: Error?
    var deleteError: Error?
    var onDelete: (() -> Void)?
    func load() throws -> PairedHostRecord? { if let loadError { throw loadError }; return record }
    func save(_ value: PairedHostRecord) throws { record = value }
    func forget() throws { onDelete?(); if let deleteError { throw deleteError }; record = nil }
}
@MainActor private final class MemoryFactory: ProbeChannelFactory {
    var channels: [MemoryChannel] = []
    var endpoints: [StatusEndpoint] = []
    var failure: Error?
    var holdConnect = false
    let connectCancelled = CancellationFlag()
    var pending: CheckedContinuation<any ProbeChannel, Never>?
    var pendingObserved: CheckedContinuation<Void, Never>?
    func waitForPendingConnect() async {
        if pending != nil { return }
        await withCheckedContinuation { pendingObserved = $0 }
    }
    func connect(endpoint: StatusEndpoint, pin: Data) async throws -> any ProbeChannel {
        endpoints.append(endpoint)
        if let failure { throw failure }
        if holdConnect {
            return await withTaskCancellationHandler {
                await withCheckedContinuation { pending = $0; pendingObserved?.resume(); pendingObserved = nil }
            } onCancel: { [connectCancelled] in connectCancelled.cancel() }
        }
        let channel = MemoryChannel(); channels.append(channel); return channel
    }
}
@MainActor private final class MemoryChannel: ProbeChannel {
    let connectionID = UUID()
    var cancelled = false
    var controllerID = UUID.zero
    var finished: CheckedContinuation<Void, Never>?
    var dispatchObserved: CheckedContinuation<Void, Never>?
    var sent: [WireFrame] = []
    var dispatch: (@MainActor @Sendable (WireFrame, UUID) async throws -> WireFrame?)?
    func exporter(context: Data) throws -> Data { Data(repeating: 8, count: 32) }
    func send(_ frame: WireFrame) async throws { sent.append(frame) }
    func run(dispatch: @escaping @MainActor @Sendable (WireFrame, UUID) async throws -> WireFrame?) async throws {
        self.dispatch = dispatch
        dispatchObserved?.resume(); dispatchObserved = nil
        if cancelled { return }
        await withCheckedContinuation { finished = $0 }
    }
    func cancel() { cancelled = true; finished?.resume(); finished = nil }
    func deliver(_ frame: WireFrame) async throws -> WireFrame? {
        // The model starts its serial receive loop after awaiting Hello send.
        if dispatch == nil { await withCheckedContinuation { dispatchObserved = $0 } }
        return try await XCTUnwrap(dispatch)(frame, connectionID)
    }
}
@MainActor private func XCTAssertAsyncThrows(_ body: () async throws -> Void, file: StaticString = #filePath, line: UInt = #line) async {
    do { try await body(); XCTFail("Expected refusal", file: file, line: line) } catch {}
}

private final class CancellationFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    var value: Bool { lock.withLock { cancelled } }
    func cancel() { lock.withLock { cancelled = true } }
}

@MainActor private final class MemoryProbeStoreBackend: ProbeStoreBackend {
    var key: SecKey?
    var record: PairedHostRecord?
    var creations = 0
    func loadControllerIdentity() throws -> SecKey? { key }
    func createControllerIdentityIfAbsent() throws -> SecKey {
        if let key { return key }
        creations += 1
        let created = try MemoryIdentity().key
        key = created; return created
    }
    func loadPairedHost() throws -> PairedHostRecord? { record }
    func savePairedHost(_ record: PairedHostRecord) throws { self.record = record }
    func forgetPairedHost() throws { record = nil }
}
