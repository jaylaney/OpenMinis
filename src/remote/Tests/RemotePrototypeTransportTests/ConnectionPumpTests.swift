import Foundation
import CryptoKit
import XCTest
import RemotePrototypeWire
@testable import RemotePrototypeTransport

final class ConnectionPumpTests: XCTestCase, @unchecked Sendable {
    // Removing candidate accounting would admit the third socket before confirmation.
    func testTwoPendingIncludesCandidate() async throws {
        let timer = PumpTestTimer()
        let pump = ConnectionPump(role: .host, now: { timer.now }, timers: timer)
        let a = PumpTestChannel(), b = PumpTestChannel(), c = PumpTestChannel()
        try pump.accept(a.channel); try pump.accept(b.channel)
        a.feed(try WireFrame.hello(hello(.enrollment)).encode())
        let run = Task { try await pump.run(connectionID: a.id) { frame, id in
            switch frame {
            case .hello: return .challenge(try challenge(.enrollment))
            case .proof:
                try pump.retainCandidate(connectionID: id, untilNanoseconds: 120_000_000_000)
                return .candidateAccepted(try candidate())
            default: throw PumpTestError.unexpected
            }
        } }
        await a.waitForSend(count: 1)
        a.feed(try proof().encode())
        await a.waitForRead(count: 3)
        XCTAssertThrowsError(try pump.accept(c.channel))
        XCTAssertTrue(c.cancelled)
        // Proof completion must stop the auth timer, but leave the candidate slot occupied.
        timer.advance(to: 10_000_000_000)
        XCTAssertFalse(a.cancelled)
        XCTAssertThrowsError(try pump.accept(PumpTestChannel().channel))
        try await pump.send(.enrollmentCommitted(try committed()), over: a.id)
        try pump.accept(PumpTestChannel(acceptedAt: timer.now).channel)
        pump.closeAll(); _ = try? await run.value
    }

    // Losing trusted acceptance time, equality checks, or cancellation would leave these live.
    func testDeadlinesAndBackpressure() async throws {
        let timer = PumpTestTimer()
        let pump = ConnectionPump(role: .host, now: { timer.now }, timers: timer)
        let accepted = PumpTestChannel(acceptedAt: 0)
        timer.advance(to: 9_999_999_999)
        try pump.accept(accepted.channel)
        timer.advance(to: 10_000_000_000)
        XCTAssertTrue(accepted.cancelled)
        let expired = PumpTestChannel(acceptedAt: 0)
        XCTAssertThrowsError(try pump.accept(expired.channel))
        XCTAssertTrue(expired.cancelled)
        let overflow = PumpTestChannel(acceptedAt: UInt64.max - 1)
        XCTAssertThrowsError(try pump.accept(overflow.channel))
        XCTAssertTrue(overflow.cancelled)

        let slow = PumpTestChannel(acceptedAt: timer.now, blocksSends: true)
        let controller = ConnectionPump(role: .controller, now: { timer.now }, timers: timer)
        try controller.accept(slow.channel)
        let send = Task { try await controller.send(.hello(try hello(.normal)), over: slow.id) }
        await slow.waitForSend(count: 1)
        do { try await controller.send(.hello(try hello(.normal)), over: slow.id); XCTFail("second queued send") } catch {}
        XCTAssertTrue(slow.cancelled) // second send is a protocol/resource violation
        _ = try? await send.value

        let slow2 = PumpTestChannel(acceptedAt: timer.now, blocksSends: true)
        try controller.accept(slow2.channel)
        let send2 = Task { try await controller.send(.hello(try hello(.normal)), over: slow2.id) }
        await slow2.waitForSend(count: 1)
        timer.advance(to: 20_000_000_000)
        XCTAssertTrue(slow2.cancelled)
        do { try await send2.value; XCTFail("send escaped deadline") } catch {}

        // Malformed size and unknown type fail before dispatch. No buffer request exceeds 4100.
        for bytes in [Data([0,0,16,1]), Data([0,0,0,1,0x99]), try WireFrame.statusRequest.encode()] {
            let peer = PumpTestChannel(acceptedAt: timer.now)
            try pump.accept(peer.channel); peer.feed(bytes)
            do { try await pump.run(connectionID: peer.id) { _, _ in XCTFail("invalid frame dispatched"); return nil }; XCTFail("invalid frame accepted") } catch {}
            XCTAssertTrue(peer.cancelled)
            XCTAssertTrue(peer.readSizes.allSatisfy { (1...4100).contains($0) })
        }
        pump.closeAll(); controller.closeAll()
    }

    // Predecoding both frames under the old state rejects a valid coalesced server completion.
    func testCoalescedServerTransitions() async throws {
        let timer = PumpTestTimer()
        let pump = ConnectionPump(role: .controller, now: { timer.now }, timers: timer)
        let peer = PumpTestChannel(); try pump.accept(peer.channel)
        try await pump.send(.hello(try hello(.enrollment)), over: peer.id)
        peer.feed(try WireFrame.challenge(challenge(.enrollment)).encode())
        let seen = PumpTestFrames()
        let run = Task { try await pump.run(connectionID: peer.id) { frame, _ in
            await seen.append(frame)
            if case .challenge = frame { return try proof() }
            return nil
        } }
        await peer.waitForSend(count: 2)
        peer.feed(try WireFrame.candidateAccepted(candidate()).encode() + WireFrame.enrollmentCommitted(committed()).encode())
        try await run.value
        let frames = await seen.frames
        XCTAssertEqual(frames.count, 3)
        XCTAssertEqual(frames[1], try .candidateAccepted(candidate()))
        XCTAssertEqual(frames[2], try .enrollmentCommitted(committed()))
        XCTAssertTrue(peer.cancelled)
    }

    // Cancellation during an awaited owner job must discard its eventual response.
    func testDisconnectDiscardsLateResponse() async throws {
        let timer = PumpTestTimer()
        let pump = ConnectionPump(role: .host, now: { timer.now }, timers: timer)
        let peer = PumpTestChannel(); try pump.accept(peer.channel)
        let gate = PumpTestGate()
        peer.feed(try WireFrame.hello(hello(.normal)).encode())
        let run = Task { try await pump.run(connectionID: peer.id) { _, _ in
            await gate.arriveAndWait()
            return .challenge(try challenge(.normal))
        } }
        await gate.waitForArrival()
        pump.close(connectionID: peer.id)
        await gate.release()
        _ = try? await run.value
        XCTAssertEqual(peer.sent.count, 0)
        XCTAssertTrue(peer.cancelled)
    }

    // Awaiting the first response must not legalize an already-buffered second client RPC.
    func testPipelinedClientRequestClosesBeforeDispatch() async throws {
        let timer = PumpTestTimer()
        let pump = ConnectionPump(role: .host, now: { timer.now }, timers: timer)
        let peer = PumpTestChannel(); try pump.accept(peer.channel)
        peer.feed(try WireFrame.hello(hello(.normal)).encode())
        let seen = PumpTestFrames()
        let run = Task { try await pump.run(connectionID: peer.id) { frame, _ in
            await seen.append(frame)
            switch frame {
            case .hello: return .challenge(try challenge(.normal))
            case .proof: return .authenticated(try Authenticated(controllerID: pumpID, generation: 1))
            case .statusRequest: return .statusResponse(try StatusResponse(storageEpoch: pumpID))
            default: throw PumpTestError.unexpected
            }
        } }
        await peer.waitForSend(count: 1)
        peer.feed(try proof().encode())
        await peer.waitForRead(count: 3)
        // Authenticated peers no longer consume the pending socket budget.
        try pump.accept(PumpTestChannel().channel); try pump.accept(PumpTestChannel().channel)
        peer.feed(try WireFrame.statusRequest.encode() + WireFrame.statusRequest.encode())
        do { try await run.value; XCTFail("pipelining accepted") } catch {}
        XCTAssertTrue(peer.cancelled)
        let frames = await seen.frames
        XCTAssertEqual(frames.count, 2)
        pump.closeAll()
    }

    // A server cannot pre-send the result before a controller proof; only
    // transitions with no intervening client message may consume a coalesced suffix.
    func testServerCannotPreemptProofWithCoalescedResult() async throws {
        let timer = PumpTestTimer()
        let pump = ConnectionPump(role: .controller, now: { timer.now }, timers: timer)
        let peer = PumpTestChannel(); try pump.accept(peer.channel)
        try await pump.send(.hello(try hello(.normal)), over: peer.id)
        peer.feed(try WireFrame.challenge(challenge(.normal)).encode() + WireFrame.authenticated(Authenticated(controllerID: pumpID, generation: 1)).encode())
        do { try await pump.run(connectionID: peer.id) { frame, _ in
            if case .challenge = frame { return try proof() }
            XCTFail("premature result dispatched"); pump.close(connectionID: peer.id); return nil
        }; XCTFail("premature result accepted") } catch {}
        XCTAssertTrue(peer.cancelled)
    }

    // A snapshot already delivered with Authenticated cannot answer a request
    // created later by dispatching that authentication frame.
    func testAuthenticatedCannotPreemptStatusRequestWithCoalescedSnapshot() async throws {
        let timer = PumpTestTimer()
        let pump = ConnectionPump(role: .controller, now: { timer.now }, timers: timer)
        let peer = PumpTestChannel(); try pump.accept(peer.channel)
        try await pump.send(.hello(try hello(.normal)), over: peer.id)
        peer.feed(try WireFrame.challenge(challenge(.normal)).encode())
        let seen = PumpTestFrames()
        let run = Task { try await pump.run(connectionID: peer.id) { frame, _ in
            switch frame {
            case .challenge: return try proof()
            case .authenticated: return .statusRequest
            case .statusResponse:
                await seen.append(frame)
                XCTFail("unsolicited snapshot dispatched")
                pump.close(connectionID: peer.id); return nil
            default: throw PumpTestError.unexpected
            }
        } }
        await peer.waitForRead(count: 2)
        peer.feed(try WireFrame.authenticated(Authenticated(controllerID: pumpID, generation: 1)).encode() + WireFrame.statusResponse(StatusResponse(storageEpoch: pumpID)).encode())
        do { try await run.value; XCTFail("preemptive snapshot accepted") } catch {}
        let snapshots = await seen.frames
        XCTAssertEqual(snapshots.count, 0)
        XCTAssertTrue(peer.cancelled)
    }

    // A second snapshot already in the same receive cannot answer a next request
    // created later by dispatching the first snapshot.
    func testStatusResponseCannotPreemptNextRequestWithCoalescedSnapshot() async throws {
        let timer = PumpTestTimer()
        let pump = ConnectionPump(role: .controller, now: { timer.now }, timers: timer)
        let peer = PumpTestChannel(); try pump.accept(peer.channel)
        try await pump.send(.hello(try hello(.normal)), over: peer.id)
        peer.feed(try WireFrame.challenge(challenge(.normal)).encode())
        let seen = PumpTestFrames()
        let run = Task { try await pump.run(connectionID: peer.id) { frame, _ in
            switch frame {
            case .challenge: return try proof()
            case .authenticated: return .statusRequest
            case .statusResponse:
                await seen.append(frame)
                let snapshots = await seen.frames
                if snapshots.count > 1 {
                    XCTFail("unsolicited second snapshot dispatched")
                    pump.close(connectionID: peer.id); return nil
                }
                return .statusRequest
            default: throw PumpTestError.unexpected
            }
        } }
        await peer.waitForRead(count: 2)
        peer.feed(try WireFrame.authenticated(Authenticated(controllerID: pumpID, generation: 1)).encode())
        await peer.waitForRead(count: 3)
        let snapshot = try WireFrame.statusResponse(StatusResponse(storageEpoch: pumpID)).encode()
        peer.feed(snapshot + snapshot)
        do { try await run.value; XCTFail("preemptive next snapshot accepted") } catch {}
        let snapshots = await seen.frames
        XCTAssertLessThanOrEqual(snapshots.count, 1)
        XCTAssertTrue(peer.cancelled)
    }

    // A client refusal is a wrong-direction frame and must never reach host dispatch.
    func testWrongDirectionRefusalIsRejected() async throws {
        let timer = PumpTestTimer()
        let pump = ConnectionPump(role: .host, now: { timer.now }, timers: timer)
        let peer = PumpTestChannel(); try pump.accept(peer.channel)
        peer.feed(try WireFrame.refused(Refused(reason: .generic)).encode())
        do { try await pump.run(connectionID: peer.id) { _, _ in XCTFail("client refusal dispatched"); return nil }; XCTFail("client refusal accepted") } catch {}
        XCTAssertTrue(peer.cancelled)
    }

    // Send timeout must still apply after the authentication deadline is removed.
    func testSendDeadlineStartsAtSendAfterAuthentication() async throws {
        let timer = PumpTestTimer()
        let pump = ConnectionPump(role: .host, now: { timer.now }, timers: timer)
        let peer = PumpTestChannel(); try pump.accept(peer.channel)
        peer.feed(try WireFrame.hello(hello(.normal)).encode())
        let run = Task { try await pump.run(connectionID: peer.id) { frame, _ in
            switch frame {
            case .hello: return .challenge(try challenge(.normal))
            case .proof: return .authenticated(try Authenticated(controllerID: pumpID, generation: 1))
            case .statusRequest: return .statusResponse(try StatusResponse(storageEpoch: pumpID))
            default: throw PumpTestError.unexpected
            }
        } }
        await peer.waitForRead(count: 2); peer.feed(try proof().encode())
        await peer.waitForRead(count: 3)
        timer.advance(to: 25_000_000_000)
        XCTAssertFalse(peer.cancelled)
        peer.blockSends()
        peer.feed(try WireFrame.statusRequest.encode())
        await peer.waitForSend(count: 3)
        timer.advance(to: 34_999_999_999); XCTAssertFalse(peer.cancelled)
        timer.advance(to: 35_000_000_000); XCTAssertTrue(peer.cancelled)
        do { try await run.value; XCTFail("slow reader survived") } catch {}
    }

    // Fragmented hostile bodies must consume only the remaining single-frame budget.
    func testPartialFrameReadBudgetIsBounded() async throws {
        let timer = PumpTestTimer()
        let pump = ConnectionPump(role: .host, now: { timer.now }, timers: timer)
        let peer = PumpTestChannel(); try pump.accept(peer.channel)
        peer.feed(Data([0]))
        let run = Task { try await pump.run(connectionID: peer.id) { _, _ in XCTFail("invalid body dispatched"); return nil } }
        await peer.waitForRead(count: 2)
        peer.feed(Data([0, 16, 0]) + Data(repeating: 0x99, count: 4096))
        do { try await run.value; XCTFail("unknown max-size body accepted") } catch {}
        XCTAssertEqual(peer.readSizes, [4100, 4099])
        XCTAssertTrue(peer.cancelled)
    }

    // A delayed trusted owner result cannot revive auth, even if a timer callback is delayed.
    func testCandidateHandoffCannotReviveExpiredProof() async throws {
        let timer = PumpTestTimer()
        let pump = ConnectionPump(role: .host, now: { timer.now }, timers: timer)
        let peer = PumpTestChannel(); try pump.accept(peer.channel)
        peer.feed(try WireFrame.hello(hello(.enrollment)).encode())
        let gate = PumpTestGate()
        let run = Task { try await pump.run(connectionID: peer.id) { frame, id in
            if case .hello = frame { return .challenge(try challenge(.enrollment)) }
            await gate.arriveAndWait()
            try pump.retainCandidate(connectionID: id, untilNanoseconds: 120_000_000_000)
            return .candidateAccepted(try candidate())
        } }
        await peer.waitForRead(count: 2); peer.feed(try proof().encode())
        await gate.waitForArrival()
        timer.setTimeWithoutFiring(10_000_000_000)
        await gate.release()
        do { try await run.value; XCTFail("expired proof revived") } catch {}
        XCTAssertTrue(peer.cancelled)
        XCTAssertEqual(peer.sent.count, 1)
    }

    // Generic wire decoding permits placeholders; the pump must validate them using the fixed mode.
    func testModeAwareChallengeAndProof() async throws {
        let timer = PumpTestTimer()
        let controller = ConnectionPump(role: .controller, now: { timer.now }, timers: timer)
        let peer = PumpTestChannel(); try controller.accept(peer.channel)
        try await controller.send(.hello(try hello(.normal)), over: peer.id)
        peer.feed(try WireFrame.challenge(challenge(.enrollment)).encode())
        do { try await controller.run(connectionID: peer.id) { _, _ in XCTFail("wrong mode dispatched"); return nil }; XCTFail("wrong challenge") } catch {}
        let host = ConnectionPump(role: .host, now: { timer.now }, timers: timer)
        let p = PumpTestChannel(); try host.accept(p.channel)
        p.feed(try WireFrame.hello(hello(.normal)).encode())
        let run = Task { try await host.run(connectionID: p.id) { frame, _ in
            if case .hello = frame { return .challenge(try challenge(.normal)) }
            XCTFail("wrong proof dispatched"); return nil
        } }
        await p.waitForSend(count: 1)
        p.feed(try WireFrame.proof(Proof(signature: Data(count: 64), secretProof: Data(repeating: 1, count: 32))).encode())
        do { try await run.value; XCTFail("wrong proof") } catch {}
        XCTAssertTrue(p.cancelled)
    }
}

private let pumpID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
private func hello(_ mode: HandshakeMode) throws -> Hello {
    try Hello(mode: mode, hostID: pumpID, hostPin: Data(count: 32), controllerPoint: P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32)).publicKey.x963Representation, clientNonce: Data(count: 32), invitationID: mode == .normal ? .zero : pumpID)
}
private func challenge(_ mode: HandshakeMode) throws -> Challenge { try Challenge(serverNonce: Data(count: 32), controllerID: mode == .enrollment ? .zero : pumpID, generation: mode == .enrollment ? 0 : 1) }
private func proof() throws -> WireFrame { .proof(try Proof(signature: Data(count: 64), secretProof: Data(count: 32))) }
private func candidate() throws -> CandidateAccepted { try CandidateAccepted(claimDigest: Data(count: 32), sasNonce: Data(count: 32)) }
private func committed() throws -> EnrollmentCommitted { try EnrollmentCommitted(claimDigest: Data(count: 32), controllerID: pumpID, generation: 1) }
private enum PumpTestError: Error { case unexpected, closed }
private actor PumpTestFrames { var frames: [WireFrame] = []; func append(_ frame: WireFrame) { frames.append(frame) } }
private actor PumpTestGate {
    private var arrived = false
    private var arrival: CheckedContinuation<Void, Never>?
    private var completion: CheckedContinuation<Void, Never>?
    func arriveAndWait() async { arrived = true; arrival?.resume(); arrival = nil; await withCheckedContinuation { completion = $0 } }
    func waitForArrival() async { if !arrived { await withCheckedContinuation { arrival = $0 } } }
    func release() { completion?.resume(); completion = nil }
}

private final class PumpTestTimer: ConnectionPumpTimers, @unchecked Sendable {
    private let lock = NSLock()
    private var time: UInt64 = 0
    private var jobs: [(UInt64, PumpTestTimerToken, @Sendable () -> Void)] = []
    var now: UInt64 { lock.withLock { time } }
    func schedule(deadlineNanoseconds: UInt64, _ action: @escaping @Sendable () -> Void) -> any ConnectionPumpTimer {
        let token = PumpTestTimerToken()
        lock.withLock { jobs.append((deadlineNanoseconds, token, action)) }
        return token
    }
    func setTimeWithoutFiring(_ value: UInt64) { lock.withLock { time = value } }
    func advance(to value: UInt64) {
        let ready = lock.withLock { time = value; let ready = jobs.filter { $0.0 <= value }; jobs.removeAll { $0.0 <= value }; return ready }
        for job in ready where !job.1.cancelled { job.2() }
    }
}
private final class PumpTestTimerToken: ConnectionPumpTimer, @unchecked Sendable {
    private let lock = NSLock(); private var stopped = false
    var cancelled: Bool { lock.withLock { stopped } }
    func cancel() { lock.withLock { stopped = true } }
}
private final class PumpTestChannel: StatusTLSChannelBackend, @unchecked Sendable {
    let id = UUID()
    let acceptedAt: UInt64
    private var blocksSends: Bool
    private let lock = NSLock()
    private var chunks: [Data] = []
    private var read: CheckedContinuation<Data, Error>?
    private var write: CheckedContinuation<Void, Error>?
    private var writes: [Data] = []
    private var sizes: [Int] = []
    private var stopped = false
    private var observers: [(Int, CheckedContinuation<Void, Never>)] = []
    private var readObservers: [(Int, CheckedContinuation<Void, Never>)] = []
    init(acceptedAt: UInt64 = 0, blocksSends: Bool = false) { self.acceptedAt = acceptedAt; self.blocksSends = blocksSends }
    func blockSends() { lock.withLock { blocksSends = true } }
    var channel: StatusTLSChannel { StatusTLSChannel(connectionID: id, acceptedAtNanoseconds: acceptedAt, backend: self) }
    var cancelled: Bool { lock.withLock { stopped } }
    var sent: [Data] { lock.withLock { writes } }
    var readSizes: [Int] { lock.withLock { sizes } }
    func ready() async throws { if cancelled { throw PumpTestError.closed } }
    func receive(maximumBytes: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            lock.withLock {
                sizes.append(maximumBytes)
                let ready = readObservers.filter { $0.0 <= sizes.count }; readObservers.removeAll { $0.0 <= sizes.count }
                for observer in ready { observer.1.resume() }
                if stopped { continuation.resume(throwing: PumpTestError.closed) }
                else if !chunks.isEmpty {
                    let chunk = chunks.removeFirst(); let prefix = Data(chunk.prefix(maximumBytes)); let suffix = Data(chunk.dropFirst(maximumBytes))
                    if !suffix.isEmpty { chunks.insert(suffix, at: 0) }; continuation.resume(returning: prefix)
                } else { read = continuation }
            }
        }
    }
    func feed(_ data: Data) {
        lock.withLock {
            if let read { self.read = nil; let maximum = sizes.last!; let suffix = Data(data.dropFirst(maximum)); if !suffix.isEmpty { chunks.append(suffix) }; read.resume(returning: Data(data.prefix(maximum))) }
            else { chunks.append(data) }
        }
    }
    func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            lock.withLock {
                if stopped { continuation.resume(throwing: PumpTestError.closed); return }
                writes.append(data)
                let ready = observers.filter { $0.0 <= writes.count }; observers.removeAll { $0.0 <= writes.count }
                if blocksSends { write = continuation } else { continuation.resume() }
                for observer in ready { observer.1.resume() }
            }
        }
    }
    func waitForSend(count: Int) async {
        await withCheckedContinuation { continuation in lock.withLock { if writes.count >= count { continuation.resume() } else { observers.append((count, continuation)) } } }
    }
    func waitForRead(count: Int) async {
        await withCheckedContinuation { continuation in lock.withLock { if sizes.count >= count { continuation.resume() } else { readObservers.append((count, continuation)) } } }
    }
    func exporter(context: Data) throws -> Data { Data(count: 32) }
    func cancel() {
        lock.withLock { stopped = true; read?.resume(throwing: PumpTestError.closed); read = nil; write?.resume(throwing: PumpTestError.closed); write = nil }
    }
}
