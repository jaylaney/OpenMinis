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

final class BridgeBox<T>: @unchecked Sendable {
    let lock = NSLock(); private var value: T
    init(_ value: T) { self.value = value }
    func get() -> T { lock.withLock { value } }
    func set(_ value: T) { lock.withLock { self.value = value } }
    func update(_ body: (inout T) -> Void) { lock.withLock { body(&value) } }
    func swap(_ value: T) -> T { lock.withLock { let old = self.value; self.value = value; return old } }
}
struct BridgeClock: StatusClock { let now = BridgeBox(StatusTLSClock.nowNanoseconds()); func nowNanoseconds() -> UInt64 { now.get() } }
struct BridgeRandom: StatusRandomSource { func bytes(count: Int) throws -> Data { Data(repeating: 7, count: count) } }
final class BridgeChangingRandom: StatusRandomSource, Sendable {
    private let next = BridgeBox<UInt8>(7)
    func bytes(count: Int) throws -> Data {
        let value = next.get(); next.set(value &+ 1)
        return Data(repeating: value, count: count)
    }
}
struct BridgeBackup: StatusBackupExclusion { func applyAndVerify(_ directory: URL) throws {} }
final class BridgeNative: SQLiteNative, @unchecked Sendable {
    let unknownCommit = BridgeBox(false)
    let failNextCommit = BridgeBox(false)
    let failNextRead = BridgeBox(false)
    let onStep = BridgeBox<(@Sendable (String) -> Void)?>(nil)
    func step(_ s: OpaquePointer) -> Int32 {
        let sql = String(cString: sqlite3_sql(s))
        onStep.get()?(sql)
        if sql.hasPrefix("SELECT"), failNextRead.swap(false) { return SQLITE_IOERR }
        if sql == "COMMIT", failNextCommit.swap(false) { return SQLITE_IOERR }
        if sql == "COMMIT", unknownCommit.get() {
            unknownCommit.set(false); _ = sqlite3_step(s); return SQLITE_IOERR
        }
        return sqlite3_step(s)
    }
    func failure(_ db: OpaquePointer) -> JournalStorageError { JournalStorageError(kind: .sqlite, message: "secret-storage-error", sqliteCode: SQLITE_IOERR, sqliteExtendedCode: 266) }
}
final class BridgeListener: HostListener, @unchecked Sendable {
    let acceptBlock = BridgeBox<(@Sendable (StatusTLSChannel) -> Void)?>(nil)
    let availability = BridgeBox<(@Sendable (Bool) -> Void)?>(nil)
    let startGate = BridgeBox<BridgeAsyncGate?>(nil)
    let failStart = BridgeBox(false)
    func start() async throws -> UInt16 {
        await startGate.get()?.arriveIfHeld()
        if failStart.get() { throw HostBridgeError.unavailable }
        availability.get()?(true); return 49152
    }
    func cancel() { availability.get()?(false) }
    func accept(_ c: StatusTLSChannel) { acceptBlock.get()?(c) }
}
struct HostFixture: @unchecked Sendable {
    let service: HostService
    let listener: BridgeListener
    let configuration: StatusOnlyHostConfiguration
    let endpoint: StatusEndpoint
    let directory: URL
    let clock: BridgeClock
    let native: BridgeNative
    let queue: DispatchQueue
    let key: SecKey
    let spki: Data
    static func open(gate: BridgeAsyncGate? = nil, openCompletionGate: BridgeAsyncGate? = nil, random: any StatusRandomSource = BridgeRandom(), onChange: @escaping @Sendable () -> Void = {}) async throws -> Self {
        let key = try makeKey(2), hostKey = try makeKey(1)
        let spki = try publicSPKI(hostKey)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("host-bridge-\(UUID())")
        let clock = BridgeClock(), native = BridgeNative(), listener = BridgeListener()
        let queue = DispatchQueue(label: "bridge-owner")
        let config = StatusOnlyHostConfiguration(directory: directory, clock: clock, random: random, identityResolver: { _ in spki }, onUnavailable: {})
        let service = HostService(dependencies: HostDependencies(
            loadPrivateKey: { try makeKey(1) },
            makeListener: { _, _, accept, availability in listener.acceptBlock.set(accept); listener.availability.set(availability); return listener },
            openOwner: { config in
                await gate?.arriveIfHeld()
                let opened = try await StatusOnlyHost.open(configuration: config, native: native, backupExclusion: BridgeBackup(), queue: queue)
                await openCompletionGate?.arriveIfHeld()
                return opened
            }), onChange: onChange)
        let endpoint = try StatusEndpoint(ipv4: "100.64.0.1", port: 49152)
        try await service.enable(configuration: config, endpoint: endpoint)
        return Self(service: service, listener: listener, configuration: config, endpoint: endpoint, directory: directory, clock: clock, native: native, queue: queue, key: key, spki: spki)
    }
    func remove() { try? FileManager.default.removeItem(at: directory) }
    func handshake(invitation: Invitation, normal: Bool = false, expectChallenge: Bool = true) async throws -> BridgeChannel {
        let channel = BridgeChannel(acceptedAt: clock.now.get())
        listener.accept(channel.channel)
        let h = try Hello(mode: normal ? .normal : .enrollment, hostID: invitation.hostID, hostPin: invitation.hostPin,
                          controllerPoint: Data(publicSPKI(key).suffix(65)), clientNonce: Data(repeating: 8, count: 32), invitationID: normal ? .zero : invitation.invitationID)
        channel.hello = h
        channel.feed(try WireFrame.hello(h).encode())
        if expectChallenge { await channel.waitForSend(1); await channel.waitForRead(2) }
        return channel
    }
    func prove(_ c: BridgeChannel, invitation: Invitation, normal: Bool = false) async throws {
        guard case .challenge(let challenge) = try c.frame(0) else { throw StatusHostError.invalidHandshake }
        let transcript = try AuthTranscript(hello: c.hello!, challenge: challenge)
        let proof = try PeerAuthentication.makeProof(transcript: transcript, exporter: Data(repeating: 9, count: 32), key: key, invitationSecret: normal ? nil : invitation.secret)
        c.feed(try WireFrame.proof(proof).encode())
    }
    func normal(_ invitation: Invitation) async throws -> BridgeChannel {
        let c = try await handshake(invitation: invitation, normal: true)
        try await prove(c, invitation: invitation, normal: true)
        await c.waitForSend(2); await c.waitForRead(3)
        return c
    }
}
actor BridgeAsyncGate {
    private var held = false, arrived = false
    private var releaseWaiter: CheckedContinuation<Void, Never>?
    private var arrivalWaiter: CheckedContinuation<Void, Never>?
    func hold() { held = true; arrived = false }
    func arriveIfHeld() async {
        guard held else { return }
        arrived = true; arrivalWaiter?.resume(); arrivalWaiter = nil
        await withCheckedContinuation { releaseWaiter = $0 }
    }
    func waitForArrival() async {
        if arrived { return }
        await withCheckedContinuation { arrivalWaiter = $0 }
    }
    func release() { held = false; releaseWaiter?.resume(); releaseWaiter = nil }
}
func makeKey(_ byte: UInt8) throws -> SecKey {
    let key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: byte, count: 32))
    guard let sec = SecKeyCreateWithData(key.x963Representation as CFData, [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 256] as CFDictionary, nil) else { throw StatusHostError.invalidKey }
    return sec
}
func publicSPKI(_ key: SecKey) throws -> Data {
    let publicKey = SecKeyCopyPublicKey(key)!
    let point = SecKeyCopyExternalRepresentation(publicKey, nil)! as Data
    return try P256.Signing.PublicKey(x963Representation: point).derRepresentation
}
final class BridgeChannel: StatusTLSChannelBackend, @unchecked Sendable {
    let id = UUID(); let acceptedAt: UInt64
    let lock = NSLock()
    var hello: Hello?
    let failNextSend = BridgeBox(false)
    let holdNextSend = BridgeBox(false)
    private var sender: CheckedContinuation<Void, Error>?
    private var stopped = false, chunks: [Data] = [], writes: [Data] = [], reads = 0
    private var reader: CheckedContinuation<Data, Error>?
    private var sendWaiters: [(Int, CheckedContinuation<Void, Never>)] = []
    private var readWaiters: [(Int, CheckedContinuation<Void, Never>)] = []
    private var cancelWaiters: [CheckedContinuation<Void, Never>] = []
    private var outcomeWaiters: [(Int, CheckedContinuation<Void, Never>)] = []
    init(acceptedAt: UInt64 = StatusTLSClock.nowNanoseconds()) { self.acceptedAt = acceptedAt }
    var channel: StatusTLSChannel { StatusTLSChannel(connectionID: id, acceptedAtNanoseconds: acceptedAt, backend: self) }
    var cancelled: Bool { lock.withLock { stopped } }
    var sent: [Data] { lock.withLock { writes } }
    func frame(_ index: Int) throws -> WireFrame { var d = FrameDecoder(); return try d.consume(sent[index]).frame! }
    func ready() async throws {}
    func exporter(context: Data) throws -> Data { Data(repeating: 9, count: 32) }
    func receive(maximumBytes: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { c in lock.withLock {
            reads += 1
            let ready = readWaiters.filter { $0.0 <= reads }; readWaiters.removeAll { $0.0 <= reads }
            for w in ready { w.1.resume() }
            let outcomes = outcomeWaiters.filter { $0.0 <= reads }; outcomeWaiters.removeAll { $0.0 <= reads }
            for w in outcomes { w.1.resume() }
            if stopped { c.resume(throwing: StatusTLSError.closed) }
            else if !chunks.isEmpty { c.resume(returning: chunks.removeFirst()) }
            else { reader = c }
        } }
    }
    func feed(_ data: Data) { lock.withLock {
        if let reader { self.reader = nil; reader.resume(returning: data) } else { chunks.append(data) }
    } }
    func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in lock.withLock {
            guard !stopped, !failNextSend.get() else { c.resume(throwing: StatusTLSError.closed); return }
            writes.append(data)
            if holdNextSend.swap(false) { sender = c } else { c.resume() }
            let ready = sendWaiters.filter { $0.0 <= writes.count }; sendWaiters.removeAll { $0.0 <= writes.count }
            for w in ready { w.1.resume() }
        } }
    }
    func releaseSend() { lock.withLock { sender?.resume(); sender = nil } }
    func cancel() { lock.withLock {
        stopped = true; reader?.resume(throwing: StatusTLSError.closed); reader = nil
        sender?.resume(throwing: StatusTLSError.closed); sender = nil
        for w in cancelWaiters { w.resume() }; cancelWaiters.removeAll()
        for w in outcomeWaiters { w.1.resume() }; outcomeWaiters.removeAll()
    } }
    func waitForSend(_ n: Int) async { await withCheckedContinuation { c in lock.withLock { if writes.count >= n { c.resume() } else { sendWaiters.append((n,c)) } } } }
    func waitForRead(_ n: Int) async { await withCheckedContinuation { c in lock.withLock { if reads >= n { c.resume() } else { readWaiters.append((n,c)) } } } }
    func waitForReadOrCancel(_ n: Int) async { await withCheckedContinuation { c in lock.withLock { if reads >= n || stopped { c.resume() } else { outcomeWaiters.append((n,c)) } } } }
    func waitForCancel() async { await withCheckedContinuation { c in lock.withLock { if stopped { c.resume() } else { cancelWaiters.append(c) } } } }
}
#endif
