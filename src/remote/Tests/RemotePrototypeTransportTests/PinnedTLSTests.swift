#if os(macOS)
import XCTest
import Foundation
import Security
import CryptoKit
import Network
import RemotePrototypeCertificates
import RemotePrototypeWire
@testable import RemotePrototypeTransport

final class PinnedTLSTests: XCTestCase, @unchecked Sendable {
    // A permissive pin callback, a non-contextual exporter, or a changed TLS label
    // breaks these real socket assertions. No Hello/proof bytes precede pin success.
    func testLoopbackPinAndContextualExporter() async throws {
        let key = try makeKey()
        let identity = try HostCertificate.makeIdentity(key: key, now: Date())
        let accepted = ChannelBox()
        let acceptedAt = StatusTLSClock.nowNanoseconds()
        let listener = try StatusTLSListener.loopback(identity: identity, now: { acceptedAt }) { accepted.put($0) }
        defer { listener.cancel() }
        let port = try await listener.start()
        let client = try await StatusTLSChannel.connectLoopback(port: port, pin: pin(key))
        defer { client.cancel() }
        let server = try await accepted.take()
        defer { server.cancel() }
        try await server.ready()
        let hello = try Hello(mode: .enrollment, hostID: UUID(), hostPin: pin(key),
            controllerPoint: P256.Signing.PrivateKey().publicKey.x963Representation,
            clientNonce: Data(repeating: 2, count: 32), invitationID: UUID())
        let transcript = try AuthTranscript(hello: hello,
            challenge: Challenge(serverNonce: Data(repeating: 3, count: 32), controllerID: .zero, generation: 0))
        let context = try transcript.exporterContext()
        let clientSecret = try client.exporter(context: context)
        XCTAssertEqual(clientSecret.count, 32)
        XCTAssertEqual(clientSecret, try server.exporter(context: context))
        XCTAssertNotEqual(clientSecret, try server.exporter(context: Data(repeating: 9, count: 32)))
        XCTAssertThrowsError(try client.exporter(context: Data()))
        XCTAssertEqual(server.acceptedAtNanoseconds, acceptedAt)
        XCTAssertNotEqual(server.connectionID, client.connectionID)
        try await client.send(Data([1, 2, 3]))
        let bytes = try await server.receive(maximumBytes: 3)
        XCTAssertEqual(bytes, Data([1, 2, 3]))
        do {
            let wrong = try await StatusTLSChannel.connectLoopback(port: port, pin: Data(repeating: 0, count: 32))
            wrong.cancel()
            XCTFail("Wrong pin reached ready before any application data")
        } catch { }
    }

    // An independently invoked native exporter with a literal label catches both
    // endpoints accidentally agreeing on the same wrong label or context handling.
    func testExporterInteroperatesWithLiteralNativeLabelAndContext() async throws {
        let key = try makeKey()
        let fixture = try RawTLSListenerFixture(identity: HostCertificate.makeIdentity(key: key, now: Date()),
            version: .TLSv13, protocolName: "openminis-prototype/1")
        defer { fixture.cancel() }
        let port = try await fixture.start()
        let client = try await StatusTLSChannel.connectLoopback(port: port, pin: pin(key))
        defer { client.cancel() }
        let context = Data(SHA256.hash(data: Data("independent contextual exporter fixture".utf8)))
        let expected = try await fixture.exporter(context: context)
        XCTAssertEqual(try client.exporter(context: context), expected)
    }

    // Enabling platform trust validation or pinning the certificate rather than
    // its key makes either expired/future-dated native handshake fail.
    func testNativeSameKeyReissueIgnoresDatesHostnameAndCA() async throws {
        let key = try makeKey()
        let expectedPin = try pin(key)
        for date in [Date(timeIntervalSince1970: 0), Date(timeIntervalSince1970: 2_000_000_000)] {
            let listener = try StatusTLSListener.loopback(identity: HostCertificate.makeIdentity(key: key, now: date)) { _ in }
            let port = try await listener.start()
            let client: StatusTLSChannel
            do { client = try await StatusTLSChannel.connectLoopback(port: port, pin: expectedPin) }
            catch { listener.cancel(); throw error }
            client.cancel(); listener.cancel()
        }
    }

    // Removing version/ALPN enforcement admits peers that speak a different protocol.
    func testNativeTLS12AndMissingALPNAreRefused() async throws {
        let identity = try HostCertificate.makeIdentity(key: makeKey(), now: Date())
        let certificate = try certificate(identity)
        let publicKey = try XCTUnwrap(SecCertificateCopyKey(certificate))
        let point = try XCTUnwrap(SecKeyCopyExternalRepresentation(publicKey, nil)) as Data
        let publicP256 = try P256.Signing.PublicKey(x963Representation: point)
        let expectedPin = Data(SHA256.hash(data: publicP256.derRepresentation))
        for version in [tls_protocol_version_t.TLSv12, .TLSv13] {
            let fixture = try RawTLSListenerFixture(identity: identity, version: version)
            let port = try await fixture.start()
            do {
                let client = try await StatusTLSChannel.connectLoopback(port: port, pin: expectedPin)
                client.cancel(); XCTFail("Incompatible TLS/ALPN reached ready")
            } catch { }
            fixture.cancel()
        }
    }

    // Rechecking system trust/date/hostname or pinning certificate bytes rejects reissue.
    // Removing algorithm/curve/SPKI checking lets malformed certificates pass.
    func testPinPolicyAndEndpoint() throws {
        let key = try makeKey()
        let old = try certificate(HostCertificate.makeIdentity(key: key, now: Date(timeIntervalSince1970: 0)))
        let reissue = try certificate(HostCertificate.makeIdentity(key: key, now: Date(timeIntervalSince1970: 2_000_000_000)))
        XCTAssertNotEqual(SecCertificateCopyData(old) as Data, SecCertificateCopyData(reissue) as Data)
        XCTAssertTrue(PinnedTLS.matches(certificate: old, pin: try pin(key)))
        XCTAssertTrue(PinnedTLS.matches(certificate: reissue, pin: try pin(key)))
        let other = try certificate(HostCertificate.makeIdentity(key: makeKey(), now: Date()))
        XCTAssertFalse(PinnedTLS.matches(certificate: other, pin: try pin(key)))
        var invalidCurve = SecCertificateCopyData(old) as Data
        let oid = Data([0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07])
        let range = try XCTUnwrap(invalidCurve.range(of: oid))
        invalidCurve[range.upperBound - 1] = 8
        let badCurve = try XCTUnwrap(SecCertificateCreateWithData(nil, invalidCurve as CFData))
        XCTAssertFalse(PinnedTLS.matches(certificate: badCurve, pin: try pin(key)))
        XCTAssertThrowsError(try PinnedTLS.clientOptions(pin: Data()))
        for address in ["0.0.0.0", "127.0.0.1", "localhost", "100.128.0.1"] {
            XCTAssertThrowsError(try StatusEndpoint(ipv4: address, port: 49152))
        }
        let endpoint = try StatusEndpoint(ipv4: "100.64.0.20", port: 49152)
        XCTAssertThrowsError(try ExactAddressLifecycle(endpoint: endpoint, present: { _ in false }, bind: { _ in }, stop: {}))
    }

    // Losing the selected address must cancel resources; returning another address
    // cannot cause fallback. This drives the production lifecycle without a tailnet bind.
    func testSelectedAddressLossClosesAndRebindsOnlySavedAddress() throws {
        let endpoint = try StatusEndpoint(ipv4: "100.64.0.20", port: 49152)
        let state = PresenceFixture()
        let lifecycle = try ExactAddressLifecycle(endpoint: endpoint, present: { state.isPresent($0) }, bind: { state.bind($0) }, stop: { state.stop() })
        try lifecycle.refresh()
        XCTAssertEqual(state.binds, [endpoint])
        state.present = false
        try lifecycle.refresh()
        XCTAssertEqual(state.stops, 1)
        try lifecycle.refresh()
        XCTAssertEqual(state.binds, [endpoint])
        state.present = true
        try lifecycle.refresh()
        XCTAssertEqual(state.binds, [endpoint, endpoint])
        lifecycle.cancel()
        XCTAssertEqual(state.stops, 2)
        try lifecycle.refresh()
        XCTAssertEqual(state.binds, [endpoint, endpoint])
    }

    // Forgetting either listener cancellation or accepted-channel cancellation on
    // an injected address-loss event leaves a working native socket behind.
    func testInjectedAddressLossStopsNativeListenerAndAcceptedChannels() async throws {
        let key = try makeKey()
        let selected = try StatusEndpoint(ipv4: "100.64.0.20", port: 49152)
        let presence = LockedPresence()
        let monitor = ManualAddressMonitor()
        let accepted = ChannelBox()
        let listener = try StatusTLSListener.loopback(identity: HostCertificate.makeIdentity(key: key, now: Date()),
            selectedEndpoint: selected, present: { _ in presence.value }, monitor: monitor) { accepted.put($0) }
        defer { listener.cancel() }
        let port = try await listener.start()
        let client = try await StatusTLSChannel.connectLoopback(port: port, pin: pin(key))
        defer { client.cancel() }
        let server = try await accepted.take()
        try await server.ready()
        let reading = Task { try await server.receive(maximumBytes: 1) }
        presence.set(false)
        await monitor.changed()
        do { _ = try await reading.value; XCTFail("address loss left accepted socket open") } catch { }
        XCTAssertThrowsError(try server.exporter(context: Data(count: 32)))
        do {
            let unexpected = try await StatusTLSChannel.connectLoopback(port: port, pin: pin(key))
            unexpected.cancel(); XCTFail("address loss left listener open")
        } catch { }
    }

    // Using uptime, unchecked addition, or allowing equality extends the fixed
    // ten-second TLS/send timeout beyond the accepted continuous-clock deadline.
    func testContinuousDeadlineUsesCheckedAdditionAndExpiresAtEquality() throws {
        let deadline = try ContinuousTLSDeadline(start: 77)
        XCTAssertNoThrow(try deadline.check(now: 10_000_000_076))
        XCTAssertThrowsError(try deadline.check(now: 10_000_000_077))
        XCTAssertThrowsError(try ContinuousTLSDeadline(start: UInt64.max))
    }

    // Exporting before readiness, oversized operations, and post-cancel operations
    // fail without allocating an application frame or leaking a continuation.
    func testBoundsCancellationAndMissingExporterFailClosed() async throws {
        let key = try makeKey()
        let unstarted = NativeTLSChannel(connection: NWConnection(host: .ipv4(.loopback), port: 9,
            using: NWParameters(tls: try PinnedTLS.clientOptions(pin: pin(key)))))
        XCTAssertThrowsError(try unstarted.exporter(context: Data(count: 32)))
        unstarted.cancel()
        let accepted = ChannelBox()
        let listener = try StatusTLSListener.loopback(identity: HostCertificate.makeIdentity(key: key, now: Date())) { accepted.put($0) }
        defer { listener.cancel() }
        let port = try await listener.start()
        let client = try await StatusTLSChannel.connectLoopback(port: port, pin: pin(key))
        defer { client.cancel() }
        let server = try await accepted.take()
        try await server.ready()
        defer { server.cancel() }
        do { try await client.send(Data(count: 4101)); XCTFail("oversized send") } catch { }
        do { _ = try await server.receive(maximumBytes: 4101); XCTFail("oversized receive") } catch { }
        let receiving = Task { try await server.receive(maximumBytes: 1) }
        server.cancel()
        do { _ = try await receiving.value; XCTFail("cancelled receive") } catch { }
        XCTAssertThrowsError(try server.exporter(context: Data(count: 32)))
        do { try await server.send(Data([1])); XCTFail("send after cancellation") } catch { }
    }

    private func makeKey() throws -> SecKey {
        try XCTUnwrap(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256] as CFDictionary, nil))
    }
    private func pin(_ key: SecKey) throws -> Data {
        let point = try XCTUnwrap(SecKeyCopyExternalRepresentation(try XCTUnwrap(SecKeyCopyPublicKey(key)), nil)) as Data
        let prefix = Data([0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00])
        return Data(SHA256.hash(data: prefix + point))
    }
    private func certificate(_ identity: SecIdentity) throws -> SecCertificate {
        var certificate: SecCertificate?
        XCTAssertEqual(SecIdentityCopyCertificate(identity, &certificate), errSecSuccess)
        return try XCTUnwrap(certificate)
    }
}

private final class ChannelBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: StatusTLSChannel?
    private var waiter: CheckedContinuation<StatusTLSChannel, Error>?
    func put(_ channel: StatusTLSChannel) {
        lock.lock()
        if let waiter { self.waiter = nil; lock.unlock(); waiter.resume(returning: channel) }
        else if stored == nil { stored = channel; lock.unlock() }
        else { lock.unlock(); channel.cancel() }
    }
    func take() async throws -> StatusTLSChannel {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            if let stored { self.stored = nil; lock.unlock(); continuation.resume(returning: stored) }
            else { waiter = continuation; lock.unlock() }
        }
    }
}
private final class PresenceFixture: @unchecked Sendable {
    var present = true
    var binds: [StatusEndpoint] = []
    var stops = 0
    func isPresent(_ endpoint: StatusEndpoint) -> Bool { present && endpoint.ipv4 == "100.64.0.20" }
    func bind(_ endpoint: StatusEndpoint) { binds.append(endpoint) }
    func stop() { stops += 1 }
}
#endif

#if os(macOS)
// A deliberately incompatible peer, owned only by this test file. All sockets
// use requiredLocalEndpoint 127.0.0.1 and a disposable ephemeral port.
private final class RawTLSListenerFixture: @unchecked Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "test.openminis.raw-tls")
    private var channels: [NWConnection] = []
    private var waiter: CheckedContinuation<UInt16, Error>?
    private var readyChannel: NWConnection?
    private var exporterRequest: (Data, CheckedContinuation<Data, Error>)?
    init(identity: SecIdentity, version: tls_protocol_version_t, protocolName: String? = nil) throws {
        let options = NWProtocolTLS.Options()
        let native = options.securityProtocolOptions
        sec_protocol_options_set_local_identity(native, try XCTUnwrap(sec_identity_create(identity)))
        sec_protocol_options_set_min_tls_protocol_version(native, version)
        sec_protocol_options_set_max_tls_protocol_version(native, version)
        sec_protocol_options_set_tls_resumption_enabled(native, false)
        if let protocolName { sec_protocol_options_add_tls_application_protocol(native, protocolName) }
        let parameters = NWParameters(tls: options)
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        listener = try NWListener(using: parameters, on: .any)
    }
    func start() async throws -> UInt16 {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [self] in
                waiter = continuation
                listener.stateUpdateHandler = { [weak self] state in
                    guard let self, let waiter else { return }
                    switch state {
                    case .ready:
                        self.waiter = nil
                        waiter.resume(returning: listener.port!.rawValue)
                    case .failed(let error): self.waiter = nil; waiter.resume(throwing: error)
                    default: break
                    }
                }
                listener.newConnectionHandler = { [weak self] connection in
                    guard let self else { connection.cancel(); return }
                    channels.append(connection)
                    connection.stateUpdateHandler = { [weak self, weak connection] state in
                        guard let self, let connection else { return }
                        if case .ready = state {
                            readyChannel = connection
                            if let request = exporterRequest {
                                exporterRequest = nil
                                request.1.resume(with: Result { try literalExporter(connection, context: request.0) })
                            }
                        }
                    }
                    connection.start(queue: queue)
                }
                listener.start(queue: queue)
            }
        }
    }
    func exporter(context: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [self] in
                if let readyChannel {
                    continuation.resume(with: Result { try literalExporter(readyChannel, context: context) })
                } else { exporterRequest = (context, continuation) }
            }
        }
    }
    private func literalExporter(_ connection: NWConnection, context: Data) throws -> Data {
        let metadata = try XCTUnwrap(connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata)
        let exported = context.withUnsafeBytes { bytes in
            "EXPORTER-OpenMinis-Prototype-v1".withCString { label in
                sec_protocol_metadata_create_secret_with_context(metadata.securityProtocolMetadata,
                    31, label, 32, bytes.bindMemory(to: UInt8.self).baseAddress!, 32)
            }
        }
        return Data(try XCTUnwrap(exported) as DispatchData)
    }
    func cancel() {
        listener.cancel()
        queue.async { [self] in channels.forEach { $0.cancel() }; channels.removeAll() }
    }
    deinit { listener.cancel(); channels.forEach { $0.cancel() } }
}
#endif

#if os(macOS)
private final class LockedPresence: @unchecked Sendable {
    private let lock = NSLock()
    private var present = true
    var value: Bool { lock.withLock { present } }
    func set(_ value: Bool) { lock.withLock { present = value } }
}
private final class ManualAddressMonitor: StatusTLSAddressMonitor, @unchecked Sendable {
    private let lock = NSLock()
    private var handler: (@Sendable () -> Void)?
    private var queue: DispatchQueue?
    func start(queue: DispatchQueue, onChange: @escaping @Sendable () -> Void) {
        lock.withLock { self.queue = queue; handler = onChange }
    }
    func cancel() { lock.withLock { handler = nil; queue = nil } }
    func changed() async {
        let event = lock.withLock { (queue, handler) }
        guard let queue = event.0, let handler = event.1 else { return }
        await withCheckedContinuation { continuation in
            queue.async { handler(); continuation.resume() }
        }
    }
}
#endif
