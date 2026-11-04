import Foundation
import CryptoKit
import Security
import XCTest
import RemotePrototypeWire
import RemotePrototypeTransport

final class PeerAuthenticationTests: XCTestCase {
    let exporter = Data(repeating: 0x44, count: 32)
    let secret = Data(repeating: 0x55, count: 32)

    // Catches wrong signature encoding, double hashing, low-S-only policy, or HMAC inputs.
    func testLiteralProofAndBothValidSForms() throws {
        let t = try transcript()
        XCTAssertNoThrow(try PeerAuthentication.verify(transcript: t, exporter: exporter, proof: Proof(signature: V.signature, secretProof: V.secretProof), invitationSecret: secret))
        let oppositeMAC = Data(HMAC<SHA256>.authenticationCode(for: try t.invitationProofBytes(exporter: exporter, signature: V.oppositeSignature), using: SymmetricKey(data: secret)))
        XCTAssertNoThrow(try PeerAuthentication.verify(transcript: t, exporter: exporter, proof: Proof(signature: V.oppositeSignature, secretProof: oppositeMAC), invitationSecret: secret))
        XCTAssertEqual(V.signature.count, 64)
        let key = try fixedKey()
        let doubleHash = try XCTUnwrap(SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, Data(SHA256.hash(data: V.signing)) as CFData, nil)) as Data
        let raw = try P256.Signing.ECDSASignature(derRepresentation: doubleHash).rawRepresentation
        let mac = Data(HMAC<SHA256>.authenticationCode(for: try t.invitationProofBytes(exporter: exporter, signature: raw), using: SymmetricKey(data: secret)))
        XCTAssertThrowsError(try PeerAuthentication.verify(transcript: t, exporter: exporter, proof: Proof(signature: raw, secretProof: mac), invitationSecret: secret))
    }

    // Catches any unbound B field, exporter, invitation secret, or proof component.
    func testProofCannotCrossChannelOrClaim() throws {
        let t = try transcript()
        let proof = try Proof(signature: V.signature, secretProof: V.secretProof)
        XCTAssertThrowsError(try PeerAuthentication.verify(transcript: t, exporter: Data(repeating: 0x45, count: 32), proof: proof, invitationSecret: secret))
        let h = t.hello
        let otherPoint = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x02, count: 32)).publicKey.x963Representation
        let variants = [
            try Hello(mode: .enrollment, hostID: invitation, hostPin: h.hostPin, controllerPoint: h.controllerPoint, clientNonce: h.clientNonce, invitationID: h.invitationID),
            try Hello(mode: .enrollment, hostID: h.hostID, hostPin: Data(count: 32), controllerPoint: h.controllerPoint, clientNonce: h.clientNonce, invitationID: h.invitationID),
            try Hello(mode: .enrollment, hostID: h.hostID, hostPin: h.hostPin, controllerPoint: otherPoint, clientNonce: h.clientNonce, invitationID: h.invitationID),
            try Hello(mode: .enrollment, hostID: h.hostID, hostPin: h.hostPin, controllerPoint: h.controllerPoint, clientNonce: Data(count: 32), invitationID: h.invitationID),
            try Hello(mode: .enrollment, hostID: h.hostID, hostPin: h.hostPin, controllerPoint: h.controllerPoint, clientNonce: h.clientNonce, invitationID: host)
        ]
        for hello in variants { XCTAssertThrowsError(try PeerAuthentication.verify(transcript: AuthTranscript(hello: hello, challenge: t.challenge), exporter: exporter, proof: proof, invitationSecret: secret)) }
        let challenge = try Challenge(serverNonce: Data(count: 32), controllerID: .zero, generation: 0)
        XCTAssertThrowsError(try PeerAuthentication.verify(transcript: AuthTranscript(hello: h, challenge: challenge), exporter: exporter, proof: proof, invitationSecret: secret))
        let normal = try normalTranscript(point: h.controllerPoint)
        XCTAssertThrowsError(try PeerAuthentication.verify(transcript: normal, exporter: exporter, proof: proof, invitationSecret: nil))
        for badSecret in [nil, Data(count: 31), Data(count: 33), Data(repeating: 0x56, count: 32)] as [Data?] {
            XCTAssertThrowsError(try PeerAuthentication.verify(transcript: t, exporter: exporter, proof: proof, invitationSecret: badSecret))
        }
        var changed = V.secretProof; changed[31] ^= 1
        XCTAssertThrowsError(try PeerAuthentication.verify(transcript: t, exporter: exporter, proof: Proof(signature: V.signature, secretProof: changed), invitationSecret: secret))
        for count in [0,31,33] { XCTAssertThrowsError(try PeerAuthentication.verify(transcript: t, exporter: Data(count: count), proof: proof, invitationSecret: secret)) }
    }

    // Catches omitting normal controller/generation, or binding only placeholder validation to mode.
    func testNormalProofBindsModeAndEachChallengeField() throws {
        let t = try normalTranscript(point: V.point)
        let proof = try PeerAuthentication.makeProof(transcript: t, exporter: exporter, key: fixedKey(), invitationSecret: nil)
        for challenge in [
            try Challenge(serverNonce: t.challenge.serverNonce, controllerID: host, generation: 1),
            try Challenge(serverNonce: t.challenge.serverNonce, controllerID: invitation, generation: 2),
            try Challenge(serverNonce: Data(count: 32), controllerID: invitation, generation: 1)
        ] {
            XCTAssertThrowsError(try PeerAuthentication.verify(transcript: AuthTranscript(hello: t.hello, challenge: challenge), exporter: exporter, proof: proof, invitationSecret: nil))
        }
        let enrollment = try transcript()
        let mac = Data(HMAC<SHA256>.authenticationCode(for: try enrollment.invitationProofBytes(exporter: exporter, signature: proof.signature), using: SymmetricKey(data: secret)))
        XCTAssertThrowsError(try PeerAuthentication.verify(transcript: enrollment, exporter: exporter, proof: Proof(signature: proof.signature, secretProof: mac), invitationSecret: secret))
    }

    // Catches missing scalar bounds/ECDSA checks and accepting non-curve wire keys.
    func testInvalidScalarsPointsAndDERSignatureRejected() throws {
        let t = try transcript()
        let order = bytes("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
        for raw in [Data(count: 64), Data(count: 32) + V.signature.suffix(32), V.signature.prefix(32) + Data(count: 32), order + V.signature.suffix(32), V.signature.prefix(32) + order] {
            let mac = Data(HMAC<SHA256>.authenticationCode(for: try t.invitationProofBytes(exporter: exporter, signature: raw), using: SymmetricKey(data: secret)))
            XCTAssertThrowsError(try PeerAuthentication.verify(transcript: t, exporter: exporter, proof: Proof(signature: raw, secretProof: mac), invitationSecret: secret))
        }
        let der = try P256.Signing.ECDSASignature(rawRepresentation: V.signature).derRepresentation
        XCTAssertThrowsError(try Proof(signature: der, secretProof: V.secretProof))
        for point in [Data(count: 65), Data([4]) + Data(repeating: 0xff, count: 64), Data([2]) + V.point.dropFirst()] {
            XCTAssertThrowsError(try Hello(mode: .enrollment, hostID: host, hostPin: Data(count: 32), controllerPoint: point, clientNonce: Data(count: 32), invitationID: invitation))
        }
    }

    // Uses real nonpersistent SecKeys: catches makeProof DER leakage or mismatched key use.
    func testMakeProofWithEphemeralSecKeyInBothModes() throws {
        let key = try XCTUnwrap(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256, kSecAttrIsPermanent: false] as CFDictionary, nil))
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(key))
        let point = try XCTUnwrap(SecKeyCopyExternalRepresentation(publicKey, nil)) as Data
        let base = try transcript()
        let enrollment = try AuthTranscript(hello: Hello(mode: .enrollment, hostID: host, hostPin: base.hello.hostPin, controllerPoint: point, clientNonce: base.hello.clientNonce, invitationID: invitation), challenge: base.challenge)
        let proof = try PeerAuthentication.makeProof(transcript: enrollment, exporter: exporter, key: key, invitationSecret: secret)
        XCTAssertEqual(proof.signature.count, 64)
        XCTAssertNoThrow(try PeerAuthentication.verify(transcript: enrollment, exporter: exporter, proof: proof, invitationSecret: secret))
        let normal = try normalTranscript(point: point)
        let normalProof = try PeerAuthentication.makeProof(transcript: normal, exporter: exporter, key: key, invitationSecret: nil)
        XCTAssertEqual(normalProof.secretProof, Data(count: 32))
        XCTAssertNoThrow(try PeerAuthentication.verify(transcript: normal, exporter: exporter, proof: normalProof, invitationSecret: nil))
        XCTAssertThrowsError(try PeerAuthentication.makeProof(transcript: base, exporter: exporter, key: key, invitationSecret: secret))
        XCTAssertThrowsError(try PeerAuthentication.makeProof(transcript: enrollment, exporter: exporter, key: key, invitationSecret: nil))
        XCTAssertThrowsError(try PeerAuthentication.makeProof(transcript: normal, exporter: exporter, key: key, invitationSecret: secret))
        XCTAssertThrowsError(try PeerAuthentication.verify(transcript: normal, exporter: exporter, proof: normalProof, invitationSecret: secret))
        let modified = try Proof(signature: normalProof.signature, secretProof: Data(repeating: 1, count: 32))
        XCTAssertThrowsError(try PeerAuthentication.verify(transcript: normal, exporter: exporter, proof: modified, invitationSecret: nil))
        let changedChallenge = try AuthTranscript(hello: normal.hello, challenge: Challenge(serverNonce: normal.challenge.serverNonce, controllerID: host, generation: 2))
        XCTAssertThrowsError(try PeerAuthentication.verify(transcript: changedChallenge, exporter: exporter, proof: normalProof, invitationSecret: nil))
    }
}
private func normalTranscript(point: Data) throws -> AuthTranscript {
    try AuthTranscript(hello: Hello(mode: .normal, hostID: host, hostPin: Data(repeating: 0x11, count: 32), controllerPoint: point, clientNonce: Data(repeating: 0x22, count: 32), invitationID: .zero), challenge: Challenge(serverNonce: Data(repeating: 0x33, count: 32), controllerID: invitation, generation: 1))
}
private func fixedKey() throws -> SecKey {
    try XCTUnwrap(SecKeyCreateWithData((V.point + Data(count: 31) + Data([1])) as CFData, [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 256] as CFDictionary, nil))
}

// Literal vectors independently generated with Python hashlib/hmac and P256 integer arithmetic.
private enum V {
    static let point = bytes("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    static let signing = bytes("00274f70656e4d696e69732f50726f746f747970652f76312f636f6e74726f6c6c65722d70726f6f660000013a00204f70656e4d696e69732f50726f746f747970652f76312f68616e647368616b650000000101000000100102030405060708090a0b0c0d0e0f100000002011111111111111111111111111111111111111111111111111111111111111110000005b3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5000000202222222222222222222222222222222222222222222222222222222222222222000000203333333333333333333333333333333333333333333333333333333333333333000000101112131415161718191a1b1c1d1e1f200000001000000000000000000000000000000000000000080000000000000000000000204444444444444444444444444444444444444444444444444444444444444444")
    static let signature = bytes("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978b171f6a2a3be8d112b5ccb2b09abe46d2cbbc6937adf46e1220ed3f2fe2aa5b7")
    static let oppositeSignature = bytes("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc476699784e8e095c5c4172efd4a334d4f6541b92902b341a2c3857a3d1aaf6cffe387f9a")
    static let secretProof = bytes("4cbc837ef3b88a17e541e26d292887511dc0fd4308e49573de382d0852230626")
}

private func bytes(_ text: String) -> Data {
    let c = Array(text)
    return Data(stride(from: 0, to: c.count, by: 2).map { UInt8(String(c[$0...$0 + 1]), radix: 16)! })
}
private let host = UUID(uuidString: "01020304-0506-0708-090a-0b0c0d0e0f10")!
private let invitation = UUID(uuidString: "11121314-1516-1718-191a-1b1c1d1e1f20")!
private func transcript() throws -> AuthTranscript {
    try AuthTranscript(hello: Hello(mode: .enrollment, hostID: host, hostPin: Data(repeating: 0x11, count: 32), controllerPoint: V.point, clientNonce: Data(repeating: 0x22, count: 32), invitationID: invitation), challenge: Challenge(serverNonce: Data(repeating: 0x33, count: 32), controllerID: .zero, generation: 0))
}
