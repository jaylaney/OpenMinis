import Foundation
import CryptoKit
import XCTest
import RemotePrototypeWire

final class AuthTranscriptTests: XCTestCase {
    // Catches wrong labels, F prefixes, UUID order, SPKI, field order, or SAS padding.
    func testLiteralTranscriptVectors() throws {
        let t = try transcript()
        XCTAssertEqual(t.hello.controllerSPKI.count, 91)
        XCTAssertEqual(t.hello.controllerSPKI, V.spki)
        XCTAssertEqual(Data(SHA256.hash(data: t.hello.controllerSPKI)), V.pin)
        XCTAssertEqual(try t.canonicalBytes(), V.B)
        XCTAssertEqual(try t.exporterContext(), V.context)
        XCTAssertEqual(try t.controllerProofBytes(exporter: Data(repeating: 0x44, count: 32)), V.signing)
        XCTAssertEqual(try t.invitationProofBytes(exporter: Data(repeating: 0x44, count: 32), signature: V.signature), V.invitationProof)
        XCTAssertEqual(Data(HMAC<SHA256>.authenticationCode(for: V.invitationProof, using: SymmetricKey(data: Data(repeating: 0x55, count: 32)))), V.secretProof)
        XCTAssertEqual(try t.claimDigest(exporter: Data(repeating: 0x44, count: 32), signature: V.signature, secretProof: V.secretProof), V.claim)
        XCTAssertEqual(try comparisonCode(secret: Data(repeating: 0x55, count: 32), claimDigest: V.claim, sasNonce: V.sasNonce), "06135611")
    }

    // Catches mode-unaware transcript/claim validation and unchecked exporter/signature sizes.
    func testTranscriptRequiresModeAndExactLengths() throws {
        let t = try transcript()
        XCTAssertThrowsError(try AuthTranscript(hello: t.hello, challenge: Challenge(serverNonce: Data(count: 32), controllerID: host, generation: 1)))
        for count in [0, 31, 33] {
            XCTAssertThrowsError(try t.controllerProofBytes(exporter: Data(count: count)))
            XCTAssertThrowsError(try t.claimDigest(exporter: Data(count: count), signature: V.signature, secretProof: V.secretProof))
            XCTAssertThrowsError(try t.invitationProofBytes(exporter: Data(count: 32), signature: Data(count: count)))
            XCTAssertThrowsError(try comparisonCode(secret: Data(count: count), claimDigest: V.claim, sasNonce: V.sasNonce))
            XCTAssertThrowsError(try comparisonCode(secret: Data(count: 32), claimDigest: Data(count: count), sasNonce: V.sasNonce))
            XCTAssertThrowsError(try comparisonCode(secret: Data(count: 32), claimDigest: V.claim, sasNonce: Data(count: count)))
        }
        let normal = try AuthTranscript(hello: Hello(mode: .normal, hostID: host, hostPin: Data(count: 32), controllerPoint: V.point, clientNonce: Data(count: 32), invitationID: .zero), challenge: Challenge(serverNonce: Data(count: 32), controllerID: invitation, generation: 1))
        XCTAssertThrowsError(try normal.claimDigest(exporter: Data(count: 32), signature: V.signature, secretProof: V.secretProof))
        XCTAssertNoThrow(try normal.claimDigest(exporter: Data(count: 32), signature: V.signature, secretProof: Data(count: 32)))
    }

    // Catches omission of claim or post-fixation SAS nonce from the comparison HMAC.
    func testComparisonBindsClaimAndPostFixationNonce() throws {
        let secret = Data(repeating: 0x55, count: 32)
        XCTAssertNotEqual(try comparisonCode(secret: secret, claimDigest: Data(count: 32), sasNonce: V.sasNonce), V.code)
        XCTAssertNotEqual(try comparisonCode(secret: secret, claimDigest: V.claim, sasNonce: Data(count: 32)), V.code)
        XCTAssertNotEqual(try comparisonCode(secret: Data(repeating: 0x56, count: 32), claimDigest: V.claim, sasNonce: V.sasNonce), V.code)
    }
}

// Literal vectors independently generated with Python hashlib/hmac and P256 integer arithmetic.
private enum V {
    static let point = bytes("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    static let spki = bytes("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    static let pin = bytes("5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3")
    static let B = bytes("00204f70656e4d696e69732f50726f746f747970652f76312f68616e647368616b650000000101000000100102030405060708090a0b0c0d0e0f100000002011111111111111111111111111111111111111111111111111111111111111110000005b3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5000000202222222222222222222222222222222222222222222222222222222222222222000000203333333333333333333333333333333333333333333333333333333333333333000000101112131415161718191a1b1c1d1e1f200000001000000000000000000000000000000000000000080000000000000000")
    static let context = bytes("df65302d71069be17989cf33480626bc8ad092f47bec98e58725992cf4e796de")
    static let signing = bytes("00274f70656e4d696e69732f50726f746f747970652f76312f636f6e74726f6c6c65722d70726f6f660000013a00204f70656e4d696e69732f50726f746f747970652f76312f68616e647368616b650000000101000000100102030405060708090a0b0c0d0e0f100000002011111111111111111111111111111111111111111111111111111111111111110000005b3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5000000202222222222222222222222222222222222222222222222222222222222222222000000203333333333333333333333333333333333333333333333333333333333333333000000101112131415161718191a1b1c1d1e1f200000001000000000000000000000000000000000000000080000000000000000000000204444444444444444444444444444444444444444444444444444444444444444")
    static let signature = bytes("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978b171f6a2a3be8d112b5ccb2b09abe46d2cbbc6937adf46e1220ed3f2fe2aa5b7")
    static let invitationProof = bytes("00274f70656e4d696e69732f50726f746f747970652f76312f696e7669746174696f6e2d70726f6f660000013a00204f70656e4d696e69732f50726f746f747970652f76312f68616e647368616b650000000101000000100102030405060708090a0b0c0d0e0f100000002011111111111111111111111111111111111111111111111111111111111111110000005b3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5000000202222222222222222222222222222222222222222222222222222222222222222000000203333333333333333333333333333333333333333333333333333333333333333000000101112131415161718191a1b1c1d1e1f200000001000000000000000000000000000000000000000080000000000000000000000204444444444444444444444444444444444444444444444444444444444444444000000407cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978b171f6a2a3be8d112b5ccb2b09abe46d2cbbc6937adf46e1220ed3f2fe2aa5b7")
    static let secretProof = bytes("4cbc837ef3b88a17e541e26d292887511dc0fd4308e49573de382d0852230626")
    static let claim = bytes("7eda802b614ae82f2daf54810c90ec20b90b556e9d517e610d0e51f36c65837a")
    static let sasNonce = bytes("0000000000000000000000000000000000000000000000000000000000000006")
    static let sas = bytes("de2cde0001c21d3b021fc5cb9a85e292af51159bb647f829fc9d8b33706cac37")
    static let code = "06135611"
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
