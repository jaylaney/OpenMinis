#if os(macOS)
import Foundation
import CryptoKit
import Security
import XCTest
import RemotePrototypeCertificates

final class HostCertificateTests: XCTestCase {
    // Catches certificates using a generated replacement key, or pins bound to certificate bytes.
    func testSameKeyCertificateKeepsPin() throws {
        let key = try fixtureKey(1)
        let first = try HostCertificate.makeIdentity(key: key, now: Date(timeIntervalSince1970: 1_700_000_000))
        let second = try HostCertificate.makeIdentity(key: key, now: Date(timeIntervalSince1970: 1_700_100_000))
        let expectedPoint = try point(key)
        let firstCertificate = try certificate(first)
        let secondCertificate = try certificate(second)
        XCTAssertEqual(try point(XCTUnwrap(SecCertificateCopyKey(firstCertificate))), expectedPoint)
        XCTAssertEqual(try point(XCTUnwrap(SecCertificateCopyKey(secondCertificate))), expectedPoint)
        let prefix = Data([0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00])
        XCTAssertEqual(Data(SHA256.hash(data: prefix + expectedPoint)).map { String(format: "%02x", $0) }.joined(), "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3")
        XCTAssertNotEqual(SecCertificateCopyData(firstCertificate) as Data, SecCertificateCopyData(secondCertificate) as Data)
        var privateKey: SecKey?
        XCTAssertEqual(SecIdentityCopyPrivateKey(first, &privateKey), errSecSuccess)
        XCTAssertEqual(try point(XCTUnwrap(privateKey)), expectedPoint)
        let other = try HostCertificate.makeIdentity(key: fixtureKey(2), now: Date(timeIntervalSince1970: 1_700_000_000))
        XCTAssertNotEqual(try point(XCTUnwrap(SecCertificateCopyKey(certificate(other)))), expectedPoint)
    }

    // Catches acceptance of public keys and non-P256 private keys as TLS identities.
    func testRejectsUnsupportedOrPublicKey() throws {
        let privateKey = try fixtureKey(1)
        XCTAssertThrowsError(try HostCertificate.makeIdentity(key: XCTUnwrap(SecKeyCopyPublicKey(privateKey)), now: Date()))
        let p384 = try XCTUnwrap(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 384] as CFDictionary, nil))
        XCTAssertThrowsError(try HostCertificate.makeIdentity(key: p384, now: Date()))
    }

    private func fixtureKey(_ scalar: UInt8) throws -> SecKey {
        let bytes = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0, count: 31) + Data([scalar])).x963Representation
        return try XCTUnwrap(SecKeyCreateWithData(bytes as CFData, [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 256] as CFDictionary, nil))
    }
    private func point(_ key: SecKey) throws -> Data {
        let publicKey = SecKeyCopyPublicKey(key) ?? key
        return try XCTUnwrap(SecKeyCopyExternalRepresentation(publicKey, nil)) as Data
    }
    private func certificate(_ identity: SecIdentity) throws -> SecCertificate {
        var certificate: SecCertificate?
        XCTAssertEqual(SecIdentityCopyCertificate(identity, &certificate), errSecSuccess)
        return try XCTUnwrap(certificate)
    }
}
#endif
