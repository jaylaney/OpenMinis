#if os(macOS)
import Foundation
import Security
import X509

public enum HostCertificateError: Error, Equatable, Sendable {
    case unsupportedKey
    case identityConstructionFailed
}

/// Mac-only self-signed TLS certificate. No Keychain or trust-store operations.
public enum HostCertificate {
    public static func makeIdentity(key: SecKey, now: Date) throws -> SecIdentity {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrKeyClass as String] as? String == kSecAttrKeyClassPrivate as String,
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
              SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256) else {
            throw HostCertificateError.unsupportedKey
        }
        // X509 wraps SecKey and signs through Security; private key bytes are never exported.
        let privateKey = try Certificate.PrivateKey(key)
        let name = try DistinguishedName { CommonName("OpenMinis Prototype") }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: privateKey.publicKey,
            notValidBefore: now.addingTimeInterval(-300),
            notValidAfter: now.addingTimeInterval(86_400 * 30),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
                try ExtendedKeyUsage([.serverAuth])
            },
            issuerPrivateKey: privateKey
        )
        let secCertificate = try SecCertificate.makeWithCertificate(certificate)
        guard let identity = SecIdentityCreate(nil, secCertificate, key) else {
            throw HostCertificateError.identityConstructionFailed
        }
        return identity
    }
}
#endif
