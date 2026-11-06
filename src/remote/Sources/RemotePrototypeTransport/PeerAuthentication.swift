import Foundation
import CryptoKit
import Security
import RemotePrototypeWire

public enum PeerAuthenticationError: Error, Equatable, Sendable { case invalidProof }

/// Pure proof cryptography: no sockets, persistence, admission, or acceptance state.
public enum PeerAuthentication {
    public static func verify(transcript: AuthTranscript, exporter: Data, proof: Proof, invitationSecret: Data?) throws {
        try proof.validate(mode: transcript.hello.mode)
        let message = try transcript.controllerProofBytes(exporter: exporter)
        try validateSecret(invitationSecret, mode: transcript.hello.mode)
        guard validScalar(Data(proof.signature.prefix(32))), validScalar(Data(proof.signature.suffix(32))) else {
            throw PeerAuthenticationError.invalidProof
        }
        let key = try P256.Signing.PublicKey(x963Representation: transcript.hello.controllerPoint)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: proof.signature)
        // Message overload hashes once; accepts either mathematically valid S form.
        guard key.isValidSignature(signature, for: message) else { throw PeerAuthenticationError.invalidProof }
        if let secret = invitationSecret {
            let bytes = try transcript.invitationProofBytes(exporter: exporter, signature: proof.signature)
            guard HMAC<SHA256>.isValidAuthenticationCode(proof.secretProof, authenticating: bytes, using: SymmetricKey(data: secret)) else {
                throw PeerAuthenticationError.invalidProof
            }
        }
    }

    public static func makeProof(transcript: AuthTranscript, exporter: Data, key: SecKey, invitationSecret: Data?) throws -> Proof {
        try validateSecret(invitationSecret, mode: transcript.hello.mode)
        let message = try transcript.controllerProofBytes(exporter: exporter)
        guard let publicKey = SecKeyCopyPublicKey(key),
              let point = SecKeyCopyExternalRepresentation(publicKey, nil),
              point as Data == transcript.hello.controllerPoint,
              SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256),
              let der = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, nil) else {
            throw PeerAuthenticationError.invalidProof
        }
        let signature = try P256.Signing.ECDSASignature(derRepresentation: der as Data).rawRepresentation
        let secretProof: Data
        if let secret = invitationSecret {
            secretProof = Data(HMAC<SHA256>.authenticationCode(
                for: try transcript.invitationProofBytes(exporter: exporter, signature: signature),
                using: SymmetricKey(data: secret)))
        } else {
            secretProof = Data(count: 32)
        }
        let proof = try Proof(signature: signature, secretProof: secretProof)
        try proof.validate(mode: transcript.hello.mode)
        return proof
    }

    private static func validateSecret(_ secret: Data?, mode: HandshakeMode) throws {
        switch mode {
        case .enrollment:
            guard secret?.count == 32 else { throw PeerAuthenticationError.invalidProof }
        case .normal:
            guard secret == nil else { throw PeerAuthenticationError.invalidProof }
        }
    }

    private static func validScalar(_ scalar: Data) -> Bool {
        // P256 order n; accept 1 <= scalar < n, with no low-S restriction.
        let order = Data([0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                          0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51])
        return scalar.count == 32 && scalar.contains(where: { $0 != 0 }) && scalar.lexicographicallyPrecedes(order)
    }
}
