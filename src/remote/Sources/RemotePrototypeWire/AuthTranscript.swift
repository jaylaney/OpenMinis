import Foundation
import CryptoKit

/// Immutable wire claims. This value confers no admission, channel, or UI authority.
public struct AuthTranscript: Equatable, Sendable {
    public static let exporterLabel = "EXPORTER-OpenMinis-Prototype-v1"
    public static let exporterLength = 32
    public let hello: Hello
    public let challenge: Challenge

    public init(hello: Hello, challenge: Challenge) throws {
        try challenge.validate(mode: hello.mode)
        self.hello = hello
        self.challenge = challenge
    }

    public func canonicalBytes() throws -> Data {
        try challenge.validate(mode: hello.mode)
        return framed("OpenMinis/Prototype/v1/handshake", [
            Data([hello.mode.rawValue]), hello.hostID.wireBytes, hello.hostPin,
            hello.controllerSPKI, hello.clientNonce, challenge.serverNonce,
            hello.invitationID.wireBytes, challenge.controllerID.wireBytes,
            uintBytes(challenge.generation, count: 8)
        ])
    }

    public func exporterContext() throws -> Data {
        Data(SHA256.hash(data: try canonicalBytes()))
    }

    /// The un-hashed message. The ECDSA message API hashes this exactly once.
    public func controllerProofBytes(exporter: Data) throws -> Data {
        try requireSize(exporter, Self.exporterLength)
        return framed("OpenMinis/Prototype/v1/controller-proof", [try canonicalBytes(), exporter])
    }

    public func invitationProofBytes(exporter: Data, signature: Data) throws -> Data {
        try requireSize(exporter, Self.exporterLength)
        try requireSize(signature, 64)
        return framed("OpenMinis/Prototype/v1/invitation-proof", [try canonicalBytes(), exporter, signature])
    }

    public func claimDigest(exporter: Data, signature: Data, secretProof: Data) throws -> Data {
        try requireSize(exporter, Self.exporterLength)
        let proof = try Proof(signature: signature, secretProof: secretProof)
        try proof.validate(mode: hello.mode)
        return Data(SHA256.hash(data: framed("OpenMinis/Prototype/v1/claim", [try canonicalBytes(), exporter, signature, secretProof])))
    }
}

/// Caller supplies the nonce drawn by the owner only after fixing its accepted claim.
/// Computing this primitive does not mean that the caller's claim has been accepted.
public func comparisonCode(secret: Data, claimDigest: Data, sasNonce: Data) throws -> String {
    try requireSize(secret, 32)
    try requireSize(claimDigest, 32)
    try requireSize(sasNonce, 32)
    let bytes = HMAC<SHA256>.authenticationCode(
        for: framed("OpenMinis/Prototype/v1/comparison", [claimDigest, sasNonce]),
        using: SymmetricKey(data: secret))
    let number = bytes.prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) } % 100_000_000
    let digits = String(number)
    return String(repeating: "0", count: 8 - digits.count) + digits
}

// All callers use fixed ASCII labels and fixed-size validated fields.
private func framed(_ label: String, _ fields: [Data]) -> Data {
    let labelBytes = Data(label.utf8)
    var result = uintBytes(UInt64(labelBytes.count), count: 2) + labelBytes
    for field in fields {
        result.append(uintBytes(UInt64(field.count), count: 4))
        result.append(field)
    }
    return result
}
