import Foundation
import CryptoKit

public enum WireError: Error, Equatable, Sendable { case invalidLength, invalidValue, unknownType }
public enum HandshakeMode: UInt8, Sendable { case enrollment = 1, normal = 2 }

extension UUID {
    public static let zero = UUID(uuid: (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0))
    var wireBytes: Data { var value = uuid; return withUnsafeBytes(of: &value) { Data($0) } }
}
func requireSize(_ data: Data, _ count: Int) throws { guard data.count == count else { throw WireError.invalidLength } }
func requireID(_ id: UUID) throws { guard id != .zero else { throw WireError.invalidValue } }
func requireGeneration(_ value: UInt64) throws { guard value > 0, value <= UInt64(Int64.max) else { throw WireError.invalidValue } }
func uintBytes(_ value: UInt64, count: Int) -> Data { Data((0..<count).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }) }

public struct Hello: Equatable, Sendable {
    public let mode: HandshakeMode
    public let hostID: UUID
    public let hostPin: Data
    public let controllerPoint: Data
    public let clientNonce: Data
    public let invitationID: UUID
    public init(mode: HandshakeMode, hostID: UUID, hostPin: Data, controllerPoint: Data, clientNonce: Data, invitationID: UUID) throws {
        try requireID(hostID); try requireSize(hostPin, 32); try requireSize(clientNonce, 32); try requireSize(controllerPoint, 65)
        guard controllerPoint.first == 4 else { throw WireError.invalidValue }
        let key = try P256.Signing.PublicKey(x963Representation: controllerPoint)
        guard key.x963Representation == controllerPoint else { throw WireError.invalidValue }
        if mode == .normal { guard invitationID == .zero else { throw WireError.invalidValue } } else { try requireID(invitationID) }
        self.mode = mode; self.hostID = hostID; self.hostPin = hostPin; self.controllerPoint = controllerPoint; self.clientNonce = clientNonce; self.invitationID = invitationID
    }
    public var controllerSPKI: Data { Data([0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00]) + controllerPoint }
}
public struct Challenge: Equatable, Sendable {
    public let serverNonce: Data
    public let controllerID: UUID
    public let generation: UInt64
    public init(serverNonce: Data, controllerID: UUID, generation: UInt64) throws {
        try requireSize(serverNonce, 32)
        if controllerID == .zero { guard generation == 0 else { throw WireError.invalidValue } } else { try requireGeneration(generation) }
        self.serverNonce = serverNonce; self.controllerID = controllerID; self.generation = generation
    }
    public func validate(mode: HandshakeMode) throws {
        guard (mode == .enrollment) == (controllerID == .zero) else { throw WireError.invalidValue }
    }
}
public struct Proof: Equatable, Sendable {
    public let signature: Data
    public let secretProof: Data
    public init(signature: Data, secretProof: Data) throws { try requireSize(signature, 64); try requireSize(secretProof, 32); self.signature = signature; self.secretProof = secretProof }
    public func validate(mode: HandshakeMode) throws { if mode == .normal && secretProof != Data(count: 32) { throw WireError.invalidValue } }
}
public struct CandidateAccepted: Equatable, Sendable {
    public let claimDigest: Data
    public let sasNonce: Data
    public init(claimDigest: Data, sasNonce: Data) throws { try requireSize(claimDigest, 32); try requireSize(sasNonce, 32); self.claimDigest = claimDigest; self.sasNonce = sasNonce }
}
public struct EnrollmentCommitted: Equatable, Sendable {
    public let claimDigest: Data
    public let controllerID: UUID
    public let generation: UInt64
    public init(claimDigest: Data, controllerID: UUID, generation: UInt64) throws { try requireSize(claimDigest, 32); try requireID(controllerID); try requireGeneration(generation); self.claimDigest = claimDigest; self.controllerID = controllerID; self.generation = generation }
}
public struct Authenticated: Equatable, Sendable {
    public let controllerID: UUID
    public let generation: UInt64
    public init(controllerID: UUID, generation: UInt64) throws { try requireID(controllerID); try requireGeneration(generation); self.controllerID = controllerID; self.generation = generation }
}
public struct StatusResponse: Equatable, Sendable {
    public let storageEpoch: UUID
    public var executionSupported: UInt8 { 0 }
    public init(storageEpoch: UUID) throws { try requireID(storageEpoch); self.storageEpoch = storageEpoch }
}
public struct Refused: Equatable, Sendable {
    public enum Reason: UInt8, Sendable { case generic = 1, unavailable = 2, staleChannel = 3 }
    public let reason: Reason
    public init(reason: Reason) { self.reason = reason }
}

struct WireReader {
    let bytes: Data
    var offset = 0
    init(_ bytes: Data) { self.bytes = Data(bytes) }
    mutating func take(_ count: Int) throws -> Data { guard count >= 0, count <= bytes.count - offset else { throw WireError.invalidLength }; defer { offset += count }; return bytes.subdata(in: offset..<offset + count) }
    mutating func integer(_ count: Int) throws -> UInt64 { try take(count).reduce(0) { ($0 << 8) | UInt64($1) } }
    mutating func id() throws -> UUID { let b = Array(try take(16)); return UUID(uuid: (b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15])) }
}
