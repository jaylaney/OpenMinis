import Foundation

public enum WireFrame: Equatable, Sendable {
    case hello(Hello), challenge(Challenge), proof(Proof), candidateAccepted(CandidateAccepted)
    case enrollmentCommitted(EnrollmentCommitted), authenticated(Authenticated), statusRequest
    case statusResponse(StatusResponse), refused(Refused)

    public func encode() throws -> Data {
        let type: UInt8
        let payload: Data
        switch self {
        case .hello(let m): type = 0x01; payload = Data([m.mode.rawValue]) + m.hostID.wireBytes + m.hostPin + m.controllerPoint + m.clientNonce + m.invitationID.wireBytes
        case .challenge(let m): type = 0x02; payload = m.serverNonce + m.controllerID.wireBytes + uintBytes(m.generation, count: 8)
        case .proof(let m): type = 0x03; payload = m.signature + m.secretProof
        case .candidateAccepted(let m): type = 0x04; payload = m.claimDigest + m.sasNonce
        case .enrollmentCommitted(let m): type = 0x05; payload = m.claimDigest + m.controllerID.wireBytes + uintBytes(m.generation, count: 8)
        case .authenticated(let m): type = 0x06; payload = m.controllerID.wireBytes + uintBytes(m.generation, count: 8)
        case .statusRequest: type = 0x10; payload = Data()
        case .statusResponse(let m): type = 0x11; payload = m.storageEpoch.wireBytes + Data([0])
        case .refused(let m): type = 0x7f; payload = Data([m.reason.rawValue])
        }
        return uintBytes(UInt64(payload.count + 1), count: 4) + Data([type]) + payload
    }

    static func decode(_ body: Data) throws -> WireFrame {
        var reader = WireReader(body)
        let type = try reader.integer(1)
        let lengths: [UInt64: Int] = [1:162, 2:56, 3:96, 4:64, 5:56, 6:24, 0x10:0, 0x11:17, 0x7f:1]
        guard let length = lengths[type] else { throw WireError.unknownType }
        guard body.count == length + 1 else { throw WireError.invalidLength }
        switch type {
        case 1:
            guard let mode = HandshakeMode(rawValue: UInt8(try reader.integer(1))) else { throw WireError.invalidValue }
            return .hello(try Hello(mode: mode, hostID: reader.id(), hostPin: reader.take(32), controllerPoint: reader.take(65), clientNonce: reader.take(32), invitationID: reader.id()))
        case 2: return .challenge(try Challenge(serverNonce: reader.take(32), controllerID: reader.id(), generation: reader.integer(8)))
        case 3: return .proof(try Proof(signature: reader.take(64), secretProof: reader.take(32)))
        case 4: return .candidateAccepted(try CandidateAccepted(claimDigest: reader.take(32), sasNonce: reader.take(32)))
        case 5: return .enrollmentCommitted(try EnrollmentCommitted(claimDigest: reader.take(32), controllerID: reader.id(), generation: reader.integer(8)))
        case 6: return .authenticated(try Authenticated(controllerID: reader.id(), generation: reader.integer(8)))
        case 0x10: return .statusRequest
        case 0x11:
            let epoch = try reader.id()
            guard try reader.integer(1) == 0 else { throw WireError.invalidValue }
            return .statusResponse(try StatusResponse(storageEpoch: epoch))
        default:
            guard let reason = Refused.Reason(rawValue: UInt8(try reader.integer(1))) else { throw WireError.invalidValue }
            return .refused(Refused(reason: reason))
        }
    }
}

public struct FrameDecodeStep: Equatable, Sendable {
    public let bytesConsumed: Int
    public let frame: WireFrame?
}

/// Consumes only through one complete frame. The caller must evaluate its state
/// transition before passing any unconsumed suffix back to this decoder.
public struct FrameDecoder: Sendable {
    private var buffer = Data()
    public var bufferedByteCount: Int { buffer.count }
    public init() {}
    public mutating func consume(_ bytes: Data) throws -> FrameDecodeStep {
        var consumed = 0
        if buffer.count < 4 {
            let amount = min(4 - buffer.count, bytes.count)
            buffer.append(contentsOf: bytes.prefix(amount)); consumed += amount
            guard buffer.count == 4 else { return FrameDecodeStep(bytesConsumed: consumed, frame: nil) }
        }
        let length = buffer.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard (1...4096).contains(length) else { throw WireError.invalidLength }
        let total = Int(length) + 4
        let amount = min(total - buffer.count, bytes.count - consumed)
        buffer.append(contentsOf: bytes.dropFirst(consumed).prefix(amount)); consumed += amount
        guard buffer.count == total else { return FrameDecodeStep(bytesConsumed: consumed, frame: nil) }
        let frame = try WireFrame.decode(Data(buffer.dropFirst(4)))
        buffer.removeAll(keepingCapacity: false)
        return FrameDecodeStep(bytesConsumed: consumed, frame: frame)
    }
}
