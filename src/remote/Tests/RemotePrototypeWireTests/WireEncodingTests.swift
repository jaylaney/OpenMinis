import Foundation
import XCTest
@testable import RemotePrototypeWire

final class WireEncodingTests: XCTestCase {
    let id = UUID(uuidString: "01020304-0506-0708-090a-0b0c0d0e0f10")!
    let invitationID = UUID(uuidString: "11121314-1516-1718-191a-1b1c1d1e1f20")!
    let point = hex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    // Independent, display-order UUID and fixed wire layout fixtures.
    var vectors: [Data] { [
        hex("000000a301010102030405060708090a0b0c0d0e0f101111111111111111111111111111111111111111111111111111111111111111046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f522222222222222222222222222222222222222222222222222222222222222221112131415161718191a1b1c1d1e1f20"),
        hex("0000003902" + String(repeating: "22", count: 32) + String(repeating: "00", count: 24)),
        hex("0000006103" + String(repeating: "33", count: 64) + String(repeating: "00", count: 32)),
        hex("0000004104" + String(repeating: "11", count: 32) + String(repeating: "22", count: 32)),
        hex("0000003905" + String(repeating: "11", count: 32) + "0102030405060708090a0b0c0d0e0f100000000000000001"),
        hex("00000019060102030405060708090a0b0c0d0e0f100000000000000001"),
        hex("0000000110"), hex("00000012110102030405060708090a0b0c0d0e0f1000"), hex("000000027f01")
    ] }

    func testExactGoldenFrames() throws {
        let frames: [WireFrame] = [
            .hello(try Hello(mode: .enrollment, hostID: id, hostPin: Data(repeating: 0x11, count: 32), controllerPoint: point, clientNonce: Data(repeating: 0x22, count: 32), invitationID: invitationID)),
            .challenge(try Challenge(serverNonce: Data(repeating: 0x22, count: 32), controllerID: .zero, generation: 0)),
            .proof(try Proof(signature: Data(repeating: 0x33, count: 64), secretProof: Data(repeating: 0, count: 32))),
            .candidateAccepted(try CandidateAccepted(claimDigest: Data(repeating: 0x11, count: 32), sasNonce: Data(repeating: 0x22, count: 32))),
            .enrollmentCommitted(try EnrollmentCommitted(claimDigest: Data(repeating: 0x11, count: 32), controllerID: id, generation: 1)),
            .authenticated(try Authenticated(controllerID: id, generation: 1)), .statusRequest,
            .statusResponse(try StatusResponse(storageEpoch: id)), .refused(Refused(reason: .generic))
        ]
        for (frame, vector) in zip(frames, vectors) {
            XCTAssertEqual(try frame.encode(), vector)
            var decoder = FrameDecoder()
            let step = try decoder.consume(vector)
            XCTAssertEqual(step.frame, frame)
            XCTAssertEqual(step.bytesConsumed, vector.count)
        }
    }

    func testSplitAndCoalescedAuthenticationFrames() throws {
        for vector in vectors {
            for split in 0...vector.count {
                var decoder = FrameDecoder()
                let first = try decoder.consume(Data(vector.prefix(split)))
                XCTAssertEqual(first.bytesConsumed, split)
                let second = try decoder.consume(Data(vector.dropFirst(split)))
                XCTAssertEqual(second.bytesConsumed, vector.count - split)
                XCTAssertNotNil(first.frame ?? second.frame)
                XCTAssertLessThanOrEqual(decoder.bufferedByteCount, 4100)
            }
        }
        let joined = vectors[3] + vectors[4]
        var decoder = FrameDecoder()
        let first = try decoder.consume(joined)
        XCTAssertEqual(first.bytesConsumed, 69)
        XCTAssertEqual(try first.frame?.encode(), vectors[3])
        let second = try decoder.consume(Data(joined.dropFirst(first.bytesConsumed)))
        XCTAssertEqual(second.bytesConsumed, 61)
        XCTAssertEqual(try second.frame?.encode(), vectors[4])
    }

    func testBoundedAndCanonical() throws {
        for bad in [hex("00000000"), hex("00001001"), hex("000000017e"), hex("000000021000"), hex("000000027f00")] {
            var decoder = FrameDecoder()
            XCTAssertThrowsError(try decoder.consume(bad + Data(repeating: 0, count: 10000)))
            XCTAssertLessThanOrEqual(decoder.bufferedByteCount, 4100)
        }
        var badStatus = vectors[7]; badStatus[badStatus.count - 1] = 1
        var decoder = FrameDecoder(); XCTAssertThrowsError(try decoder.consume(badStatus))
        XCTAssertThrowsError(try Hello(mode: .normal, hostID: id, hostPin: Data(count: 32), controllerPoint: point, clientNonce: Data(count: 32), invitationID: id))
        XCTAssertThrowsError(try Hello(mode: .enrollment, hostID: id, hostPin: Data(count: 32), controllerPoint: Data(count: 65), clientNonce: Data(count: 32), invitationID: id))
        XCTAssertThrowsError(try Challenge(serverNonce: Data(count: 32), controllerID: id, generation: 0))
        XCTAssertThrowsError(try Authenticated(controllerID: .zero, generation: 1))
        XCTAssertThrowsError(try Authenticated(controllerID: id, generation: UInt64(Int64.max) + 1))
        XCTAssertNoThrow(try Authenticated(controllerID: id, generation: UInt64(Int64.max)))
        let normal = try Hello(mode: .normal, hostID: id, hostPin: Data(count: 32), controllerPoint: point, clientNonce: Data(count: 32), invitationID: .zero)
        XCTAssertEqual(normal.controllerSPKI, hex("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"))
        XCTAssertThrowsError(try Challenge(serverNonce: Data(count: 32), controllerID: .zero, generation: 1))
        XCTAssertThrowsError(try Challenge(serverNonce: Data(count: 32), controllerID: .zero, generation: 0).validate(mode: .normal))
        XCTAssertThrowsError(try Challenge(serverNonce: Data(count: 32), controllerID: id, generation: 1).validate(mode: .enrollment))
        XCTAssertThrowsError(try Hello(mode: .enrollment, hostID: .zero, hostPin: Data(count: 32), controllerPoint: point, clientNonce: Data(count: 32), invitationID: id))
        XCTAssertThrowsError(try Hello(mode: .enrollment, hostID: id, hostPin: Data(count: 31), controllerPoint: point, clientNonce: Data(count: 32), invitationID: id))
        XCTAssertThrowsError(try StatusResponse(storageEpoch: .zero))
        var partial = FrameDecoder()
        let step = try partial.consume(hex("00001000") + Data(repeating: 0, count: 4095))
        XCTAssertNil(step.frame); XCTAssertEqual(step.bytesConsumed, 4099); XCTAssertEqual(partial.bufferedByteCount, 4099)
        XCTAssertThrowsError(try partial.consume(Data(repeating: 0, count: 10000)))
        XCTAssertEqual(partial.bufferedByteCount, 4100)
        // Normal generation, UUID and status capability must also fail on decode.
        for bad in [hex("00000019060102030405060708090a0b0c0d0e0f100000000000000000"),
                    hex("00000019060102030405060708090a0b0c0d0e0f108000000000000000"),
                    hex("00000012110000000000000000000000000000000000")] {
            var invalid = FrameDecoder(); XCTAssertThrowsError(try invalid.consume(bad))
        }
        XCTAssertThrowsError(try Proof(signature: Data(count: 64), secretProof: Data(repeating: 1, count: 32)).validate(mode: .normal))
    }

    func testInvitation103Bytes() throws {
        let golden = "omstatus1:AWRAAAHAAAECAwQFBgcICQoLDA0ODxARERERERERERERERERERERERERERERERERERERERERERESExQVFhcYGRobHB0eHyAiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg"
        let invitation = try Invitation(endpoint: StatusEndpoint(ipv4: "100.64.0.1", port: 49152), hostID: id, hostPin: Data(repeating: 0x11, count: 32), invitationID: invitationID, secret: Data(repeating: 0x22, count: 32))
        XCTAssertEqual(try invitation.encode(), golden)
        XCTAssertEqual(try Invitation.decode(golden), invitation)
        for text in [golden + "=", golden + " ", " " + golden, String(golden.dropLast()) + "+", String(golden.dropLast()), golden + "A"] { XCTAssertThrowsError(try Invitation.decode(text)) }
        // Reject noncanonical unused base64 bits, invalid version, bad endpoint and zero IDs.
        let raw = Data(base64Encoded: String(golden.dropFirst(10)) + "==")!
        for (offset, value) in [(0, UInt8(2)), (1, 99), (5, 0), (6, 0)] {
            var bad = raw; bad[offset] = value
            if offset == 5 || offset == 6 { bad[5] = 0; bad[6] = 0 }
            let text = "omstatus1:" + bad.base64EncodedString().replacingOccurrences(of: "=", with: "").replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            XCTAssertThrowsError(try Invitation.decode(text))
        }
        // Both non-placeholder IDs must reject an actual all-zero 16-byte mutation.
        for range in [7..<23, 55..<71] {
            var bad = raw; bad.replaceSubrange(range, with: Data(count: 16))
            let text = "omstatus1:" + bad.base64EncodedString().replacingOccurrences(of: "=", with: "").replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            XCTAssertEqual(text.count, golden.count)
            XCTAssertThrowsError(try Invitation.decode(text))
        }
        XCTAssertThrowsError(try Invitation.decode(String(golden.dropLast()) + "h"))
        for ip in ["100.63.0.1", "100.128.0.1", "127.0.0.1", "100.064.0.1", "100.64.0.1 ", "host", "::1", "100.64.0.256"] { XCTAssertThrowsError(try StatusEndpoint(ipv4: ip, port: 49152)) }
        XCTAssertThrowsError(try StatusEndpoint(ipv4: "100.64.0.1", port: 1023))
        XCTAssertNoThrow(try StatusEndpoint(ipv4: "100.127.255.255", port: 65535))
    }
}

private func hex(_ text: String) -> Data {
    let chars = Array(text); return Data(stride(from: 0, to: chars.count, by: 2).map { UInt8(String(chars[$0...$0 + 1]), radix: 16)! })
}
