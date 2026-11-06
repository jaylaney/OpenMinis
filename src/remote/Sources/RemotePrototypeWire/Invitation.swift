import Foundation

public struct StatusEndpoint: Equatable, Sendable {
    public let ipv4: String
    public let port: UInt16
    var addressBytes: Data { Data(ipv4.split(separator: ".").map { UInt8($0)! }) }
    public init(ipv4: String, port: UInt16) throws {
        let components = ipv4.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 4, port >= 1024 else { throw WireError.invalidValue }
        let values = components.compactMap { component -> UInt8? in
            guard !component.isEmpty, component.utf8.allSatisfy({ (48...57).contains($0) }), let value = UInt8(component), String(value) == component else { return nil }; return value
        }
        guard values.count == 4, values[0] == 100, (64...127).contains(values[1]) else { throw WireError.invalidValue }
        self.ipv4 = ipv4; self.port = port
    }
}

public struct Invitation: Equatable, Sendable {
    public let endpoint: StatusEndpoint
    public let hostID: UUID
    public let hostPin: Data
    public let invitationID: UUID
    public let secret: Data
    public init(endpoint: StatusEndpoint, hostID: UUID, hostPin: Data, invitationID: UUID, secret: Data) throws {
        try requireID(hostID); try requireID(invitationID); try requireSize(hostPin, 32); try requireSize(secret, 32)
        self.endpoint = endpoint; self.hostID = hostID; self.hostPin = hostPin; self.invitationID = invitationID; self.secret = secret
    }
    public func encode() throws -> String {
        let binary = Data([1]) + endpoint.addressBytes + uintBytes(UInt64(endpoint.port), count: 2) + hostID.wireBytes + hostPin + invitationID.wireBytes + secret
        return "omstatus1:" + binary.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    public static func decode(_ text: String) throws -> Invitation {
        guard text.hasPrefix("omstatus1:"), text.utf8.count == 148 else { throw WireError.invalidLength }
        let encoded = String(text.dropFirst(10))
        guard encoded.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }),
              let binary = Data(base64Encoded: encoded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + "=="), binary.count == 103 else { throw WireError.invalidValue }
        var reader = WireReader(binary)
        guard try reader.integer(1) == 1 else { throw WireError.invalidValue }
        let address = try reader.take(4).map(String.init).joined(separator: ".")
        let endpoint = try StatusEndpoint(ipv4: address, port: UInt16(reader.integer(2)))
        let value = try Invitation(endpoint: endpoint, hostID: reader.id(), hostPin: reader.take(32), invitationID: reader.id(), secret: reader.take(32))
        guard try value.encode() == text else { throw WireError.invalidValue }
        return value
    }
}
