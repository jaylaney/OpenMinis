import Foundation
import Network
import Security
import CryptoKit

public enum StatusTLSError: Error, Equatable, Sendable {
    case invalidPin, unsupportedIdentity, incompatibleTLS, exporterUnavailable, invalidContext
    case unavailableAddress, closed, busy, invalidSize, timedOut
}

/// Explicit key-pin policy. System CA, hostname and certificate date validation are
/// intentionally replaced by possession of the selected P256 key in TLS 1.3.
public enum PinnedTLS {
    public static let applicationProtocol = "openminis-prototype/1"
    private static let verificationQueue = DispatchQueue(label: "org.openminis.prototype.pin")

    public static func clientOptions(pin: Data) throws -> NWProtocolTLS.Options {
        guard pin.count == 32 else { throw StatusTLSError.invalidPin }
        let options = baseOptions()
        sec_protocol_options_set_peer_authentication_required(options.securityProtocolOptions, true)
        sec_protocol_options_set_verify_block(options.securityProtocolOptions, { _, trust, complete in
            let nativeTrust = sec_trust_copy_ref(trust).takeRetainedValue()
            guard let chain = SecTrustCopyCertificateChain(nativeTrust) as? [SecCertificate],
                  let certificate = chain.first else { complete(false); return }
            complete(matches(certificate: certificate, pin: pin))
        }, verificationQueue)
        return options
    }

    public static func serverOptions(identity: SecIdentity) throws -> NWProtocolTLS.Options {
        guard let native = sec_identity_create(identity) else { throw StatusTLSError.unsupportedIdentity }
        let options = baseOptions()
        sec_protocol_options_set_local_identity(options.securityProtocolOptions, native)
        // Controller authentication is the later exporter-bound application proof.
        sec_protocol_options_set_peer_authentication_required(options.securityProtocolOptions, false)
        return options
    }

    private static func baseOptions() -> NWProtocolTLS.Options {
        let options = NWProtocolTLS.Options()
        let native = options.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(native, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(native, .TLSv13)
        sec_protocol_options_add_tls_application_protocol(native, applicationProtocol)
        sec_protocol_options_set_tls_resumption_enabled(native, false)
        sec_protocol_options_set_tls_tickets_enabled(native, false)
        // TLS 1.3 early data requires a PSK/resumption. Neither is configured.
        // No application send is allowed until ready; metadata also refuses 0-RTT.
        sec_protocol_options_set_tls_false_start_enabled(native, false)
        return options
    }

    static func matches(certificate: SecCertificate, pin: Data) -> Bool {
        guard pin.count == 32, let key = SecCertificateCopyKey(certificate),
              let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
              let representation = SecKeyCopyExternalRepresentation(key, nil),
              let publicKey = try? P256.Signing.PublicKey(x963Representation: representation as Data) else { return false }
        // Security parses the certificate algorithm/curve; CryptoKit validates the
        // uncompressed P256 point. Its DER output is the complete canonical SPKI.
        let spki = publicKey.derRepresentation
        guard spki.count == 91 else { return false }
        return Data(SHA256.hash(data: spki)) == pin
    }
}
