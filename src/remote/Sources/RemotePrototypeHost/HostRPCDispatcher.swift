#if os(macOS)
import Foundation
import RemoteExecutionCore
import RemotePrototypeWire
import RemotePrototypeTransport

/// Trusted local presentation. Descriptions intentionally contain no secret data.
public struct HostCandidatePresentation: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let candidateID: UUID
    public let comparisonCode: String
    public init(candidateID: UUID, comparisonCode: String) { self.candidateID = candidateID; self.comparisonCode = comparisonCode }
    public var description: String { "HostCandidatePresentation(redacted)" }
    public var debugDescription: String { description }
}
public struct HostPresentation: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let isEnabled: Bool
    public let isListening: Bool
    public let invitation: Invitation?
    public let candidate: HostCandidatePresentation?
    public init(isEnabled: Bool, isListening: Bool, invitation: Invitation?, candidate: HostCandidatePresentation?) {
        self.isEnabled = isEnabled; self.isListening = isListening; self.invitation = invitation; self.candidate = candidate
    }
    public var description: String { "HostPresentation(enabled: \(isEnabled), listening: \(isListening), secrets: redacted)" }
    public var debugDescription: String { description }
}

/// The only remote dispatch path. It holds opaque Core contexts/leases and
/// verifies the exact exporter-bound transcript before presenting them to Core.
public actor HostRPCDispatcher {
    private enum Phase { case hello, working, proof(AuthTranscript, StatusHandshakeContext, UUID?), authenticated(StatusControllerLease) }
    private struct Session { let channel: StatusTLSChannel; var phase: Phase }
    private struct Candidate { let accepted: StatusAcceptedCandidate; let code: String; let provenance: UUID }
    private let host: TrustedStatusHostHandle
    private let controller: StatusControllerHandle
    private let fence: ServiceFence
    private let pump: ConnectionPump
    private let endpoint: StatusEndpoint
    private let onChange: @Sendable () -> Void
    private var sessions: [UUID: Session] = [:]
    private var activeConnection: UUID?
    private var proofTransition: UUID?
    private var window: StatusEnrollmentWindow?
    private var enrollmentProvenance: UUID?
    private var openingEnrollment: UUID?
    private var candidate: Candidate?
    private var presentationToken = UUID()
    private func changed() { presentationToken = UUID(); onChange() }

    init(handles: StatusOnlyHostHandles, fence: ServiceFence, pump: ConnectionPump,
         endpoint: StatusEndpoint, onChange: @escaping @Sendable () -> Void) {
        host = handles.host; controller = handles.controller; self.fence = fence
        self.pump = pump; self.endpoint = endpoint; self.onChange = onChange
    }
    func register(_ channel: StatusTLSChannel) throws {
        try check()
        guard sessions[channel.connectionID] == nil else { throw HostBridgeError.refused }
        sessions[channel.connectionID] = Session(channel: channel, phase: .hello)
    }
    private func check() throws { guard !fence.isDisabled else { throw HostBridgeError.disabled } }
    private func live(_ id: UUID) throws -> Session {
        try check(); guard let session = sessions[id] else { throw HostBridgeError.refused }; return session
    }
    private func requireEnrollment(_ provenance: UUID?) throws -> UUID {
        guard let provenance, enrollmentProvenance == provenance else { throw HostBridgeError.refused }
        return provenance
    }
    public func handle(_ frame: WireFrame, connectionID id: UUID) async throws -> WireFrame? {
        do {
            let session = try live(id)
            switch (session.phase, frame) {
            case (.hello, .hello(let hello)):
                let provenance = hello.mode == .enrollment ? enrollmentProvenance : nil
                if hello.mode == .enrollment {
                    _ = try requireEnrollment(provenance)
                    guard window?.invitationID == hello.invitationID else { throw HostBridgeError.refused }
                }
                sessions[id]?.phase = .working
                let context = try await host.beginHandshake(StatusHandshakeInput(
                    connectionID: id, acceptedAtNanoseconds: session.channel.acceptedAtNanoseconds,
                    mode: hello.mode == .enrollment ? .enrollment : .normal,
                    hostID: hello.hostID, hostPin: hello.hostPin, controllerSPKI: hello.controllerSPKI,
                    clientNonce: hello.clientNonce, invitationID: hello.invitationID))
                _ = try live(id)
                if hello.mode == .enrollment { _ = try requireEnrollment(provenance) }
                let challenge = try Challenge(serverNonce: context.serverNonce, controllerID: context.controllerID, generation: context.generation)
                let transcript = try AuthTranscript(hello: hello, challenge: challenge)
                sessions[id]?.phase = .proof(transcript, context, provenance)
                try check(); return .challenge(challenge)
            case (.proof(let transcript, let context, let provenance), .proof(let proof)):
                // Do not submit concurrent owner authority transitions: serial
                // owner completion order need not equal actor resumption order.
                // Busy overlap closes only that pending connection; no queue.
                guard proofTransition == nil else { throw HostBridgeError.refused }
                let transition = UUID()
                proofTransition = transition
                defer { if proofTransition == transition { proofTransition = nil } }
                sessions[id]?.phase = .working
                let exporter: Data
                do {
                    exporter = try session.channel.exporter(context: transcript.exporterContext())
                    try PeerAuthentication.verify(transcript: transcript, exporter: exporter, proof: proof, invitationSecret: context.invitationSecret)
                } catch {
                    try await host.recordProofFailure(contextID: context.contextID)
                    throw HostBridgeError.refused
                }
                _ = try live(id)
                if transcript.hello.mode == .enrollment {
                    let provenance = try requireEnrollment(provenance)
                    guard let window, let secret = context.invitationSecret else { throw HostBridgeError.refused }
                    let digest = try transcript.claimDigest(exporter: exporter, signature: proof.signature, secretProof: proof.secretProof)
                    let accepted = try await host.acceptCandidate(contextID: context.contextID, claimDigest: digest)
                    _ = try live(id)
                    _ = try requireEnrollment(provenance)
                    self.window = nil // consume only this operation's presentation
                    changed()
                    try pump.retainCandidate(connectionID: id, untilNanoseconds: window.deadlineNanoseconds)
                    // Send completion is the publication boundary for local confirm.
                    try check()
                    try await pump.send(.candidateAccepted(try CandidateAccepted(claimDigest: accepted.claimDigest, sasNonce: accepted.sasNonce)), over: id)
                    _ = try live(id)
                    _ = try requireEnrollment(provenance)
                    candidate = Candidate(accepted: accepted, code: try comparisonCode(secret: secret, claimDigest: accepted.claimDigest, sasNonce: accepted.sasNonce), provenance: provenance)
                    self.window = nil
                    changed()
                    return nil
                } else {
                    let lease = try await host.authenticate(contextID: context.contextID)
                    _ = try live(id)
                    if let old = activeConnection, old != id {
                        pump.close(connectionID: old)
                        sessions.removeValue(forKey: old)
                    }
                    activeConnection = id
                    sessions[id]?.phase = .authenticated(lease)
                    try check()
                    return .authenticated(try Authenticated(controllerID: context.controllerID, generation: context.generation))
                }
            case (.authenticated(let lease), .statusRequest):
                sessions[id]?.phase = .working
                let snapshot = try await controller.status(over: lease)
                _ = try live(id)
                guard activeConnection == id else { throw HostBridgeError.refused }
                sessions[id]?.phase = .authenticated(lease)
                try check(); return .statusResponse(try StatusResponse(storageEpoch: snapshot.storageEpoch))
            default: throw HostBridgeError.refused
            }
        } catch {
            pump.close(connectionID: id)
            await disconnected(id)
            // Storage diagnostics and cryptographic material never cross the wire.
            throw fence.isDisabled ? HostBridgeError.disabled : HostBridgeError.refused
        }
    }
    func openEnrollment() async throws -> Invitation {
        try check()
        // A failed concurrent local open must not invalidate a live window, and
        // an older successful open cannot publish after a newer local operation.
        guard openingEnrollment == nil else { throw StatusHostError.invalidHandshake }
        let opening = UUID(); openingEnrollment = opening
        defer { if openingEnrollment == opening { openingEnrollment = nil } }
        let opened = try await host.openEnrollment()
        try check()
        guard openingEnrollment == opening else { throw HostBridgeError.refused }
        enrollmentProvenance = UUID()
        window = opened; candidate = nil
        changed()
        return try Invitation(endpoint: endpoint, hostID: opened.hostID, hostPin: opened.hostPin,
                              invitationID: opened.invitationID, secret: opened.secret)
    }
    func confirmCandidate(candidateID: UUID) async throws {
        try check()
        guard let candidate, candidate.accepted.candidateID == candidateID else { throw StatusHostError.invalidCandidate }
        let id = candidate.accepted.connectionID
        _ = try live(id)
        _ = try requireEnrollment(candidate.provenance)
        self.candidate = nil; changed()
        try await host.confirmCandidate(candidateID: candidateID)
        _ = try live(id)
        // Successful commit makes a subsequent fresh enrollment impossible.
        // Core-closed presentation cleanup may now drop transient provenance;
        // the exact durable success, fence and live session govern this ACK.
        let snapshot = try await host.localStatus().snapshot
        _ = try live(id)
        do {
            try await pump.send(.enrollmentCommitted(try EnrollmentCommitted(claimDigest: candidate.accepted.claimDigest,
                controllerID: snapshot.controllerID, generation: snapshot.controllerGeneration)), over: id)
        } catch { await disconnected(id); throw HostBridgeError.refused }
    }
    func rejectCandidate(candidateID: UUID) async throws {
        try check()
        guard let candidate, candidate.accepted.candidateID == candidateID else { throw StatusHostError.invalidCandidate }
        _ = try requireEnrollment(candidate.provenance)
        self.candidate = nil; window = nil; enrollmentProvenance = nil
        pump.close(connectionID: candidate.accepted.connectionID); changed()
        try await host.rejectCandidate(candidateID: candidateID)
    }
    func disconnected(_ id: UUID) async {
        sessions.removeValue(forKey: id)
        if activeConnection == id { activeConnection = nil }
        if candidate?.accepted.connectionID == id { candidate = nil; window = nil; enrollmentProvenance = nil; changed() }
        await host.disconnect(connectionID: id)
    }
    func clear() {
        sessions.removeAll(); activeConnection = nil; proofTransition = nil; window = nil; candidate = nil; enrollmentProvenance = nil; openingEnrollment = nil; changed()
    }
    func presentation(listening: Bool) async -> HostPresentation {
        guard !fence.isDisabled else { return HostPresentation(isEnabled: false, isListening: false, invitation: nil, candidate: nil) }
        let token = presentationToken
        // Core owns expiry. A presentation read asks that owner rather than
        // extending/reconstructing policy deadlines in a second authority.
        let local = try? await host.localStatus()
        if token == presentationToken, let local {
            if local.enrollment == .closed, window != nil || candidate != nil || enrollmentProvenance != nil {
                if let candidate { pump.close(connectionID: candidate.accepted.connectionID) }
                window = nil; candidate = nil; enrollmentProvenance = nil; changed()
            } else if local.enrollment == .candidate, window != nil {
                window = nil; changed()
            }
        }
        guard !fence.isDisabled else { return HostPresentation(isEnabled: false, isListening: false, invitation: nil, candidate: nil) }
        let invitation = window.flatMap { try? Invitation(endpoint: endpoint, hostID: $0.hostID, hostPin: $0.hostPin, invitationID: $0.invitationID, secret: $0.secret) }
        let visible = candidate.map { HostCandidatePresentation(candidateID: $0.accepted.candidateID, comparisonCode: $0.code) }
        return HostPresentation(isEnabled: true, isListening: listening, invitation: invitation, candidate: visible)
    }
}
#endif
