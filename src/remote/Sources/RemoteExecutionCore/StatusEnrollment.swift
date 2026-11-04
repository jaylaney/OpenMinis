import Foundation

// All values below belong exclusively to the serial owner. The complete Hello
// (including trusted acceptance time and selected host identity) is fixed once.
struct StatusFixedHandshake: Sendable {
    let input: StatusHandshakeInput
    let deadlineNanoseconds: UInt64
    let policy: StatusStoredPolicy
}

struct StatusOpenEnrollment: Sendable {
    let window: StatusEnrollmentWindow
    var failures: Int = 0
}

struct StatusFixedEnrollmentClaim: Sendable {
    let candidateID: UUID
    let connectionID: UUID
    let controllerSPKI: Data
    let claimDigest: Data
    let deadlineNanoseconds: UInt64
}

extension StatusOnlyOwner.State {
    static let zeroID = UUID(uuid: (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0))

    var enrollmentState: StatusEnrollmentState {
        if fixedEnrollmentClaim != nil { return .candidate }
        return enrollmentWindow == nil ? .closed : .open
    }

    func clearEnrollment() {
        enrollmentWindow = nil
        fixedEnrollmentClaim = nil
        enrollmentCandidate = nil
        handshakeContexts = handshakeContexts.filter { $0.value.input.mode != .enrollment }
    }

    func expireEnrollment() {
        let now = configuration.clock.nowNanoseconds()
        if let deadline = fixedEnrollmentClaim?.deadlineNanoseconds ?? enrollmentWindow?.window.deadlineNanoseconds,
           now >= deadline { clearEnrollment() }
    }

    func deadline(from start: UInt64, duration: UInt64) throws -> UInt64 {
        let (deadline, overflow) = start.addingReportingOverflow(duration)
        guard !overflow else { throw StatusHostError.deadlineOverflow }
        return deadline
    }

    func randomBytes(_ count: Int) throws -> Data {
        let bytes = try configuration.random.bytes(count: count)
        guard bytes.count == count else {
            throw JournalStorageError(kind: .invalidState, message: "Status random source returned invalid length")
        }
        return bytes
    }

    func invitationUUID() throws -> UUID {
        var bytes = Array(try randomBytes(16))
        guard bytes.contains(where: { $0 != 0 }) else {
            throw JournalStorageError(kind: .invalidState, message: "Status invitation UUID source returned invalid bytes")
        }
        bytes[6] = (bytes[6] & 0x0f) | 0x40
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        return UUID(uuid: (bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6],bytes[7],bytes[8],bytes[9],bytes[10],bytes[11],bytes[12],bytes[13],bytes[14],bytes[15]))
    }

    func openEnrollment() throws -> StatusEnrollmentWindow {
        expireEnrollment()
        let policy = try requireJournal().readPolicy()
        guard policy.controllerState == .unenrolled else { throw StatusHostError.alreadyEnrolled }
        guard enrollmentWindow == nil, fixedEnrollmentClaim == nil else { throw StatusHostError.invalidHandshake }
        let deadline = try deadline(from: configuration.clock.nowNanoseconds(), duration: 120_000_000_000)
        let window = StatusEnrollmentWindow(hostID: policy.hostID, hostPin: policy.hostPin,
                                            invitationID: try invitationUUID(), secret: try randomBytes(32),
                                            deadlineNanoseconds: deadline)
        enrollmentWindow = StatusOpenEnrollment(window: window)
        return window
    }

    func beginHandshake(_ input: StatusHandshakeInput) throws -> StatusHandshakeContext {
        let policy = try requireJournal().readPolicy()
        // Check both selected identity fields before changing any authority or
        // invitation state, even for normal-mode requests against a fresh store.
        guard input.hostID == policy.hostID, input.hostPin == policy.hostPin else {
            throw StatusHostError.identityMismatch
        }
        guard input.connectionID != Self.zeroID, input.clientNonce.count == 32 else { throw StatusHostError.invalidHandshake }
        do { try StatusSchema.validateSPKI(input.controllerSPKI) }
        catch { throw StatusHostError.invalidKey }
        let deadline = try deadline(from: input.acceptedAtNanoseconds, duration: 10_000_000_000)
        let now = configuration.clock.nowNanoseconds()
        guard input.acceptedAtNanoseconds <= now else { throw StatusHostError.invalidHandshake }
        guard now < deadline else { throw StatusHostError.deadlineExpired }
        expireEnrollment()
        handshakeContexts = handshakeContexts.filter { now < $0.value.deadlineNanoseconds }
        guard !handshakeContexts.values.contains(where: { $0.input.connectionID == input.connectionID }) else {
            throw StatusHostError.invalidHandshake
        }
        let controllerID: UUID
        let generation: UInt64
        let invitationSecret: Data?
        switch input.mode {
        case .enrollment:
            guard policy.controllerState == .unenrolled else { throw StatusHostError.alreadyEnrolled }
            guard let window = enrollmentWindow?.window, input.invitationID == window.invitationID else {
                throw StatusHostError.enrollmentClosed
            }
            controllerID = Self.zeroID
            generation = 0
            invitationSecret = window.secret
        case .normal:
            guard input.invitationID == Self.zeroID else { throw StatusHostError.invalidHandshake }
            guard policy.controllerState == .enrolled else { throw StatusHostError.notEnrolled }
            guard input.controllerSPKI == policy.controllerSPKI else { throw StatusHostError.invalidKey }
            controllerID = policy.controllerID
            generation = policy.controllerGeneration
            invitationSecret = nil
        }
        let contextID = UUID()
        let nonce = try randomBytes(32)
        handshakeContexts[contextID] = StatusFixedHandshake(input: input, deadlineNanoseconds: deadline, policy: policy)
        return StatusHandshakeContext(contextID: contextID, serverNonce: nonce, controllerID: controllerID,
                                      generation: generation, invitationSecret: invitationSecret)
    }

    // Remove first so every terminal proof outcome consumes the context once,
    // including delayed dispatch and an operation submitted in the wrong mode.
    func consumeContext(_ contextID: UUID) throws -> StatusFixedHandshake {
        guard let context = handshakeContexts.removeValue(forKey: contextID) else { throw StatusHostError.invalidContext }
        guard configuration.clock.nowNanoseconds() < context.deadlineNanoseconds else { throw StatusHostError.deadlineExpired }
        return context
    }

    func recordProofFailure(contextID: UUID) throws {
        let context = try consumeContext(contextID)
        expireEnrollment()
        guard context.input.mode == .enrollment else { return }
        guard var window = enrollmentWindow, window.window.invitationID == context.input.invitationID else {
            throw StatusHostError.enrollmentClosed
        }
        window.failures += 1
        if window.failures >= 5 { clearEnrollment() }
        else { enrollmentWindow = window }
    }

    func acceptCandidate(contextID: UUID, claimDigest: Data) throws -> StatusAcceptedCandidate {
        let context = try consumeContext(contextID)
        guard context.input.mode == .enrollment, claimDigest.count == 32 else { throw StatusHostError.invalidHandshake }
        expireEnrollment()
        let policy = try requireJournal().readPolicy()
        guard policy.controllerState == .unenrolled else { throw StatusHostError.alreadyEnrolled }
        guard let window = enrollmentWindow?.window, window.invitationID == context.input.invitationID,
              fixedEnrollmentClaim == nil else { throw StatusHostError.enrollmentClosed }
        // The invitation and exact claim become irrevocably fixed before the
        // fresh SAS randomness is requested. Competing contexts cannot replace it.
        let claim = StatusFixedEnrollmentClaim(candidateID: UUID(), connectionID: context.input.connectionID,
                                               controllerSPKI: context.input.controllerSPKI, claimDigest: claimDigest,
                                               deadlineNanoseconds: window.deadlineNanoseconds)
        enrollmentWindow = nil
        fixedEnrollmentClaim = claim
        let candidate = StatusAcceptedCandidate(candidateID: claim.candidateID, connectionID: claim.connectionID,
                                                 claimDigest: claim.claimDigest, sasNonce: try randomBytes(32))
        enrollmentCandidate = candidate
        return candidate
    }

    func authenticate(contextID: UUID) throws -> StatusControllerLease {
        let context = try consumeContext(contextID)
        guard context.input.mode == .normal else { throw StatusHostError.invalidHandshake }
        let policy = try requireJournal().readPolicy()
        guard policy.controllerState == .enrolled else { throw StatusHostError.notEnrolled }
        guard context.input.hostID == policy.hostID, context.input.hostPin == policy.hostPin else {
            throw StatusHostError.identityMismatch
        }
        guard context.input.controllerSPKI == policy.controllerSPKI else { throw StatusHostError.invalidKey }
        // The verified Challenge must still describe the committed slot, key,
        // generation and epoch. Refusal never replaces an existing good lease.
        guard context.policy == policy else { throw StatusHostError.invalidContext }
        guard let incarnation else { throw StatusHostError.closed }
        // A native policy read can consume the remaining authentication budget.
        // Recheck at the mint boundary as well as at context consumption.
        guard configuration.clock.nowNanoseconds() < context.deadlineNanoseconds else {
            throw StatusHostError.deadlineExpired
        }
        let lease = StatusControllerLease(incarnation: incarnation, connectionToken: UUID(),
                                          connectionID: context.input.connectionID, storageEpoch: policy.storageEpoch,
                                          controllerGeneration: policy.controllerGeneration)
        currentLease = lease
        return lease
    }

    func revokeController() throws {
        invalidateControllerAuthority()
        let journal = try requireJournal()
        let policy = try journal.readPolicy()
        switch policy.controllerState {
        case .unenrolled:
            // Refuse before BEGIN: no transaction, policy/key/epoch change or
            // owner quarantine is permitted for the never-enrolled slot.
            throw StatusHostError.notEnrolled
        case .revoked: return
        case .enrolled: _ = try journal.revoke()
        }
    }

    func confirmCandidate(candidateID: UUID) throws {
        expireEnrollment()
        guard let claim = fixedEnrollmentClaim, enrollmentCandidate?.candidateID == candidateID,
              claim.candidateID == candidateID else { throw StatusHostError.invalidCandidate }
        _ = try requireJournal().confirm(key: claim.controllerSPKI)
        clearEnrollment()
    }
}
