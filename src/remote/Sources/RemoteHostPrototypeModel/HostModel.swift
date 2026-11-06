#if os(macOS)
import Foundation
import Combine
import RemotePrototypeWire
import RemotePrototypeHost
import RemoteExecutionCore

/// The adapter owns external IO; the model owns only UI operations and snapshots.
@MainActor public protocol HostModelService: AnyObject {
    func openLocalPolicy(directory: URL) async throws
    func enable(directory: URL, endpoint: StatusEndpoint) async throws
    func disable() async
    func revoke() async throws
    func controllerState() async throws -> String
    func openEnrollment() async throws
    func confirm(candidateID: UUID) async throws -> HostConfirmationOutcome
    func reject(candidateID: UUID) async throws
    func presentation() async -> HostPresentation
}

@MainActor public final class HostModel: ObservableObject {
    @Published public private(set) var hasOpenOwner = false
    @Published public private(set) var enrollment: StatusEnrollmentState = .closed
    @Published public private(set) var committedNotice: String?
    public var canClose: Bool { hasOpenOwner || isBusy }
    public func loadLocalPolicy() async {
        guard !isBusy else { return }
        let id = beginOperation()
        do {
            try await service.openLocalPolicy(directory: directory)
            guard operation == id else { return }
            isBusy = false
            await refresh()
        } catch {
            finishFailure(id, "Local policy unavailable: \(error)")
            if operation == id { await refresh() }
        }
    }
    public let commandsAvailability = "Commands unavailable"
    @Published public private(set) var isEnabled = false
    @Published public private(set) var isListening = false
    @Published public private(set) var isBusy = false
    @Published public private(set) var errorMessage: String?
    @Published public private(set) var invitationText: String?
    @Published public private(set) var candidate: HostCandidatePresentation?
    @Published public private(set) var controllerState = "unknown"
    public var canRevoke: Bool { hasOpenOwner && !isBusy && controllerState == "enrolled" }
    public var canEnroll: Bool { isEnabled && isListening && !isBusy && controllerState == "unenrolled" && enrollment == .closed && invitationText == nil && candidate == nil }
    private let service: any HostModelService
    private let directory: URL
    private var operation = UUID()
    private var refreshGeneration = UUID()
    private var availabilityFailure = false

    private var presentationRefreshTask: Task<Void, Never>?
    private var presentationRefreshIncarnation = UUID()
    private let presentationRefreshWait: @MainActor @Sendable () async throws -> Void

    public convenience init(service: any HostModelService, directory: URL) {
        self.init(service: service, directory: directory, presentationRefreshWait: {
            try await Task.sleep(nanoseconds: 1_000_000_000)
        })
    }
    // Scheduling is injectable; the owner alone still decides enrollment expiry.
    init(service: any HostModelService, directory: URL,
         presentationRefreshWait: @escaping @MainActor @Sendable () async throws -> Void) {
        self.service = service; self.directory = directory; self.presentationRefreshWait = presentationRefreshWait
    }
    deinit { presentationRefreshTask?.cancel() }
    public static func production(applicationSupport: URL, arguments: [String]) throws -> HostModel {
        let id = try PrototypeInstallationSelection.parse(arguments: arguments)
        let service = ProductionHostService()
        let model = HostModel(service: service, directory: PrototypeInstallationSelection.resolve(applicationSupport: applicationSupport, installationID: id))
        service.onChange = { [weak model] in Task { @MainActor in await model?.refresh() } }
        return model
    }
    public func enable(ipv4: String, port: UInt16) async {
        do { await enable(endpoint: try StatusEndpoint(ipv4: ipv4, port: port)) }
        catch { errorMessage = "Enter an exact Tailscale IPv4 address and port 1024–65535." }
    }
    public func enable(endpoint: StatusEndpoint) async {
        guard !isBusy, !isEnabled else { return }
        let id = beginOperation()
        do {
            try await service.enable(directory: directory, endpoint: endpoint)
            guard operation == id else { return }
            isBusy = false
            await refresh()
        } catch {
            finishFailure(id, "Hosting unavailable: \(error)")
            // Startup can fail after owner publication without an availability
            // callback. Refresh resource presence/readiness under operation guards.
            if operation == id { await refresh() }
        }
    }
    public func disable() async {
        let id = beginOperation()
        clearPresentation()
        hasOpenOwner = false; committedNotice = nil
        await service.disable()
        guard operation == id else { return }
        isBusy = false
    }
    public func quit() async { await disable() }
    /// App-scoped ownership intentionally survives a dismissed window.
    public func windowClosed() {}
    public func openEnrollment() async {
        guard canEnroll else { return }
        await perform { try await self.service.openEnrollment() }
    }
    public func confirm() async {
        guard !isBusy, isEnabled, let candidate else { return }
        let id = beginOperation()
        do {
            let outcome = try await service.confirm(candidateID: candidate.candidateID)
            guard operation == id else { return }
            switch outcome {
            case .committed(let acknowledgementSent):
                committedNotice = acknowledgementSent
                    ? "Controller enrollment committed. Acknowledgement sent."
                    : "Controller enrollment committed. Acknowledgement delivery is uncertain; reconnect normally."
            }
            isBusy = false
            await refresh()
        } catch {
            finishFailure(id, "Operation failed: \(error)")
            if operation == id { await refresh() }
        }
    }
    public func reject() async {
        guard !isBusy, isEnabled, let candidate else { return }
        await perform { try await self.service.reject(candidateID: candidate.candidateID) }
    }
    public func revoke() async {
        guard canRevoke else { return }
        await perform { try await self.service.revoke() }
    }
    public func refresh() async {
        let op = operation, revision = UUID()
        let wasEnabled = isEnabled
        refreshGeneration = revision
        let value = await service.presentation()
        guard operation == op, refreshGeneration == revision else { return }
        hasOpenOwner = value.hasOpenOwner
        let state: String
        do { state = try await service.controllerState() }
        catch {
            guard operation == op, refreshGeneration == revision else { return }
            // The earlier presentation cannot remain authoritative when its
            // following readiness read fails, even before a service callback.
            clearPresentation()
            availabilityFailure = false
            if wasEnabled || value.isEnabled || hasOpenOwner { errorMessage = "Hosting readiness unavailable: \(error)" }
            return
        }
        guard operation == op, refreshGeneration == revision else { return }
        isEnabled = value.isEnabled; isListening = value.isListening
        controllerState = state
        enrollment = value.enrollment
        invitationText = value.isEnabled && value.isListening ? value.invitation.flatMap { try? $0.encode() } : nil
        candidate = value.isEnabled && value.isListening ? value.candidate : nil
        if availabilityFailure { errorMessage = nil; availabilityFailure = false }
        if value.isEnabled && !value.isListening {
            errorMessage = "Disconnected: selected address is unavailable."
            availabilityFailure = true
        }
        updatePresentationRefresh()
    }
    private func beginOperation() -> UUID {
        stopPresentationRefresh()
        operation = UUID(); refreshGeneration = UUID(); isBusy = true; errorMessage = nil; availabilityFailure = false
        return operation
    }
    private func clearPresentation() {
        stopPresentationRefresh()
        isEnabled = false; isListening = false; invitationText = nil; candidate = nil; controllerState = "unknown"; enrollment = .closed
    }
    private var needsPresentationRefresh: Bool {
        isEnabled && isListening && !isBusy && enrollment != .closed
    }
    private func updatePresentationRefresh() {
        guard needsPresentationRefresh else { stopPresentationRefresh(); return }
        guard presentationRefreshTask == nil else { return }
        let incarnation = UUID()
        presentationRefreshIncarnation = incarnation
        let wait = presentationRefreshWait
        // Hold the model only during a read, never through the idle wait.
        // One task waits and reads serially; ordinary refreshes cannot add timers.
        presentationRefreshTask = Task { [weak self] in
            while !Task.isCancelled {
                do { try await wait() } catch { return }
                guard !Task.isCancelled,
                      await self?.refreshPresentation(incarnation: incarnation) == true else { return }
            }
        }
    }
    private func refreshPresentation(incarnation: UUID) async -> Bool {
        guard presentationRefreshIncarnation == incarnation, needsPresentationRefresh else { return false }
        // Refresh retains its existing operation/revision checks across owner reads.
        await refresh()
        return presentationRefreshIncarnation == incarnation && needsPresentationRefresh
    }
    private func stopPresentationRefresh() {
        presentationRefreshIncarnation = UUID()
        presentationRefreshTask?.cancel()
        presentationRefreshTask = nil
    }
    private func finishFailure(_ id: UUID, _ message: String) {
        guard operation == id else { return }
        isBusy = false; errorMessage = message; availabilityFailure = false
    }
    private func perform(_ action: () async throws -> Void) async {
        let id = beginOperation()
        do {
            try await action()
            guard operation == id else { return }
            isBusy = false; await refresh()
        } catch {
            finishFailure(id, "Operation failed: \(error)")
            if operation == id { await refresh() }
        }
    }
}

@MainActor private final class ProductionHostService: HostModelService {
    var onChange: (@MainActor @Sendable () -> Void)?
    private lazy var host = HostService(onChange: { [weak self] in Task { @MainActor in self?.onChange?() } })
    func openLocalPolicy(directory: URL) async throws {
        try await host.openLocalPolicy(configuration: HostService.makeProductionConfiguration(directory: directory))
    }
    func enable(directory: URL, endpoint: StatusEndpoint) async throws {
        try PrototypeInstallationSelection.provisionParents(of: directory)
        try await host.enable(configuration: HostService.makeProductionConfiguration(directory: directory), endpoint: endpoint)
    }
    func disable() async { await host.disable() }
    func revoke() async throws { try await host.revokeController() }
    func controllerState() async throws -> String { try await host.localStatus().controllerState.rawValue }
    func openEnrollment() async throws { _ = try await host.openEnrollment() }
    func confirm(candidateID: UUID) async throws -> HostConfirmationOutcome { try await host.confirmCandidate(candidateID: candidateID) }
    func reject(candidateID: UUID) async throws { try await host.rejectCandidate(candidateID: candidateID) }
    func presentation() async -> HostPresentation { await host.presentation() }
}
#endif
