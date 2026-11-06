import SwiftUI
import RemoteControllerProbeModel

struct ProbeView: View {
    @ObservedObject var model: ProbeModel
    @State private var invitation = ""
    @State private var address = ""
    @State private var port = "49152"
    @State private var endpointError: String?
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(model.commandsAvailability).font(.headline).accessibilityIdentifier("commandsUnavailable")
                    Text(model.status)
                    if let id = model.connectionID { Text("Connection: \(id.uuidString)").font(.caption) }
                    if let error = model.errorMessage { Text(error).foregroundStyle(.red).accessibilityLabel("Connection error: \(error)") }
                    if let endpointError { Text(endpointError).foregroundStyle(.red) }
                }
                Section("Invitation") {
                    TextField("Paste enrollment invitation", text: $invitation, axis: .vertical)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button("Use invitation") {
                        do { try model.enterInvitation(invitation); invitation = "" } catch {}
                    }.disabled(invitation.isEmpty)
                }
                Section("Pinned host endpoint") {
                    TextField("Tailscale IPv4 address", text: $address).keyboardType(.decimalPad)
                    TextField("Port", text: $port).keyboardType(.numberPad)
                    Button("Apply endpoint") {
                        do {
                            try model.editEndpoint(ipv4: address, port: UInt16(port) ?? 0)
                            endpointError = nil
                        } catch { endpointError = "Enter a Tailscale IPv4 address and port 1024–65535 for the existing pinned host." }
                    }.disabled(!model.hasPairing)
                    Button("Connect") { Task { await model.connect() } }.disabled(!model.hasPairing || model.connectionID != nil)
                    Button("Reconnect") { Task { await model.reconnect() } }.disabled(!model.hasPairing)
                    Button("Disconnect") { model.disconnect() }.disabled(model.connectionID == nil)
                }
                if let comparison = model.comparison {
                    Section("Compare on the Mac") {
                        Text(comparison.code).font(.largeTitle.monospacedDigit()).accessibilityLabel("Comparison code: \(comparison.code)")
                        Text("Confirm the matching code locally on the Mac.")
                    }
                }
                if let epoch = model.storageEpoch {
                    Section("Committed status") { Text("Storage epoch: \(epoch.uuidString)").textSelection(.enabled) }
                }
                Section("Local pairing") {
                    Button("Forget pairing", role: .destructive) {
                        do { try model.forgetPairing() } catch {}
                    }
                    Text("Keeps the phone identity key. Mac authorization changes only when revoked on the Mac.").font(.caption)
                }
            }
            .navigationTitle("Status Probe")
            .onAppear { syncEndpoint() }
            .onChange(of: model.endpointAddress) { _ in syncEndpoint() }
            .onChange(of: model.endpointPort) { _ in syncEndpoint() }
        }
    }
    private func syncEndpoint() { address = model.endpointAddress; port = String(model.endpointPort) }
}
