import SwiftUI
import RemoteHostPrototypeModel

struct HostView: View {
    @ObservedObject var model: HostModel
    @State private var address = ""
    @State private var port = "49152"
    var body: some View {
        Form {
            Section {
                Text(model.commandsAvailability).font(.headline).accessibilityIdentifier("commandsUnavailable")
                Text(model.isListening ? "Hosting status only" : (model.isEnabled ? "Disconnected" : "Hosting disabled"))
                Text("Controller: \(model.controllerState)")
                if let error = model.errorMessage { Text(error).foregroundStyle(.red).accessibilityLabel("Hosting error: \(error)") }
            }
            Section("Selected local endpoint") {
                TextField("Tailscale IPv4 address", text: $address).disabled(model.isEnabled || model.isBusy)
                TextField("Port", text: $port).disabled(model.isEnabled || model.isBusy)
                HStack {
                    Button("Enable hosting") { Task { await model.enable(ipv4: address, port: UInt16(port) ?? 0) } }
                        .disabled(model.isEnabled || model.isBusy)
                    Button("Disable hosting") { Task { await model.disable() } }
                        .disabled(!model.isEnabled && !model.isBusy)
                }
            }
            Section("Enrollment") {
                Button("Open enrollment") { Task { await model.openEnrollment() } }.disabled(!model.canEnroll)
                if let invitation = model.invitationText {
                    Text("Copy this invitation to the phone").font(.caption)
                    Text(invitation).textSelection(.enabled).accessibilityLabel("Enrollment invitation: \(invitation)")
                }
                if let candidate = model.candidate {
                    Text(candidate.comparisonCode).font(.title.monospacedDigit()).textSelection(.enabled)
                        .accessibilityLabel("Comparison code: \(candidate.comparisonCode)")
                    Text("Confirm only when this code matches the phone.")
                    HStack {
                        Button("Confirm matching code") { Task { await model.confirm() } }.disabled(model.isBusy)
                        Button("Reject candidate") { Task { await model.reject() } }.disabled(model.isBusy)
                    }
                }
            }
            Section("Local controller policy") {
                Button("Revoke controller") { Task { await model.revoke() } }.disabled(!model.canRevoke)
                Button("Refresh local status") { Task { await model.refresh() } }.disabled(model.isBusy)
            }
        }
        .padding().frame(minWidth: 520, minHeight: 440)
        // No disappear handler: closing a window intentionally retains hosting.
    }
}
