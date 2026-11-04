import SwiftUI
import AppKit
import RemoteHostPrototypeModel

@main struct RemoteHostPrototypeApp: App {
    @StateObject private var owner = HostApplicationOwner()
    @NSApplicationDelegateAdaptor(HostApplicationDelegate.self) private var delegate
    var body: some Scene {
        WindowGroup("OpenMinis Status Host") {
            Group {
                if let model = owner.model {
                    HostView(model: model)
                } else {
                    Form {
                        Text("Commands unavailable").font(.headline)
                        Text(owner.error ?? "Hosting unavailable").foregroundStyle(.red)
                    }.padding().frame(minWidth: 480, minHeight: 180)
                }
            }
            .onAppear { delegate.model = owner.model }
        }
    }
}

@MainActor private final class HostApplicationOwner: ObservableObject {
    let model: HostModel?
    let error: String?
    init() {
        do {
            let root = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: false)
            model = try HostModel.production(applicationSupport: root, arguments: Array(ProcessInfo.processInfo.arguments.dropFirst()))
            error = nil
        } catch {
            model = nil
            self.error = "Invalid local installation selection or unavailable Application Support: \(error)"
        }
    }
}

/// SwiftUI lacks asynchronous termination and a last-window termination policy.
/// The app owns the model; this bridge only forwards sleep and graceful Quit.
@MainActor private final class HostApplicationDelegate: NSObject, NSApplicationDelegate {
    var model: HostModel?
    private var sleepObserver: NSObjectProtocol?
    private var terminating = false
    func applicationDidFinishLaunching(_ notification: Notification) {
        sleepObserver = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in
                await self?.model?.disable()
            }
        }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !terminating else { return .terminateLater }
        terminating = true
        Task { @MainActor in
            await model?.quit()
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}
