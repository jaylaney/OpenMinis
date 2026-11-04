import SwiftUI
import RemoteControllerProbeModel

@main struct RemoteControllerProbeApp: App {
    @StateObject private var model = ProbeModel.production()
    @Environment(\.scenePhase) private var scenePhase
    var body: some Scene {
        WindowGroup { ProbeView(model: model) }
            .onChange(of: scenePhase) { phase in
                if phase != .active { model.suspended() }
            }
    }
}
