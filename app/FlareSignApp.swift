import SwiftUI

@main
struct FlareSignApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .onAppear {
                    RenewalManager.shared.requestNotificationPermission()
                    RenewalManager.shared.scheduleAllRenewalNotifications(apps: appState.installedApps)
                }
        }
    }
}
