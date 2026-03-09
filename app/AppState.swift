import SwiftUI

class AppState: ObservableObject {
    @Published var installedApps: [SignedApp] = []
    @Published var signingConfig = SigningConfig()
    private let appsKey = "flaresign.installedApps"

    init() { loadInstalledApps() }

    func addInstalledApp(_ app: SignedApp) {
        installedApps.removeAll { $0.bundleID == app.bundleID }
        installedApps.append(app)
        saveInstalledApps()
        RenewalManager.shared.scheduleRenewalNotification(for: app)
    }

    func removeApp(_ app: SignedApp) {
        installedApps.removeAll { $0.id == app.id }
        saveInstalledApps()
        RenewalManager.shared.cancelRenewalNotification(for: app)
    }

    private func saveInstalledApps() {
        if let data = try? JSONEncoder().encode(installedApps) {
            UserDefaults.standard.set(data, forKey: appsKey)
        }
    }

    private func loadInstalledApps() {
        guard let data = UserDefaults.standard.data(forKey: appsKey),
              let apps = try? JSONDecoder().decode([SignedApp].self, from: data) else { return }
        installedApps = apps
    }
}
