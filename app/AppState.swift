import SwiftUI

class AppState: ObservableObject {
    @Published var installedApps: [SignedApp] = []
    @Published var signingConfig = SigningConfig()

    private let appsKey   = "flaresign.installedApps"
    private let configKey = "flaresign.signingConfig"

    init() {
        loadInstalledApps()
        loadSigningConfig()
    }

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

    func saveSigningConfig() {
        signingConfig.save()
        if let data = try? JSONEncoder().encode(signingConfig) {
            UserDefaults.standard.set(data, forKey: configKey)
        }
    }

    private func loadSigningConfig() {
        // SigningConfig.init() already loads from UserDefaults + Keychain
        // This is just a no-op placeholder in case we need extra loading later
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
