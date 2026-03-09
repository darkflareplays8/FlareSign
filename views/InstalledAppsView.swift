import SwiftUI

struct InstalledAppsView: View {
    @EnvironmentObject var appState: AppState
    @State private var appToDelete: SignedApp?
    @State private var showDeleteAlert = false

    var body: some View {
        NavigationView {
            ZStack {
                Color(.systemGroupedBackground).ignoresSafeArea()
                if appState.installedApps.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "square.grid.2x2").font(.system(size: 48)).foregroundColor(.secondary)
                        Text("No signed apps yet").font(.headline)
                        Text("Sign an IPA from the Sign tab").font(.caption).foregroundColor(.secondary)
                    }
                } else {
                    List {
                        ForEach(appState.installedApps.sorted { $0.expiryDate < $1.expiryDate }) { app in
                            AppRow(app: app)
                                .swipeActions {
                                    Button(role: .destructive) {
                                        appToDelete = app
                                        showDeleteAlert = true
                                    } label: { Label("Remove", systemImage: "trash") }
                                }
                        }
                    }
                    .listStyle(.insetGrouped)
                }
            }
            .navigationTitle("Signed Apps")
            .alert("Remove App", isPresented: $showDeleteAlert, presenting: appToDelete) { app in
                Button("Remove", role: .destructive) { appState.removeApp(app) }
                Button("Cancel", role: .cancel) {}
            } message: { app in
                Text("Remove \(app.name) from tracking? This won't uninstall it from your device.")
            }
        }
    }
}

struct AppRow: View {
    let app: SignedApp

    var statusColor: Color {
        switch app.expiryStatus {
        case .good: return .green
        case .warning: return .yellow
        case .critical: return .orange
        case .expired: return .red
        }
    }

    var statusText: String {
        if app.isExpired { return "Expired" }
        if app.daysUntilExpiry == 0 { return "Expires today" }
        return "\(app.daysUntilExpiry)d left"
    }

    var body: some View {
        HStack(spacing: 14) {
            if let data = app.iconData, let uiImage = UIImage(data: data) {
                Image(uiImage: uiImage).resizable().frame(width: 48, height: 48)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
            } else {
                RoundedRectangle(cornerRadius: 10)
                    .fill(LinearGradient(colors: [.orange, .red], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 48, height: 48)
                    .overlay(Image(systemName: "app.fill").foregroundColor(.white))
            }
            VStack(alignment: .leading, spacing: 3) {
                Text(app.name).font(.headline).lineLimit(1)
                Text(app.bundleID).font(.caption).foregroundColor(.secondary).lineLimit(1)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 3) {
                Circle().fill(statusColor).frame(width: 8, height: 8)
                Text(statusText).font(.caption2).foregroundColor(statusColor)
            }
        }
        .padding(.vertical, 4)
    }
}
