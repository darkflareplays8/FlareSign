import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @State private var showClearAlert = false

    var body: some View {
        NavigationView {
            List {
                Section("Signing") {
                    NavigationLink {
                        DefaultCredentialsView().environmentObject(appState)
                    } label: {
                        Label("Default Apple ID", systemImage: "person.circle")
                    }
                }

                Section("Notifications") {
                    HStack {
                        Label("Renewal reminders", systemImage: "bell.badge")
                        Spacer()
                        Text("Day 6").font(.caption).foregroundColor(.secondary)
                    }
                }

                Section("Data") {
                    Button(role: .destructive) { showClearAlert = true } label: {
                        Label("Clear all app records", systemImage: "trash")
                    }
                }

                Section("About") {
                    HStack {
                        Label("FlareSign", systemImage: "flame.fill")
                            .foregroundStyle(LinearGradient(colors: [.orange, .red], startPoint: .leading, endPoint: .trailing))
                        Spacer()
                        Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0")
                            .font(.caption).foregroundColor(.secondary)
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Settings")
            .alert("Clear All Records", isPresented: $showClearAlert) {
                Button("Clear", role: .destructive) {
                    appState.installedApps.forEach { appState.removeApp($0) }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This removes all app tracking records. Apps will remain installed on your device.")
            }
        }
    }
}

struct DefaultCredentialsView: View {
    @EnvironmentObject var appState: AppState
    @State private var appleID = ""
    @State private var password = ""
    @State private var saved = false

    var body: some View {
        List {
            Section("Apple ID") {
                TextField("Email", text: $appleID).textContentType(.emailAddress).autocapitalization(.none)
                SecureField("Password", text: $password).textContentType(.password)
            }
            Section {
                Button("Save") {
                    appState.signingConfig.appleID = appleID
                    appState.signingConfig.password = password
                    saved = true
                }
                .foregroundColor(.orange)
            }
        }
        .navigationTitle("Default Apple ID")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            appleID = appState.signingConfig.appleID
            password = appState.signingConfig.password
        }
        .overlay {
            if saved {
                VStack {
                    Spacer()
                    Text("Saved").padding().background(.ultraThinMaterial).clipShape(Capsule()).padding()
                }
                .onAppear { DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { saved = false } }
            }
        }
    }
}
