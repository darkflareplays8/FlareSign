import SwiftUI

struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedTab = 0

    var body: some View {
        TabView(selection: $selectedTab) {
            HomeView()
                .tabItem { Label("Sign", systemImage: "flame.fill") }
                .tag(0)
            InstalledAppsView()
                .tabItem { Label("Apps", systemImage: "square.grid.2x2") }
                .tag(1)
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gearshape") }
                .tag(2)
        }
        .accentColor(.orange)
    }
}
