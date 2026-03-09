import SwiftUI
import UniformTypeIdentifiers

struct HomeView: View {
    @EnvironmentObject var appState: AppState
    @State private var showingFilePicker = false
    @State private var selectedIPAURL: URL?
    @State private var showingSigningSheet = false
    @State private var detectedAppName = ""
    @State private var detectedBundleID = ""
    @State private var detectedVersion = ""
    @State private var detectedIconData: Data?

    var body: some View {
        NavigationView {
            ZStack {
                LinearGradient(colors: [Color(.systemBackground), Color.orange.opacity(0.05)],
                               startPoint: .top, endPoint: .bottom)
                    .ignoresSafeArea()

                VStack(spacing: 32) {
                    Spacer()

                    VStack(spacing: 8) {
                        Image(systemName: "flame.fill")
                            .font(.system(size: 64))
                            .foregroundStyle(LinearGradient(colors: [.orange, .red], startPoint: .top, endPoint: .bottom))
                        Text("FlareSign")
                            .font(.largeTitle.bold())
                            .foregroundStyle(LinearGradient(colors: [.orange, .red], startPoint: .leading, endPoint: .trailing))
                        Text("Sign & install IPAs with your Apple ID")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }

                    if let url = selectedIPAURL {
                        IPAPreviewCard(url: url, appName: detectedAppName,
                                       bundleID: detectedBundleID, version: detectedVersion,
                                       iconData: detectedIconData)
                            .transition(.scale.combined(with: .opacity))

                        Button { showingSigningSheet = true } label: {
                            Label("Sign & Install", systemImage: "flame.fill")
                                .font(.headline)
                                .frame(maxWidth: .infinity)
                                .padding()
                                .background(LinearGradient(colors: [.orange, .red], startPoint: .leading, endPoint: .trailing))
                                .foregroundColor(.white)
                                .clipShape(RoundedRectangle(cornerRadius: 14))
                        }
                        .padding(.horizontal)

                        Button { withAnimation { selectedIPAURL = nil } } label: {
                            Text("Choose different IPA")
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                        }
                    } else {
                        Button { showingFilePicker = true } label: {
                            VStack(spacing: 16) {
                                Image(systemName: "plus.circle.dashed")
                                    .font(.system(size: 48))
                                    .foregroundStyle(LinearGradient(colors: [.orange, .red], startPoint: .top, endPoint: .bottom))
                                Text("Select IPA File")
                                    .font(.headline)
                                    .foregroundColor(.primary)
                                Text("Tap to browse Files")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(40)
                            .background(
                                RoundedRectangle(cornerRadius: 20)
                                    .strokeBorder(LinearGradient(colors: [.orange, .red], startPoint: .topLeading, endPoint: .bottomTrailing), lineWidth: 2)
                                    .background(RoundedRectangle(cornerRadius: 20).fill(Color.orange.opacity(0.05)))
                            )
                        }
                        .padding(.horizontal)
                    }

                    Spacer()
                }
            }
            .navigationBarHidden(true)
            .fileImporter(isPresented: $showingFilePicker,
                          allowedContentTypes: [
                              UTType(filenameExtension: "ipa") ?? .data,
                              UTType(mimeType: "application/octet-stream") ?? .data,
                              .zip,
                              .data
                          ],
                          allowsMultipleSelection: false) { result in
                switch result {
                case .success(let urls):
                    guard let url = urls.first else { return }
                    guard url.startAccessingSecurityScopedResource() else { return }
                    selectedIPAURL = url
                    IPAParser.parse(url: url) { info in
                        DispatchQueue.main.async {
                            detectedAppName = info.name
                            detectedBundleID = info.bundleID
                            detectedVersion = info.version
                            detectedIconData = info.iconData
                            url.stopAccessingSecurityScopedResource()
                        }
                    }
                case .failure(let error):
                    print("File picker error: \(error.localizedDescription)")
                }
            }
            .sheet(isPresented: $showingSigningSheet) {
                if let url = selectedIPAURL {
                    SigningView(ipaURL: url, appName: $detectedAppName,
                                bundleID: $detectedBundleID, version: detectedVersion,
                                iconData: detectedIconData)
                        .environmentObject(appState)
                }
            }
        }
    }
}

struct IPAPreviewCard: View {
    let url: URL
    let appName: String
    let bundleID: String
    let version: String
    let iconData: Data?

    var body: some View {
        HStack(spacing: 16) {
            if let data = iconData, let uiImage = UIImage(data: data) {
                Image(uiImage: uiImage).resizable().frame(width: 60, height: 60)
                    .clipShape(RoundedRectangle(cornerRadius: 13))
            } else {
                RoundedRectangle(cornerRadius: 13)
                    .fill(LinearGradient(colors: [.orange, .red], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 60, height: 60)
                    .overlay(Image(systemName: "app.fill").foregroundColor(.white).font(.title2))
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(appName.isEmpty ? url.lastPathComponent : appName).font(.headline).lineLimit(1)
                Text(bundleID.isEmpty ? "Unknown Bundle ID" : bundleID).font(.caption).foregroundColor(.secondary).lineLimit(1)
                Text("v\(version.isEmpty ? "?" : version)").font(.caption2).foregroundColor(.orange)
            }
            Spacer()
            Image(systemName: "checkmark.circle.fill").foregroundColor(.orange).font(.title2)
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 16).fill(Color(.secondarySystemBackground)))
        .padding(.horizontal)
    }
}
