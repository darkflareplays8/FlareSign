import SwiftUI
import UniformTypeIdentifiers

struct SigningView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss

    let ipaURL: URL
    @Binding var appName: String
    @Binding var bundleID: String
    let version: String
    let iconData: Data?

    @State private var appleID = ""
    @State private var password = ""
    @State private var overrideName = ""
    @State private var overrideBundleID = ""
    @State private var useCustomProfile = false
    @State private var profileData: Data?
    @State private var showProfilePicker = false
    @State private var signingState: SigningState = .idle
    @State private var errorMessage = ""
    @State private var showAdvanced = false

    enum SigningState { case idle, signing, success, failed }

    var body: some View {
        NavigationView {
            ZStack {
                Color(.systemGroupedBackground).ignoresSafeArea()
                ScrollView {
                    VStack(spacing: 20) {
                        appHeaderCard
                        if signingState == .idle || signingState == .failed {
                            credentialsCard
                            advancedCard
                            if signingState == .failed { errorCard }
                            signButton
                        } else if signingState == .signing {
                            signingProgressCard
                        } else if signingState == .success {
                            successCard
                        }
                    }
                    .padding()
                }
            }
            .navigationTitle("Sign IPA")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
        .fileImporter(isPresented: $showProfilePicker,
                      allowedContentTypes: [UTType(filenameExtension: "mobileprovision") ?? .data],
                      allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let url = urls.first {
                profileData = try? Data(contentsOf: url)
            }
        }
        .onAppear {
            appleID = appState.signingConfig.appleID
            password = appState.signingConfig.password
        }
    }

    private var appHeaderCard: some View {
        HStack(spacing: 16) {
            if let data = iconData, let uiImage = UIImage(data: data) {
                Image(uiImage: uiImage).resizable().frame(width: 56, height: 56)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
            } else {
                RoundedRectangle(cornerRadius: 12)
                    .fill(LinearGradient(colors: [.orange, .red], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 56, height: 56)
                    .overlay(Image(systemName: "app.fill").foregroundColor(.white))
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(appName.isEmpty ? ipaURL.lastPathComponent : appName).font(.headline).lineLimit(1)
                Text(bundleID).font(.caption).foregroundColor(.secondary).lineLimit(1)
                Text("v\(version)").font(.caption2).foregroundColor(.orange)
            }
            Spacer()
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 16).fill(Color(.secondarySystemBackground)))
    }

    private var credentialsCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            Toggle("Use custom provisioning profile", isOn: $useCustomProfile).tint(.orange)

            if useCustomProfile {
                Button { showProfilePicker = true } label: {
                    HStack {
                        Image(systemName: profileData == nil ? "doc.badge.plus" : "doc.fill.badge.checkmark")
                        Text(profileData == nil ? "Select .mobileprovision" : "Profile loaded")
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(RoundedRectangle(cornerRadius: 12).fill(Color.orange.opacity(0.1)))
                    .foregroundColor(.orange)
                }
            } else {
                VStack(spacing: 12) {
                    TextField("Apple ID (email)", text: $appleID)
                        .textContentType(.emailAddress).autocapitalization(.none)
                        .padding()
                        .background(RoundedRectangle(cornerRadius: 12).fill(Color(.tertiarySystemBackground)))
                    SecureField("Password", text: $password)
                        .textContentType(.password)
                        .padding()
                        .background(RoundedRectangle(cornerRadius: 12).fill(Color(.tertiarySystemBackground)))
                }
                Text("Credentials are only used locally for signing and are never transmitted.")
                    .font(.caption2).foregroundColor(.secondary)
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 16).fill(Color(.secondarySystemBackground)))
    }

    private var advancedCard: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button { withAnimation { showAdvanced.toggle() } } label: {
                HStack {
                    Text("Advanced").font(.subheadline.bold())
                    Spacer()
                    Image(systemName: showAdvanced ? "chevron.up" : "chevron.down").foregroundColor(.secondary)
                }
                .padding()
            }
            .foregroundColor(.primary)

            if showAdvanced {
                VStack(spacing: 12) {
                    TextField("Override app name (optional)", text: $overrideName)
                        .padding()
                        .background(RoundedRectangle(cornerRadius: 12).fill(Color(.tertiarySystemBackground)))
                    TextField("Override bundle ID (optional)", text: $overrideBundleID)
                        .autocapitalization(.none)
                        .padding()
                        .background(RoundedRectangle(cornerRadius: 12).fill(Color(.tertiarySystemBackground)))
                }
                .padding([.horizontal, .bottom])
            }
        }
        .background(RoundedRectangle(cornerRadius: 16).fill(Color(.secondarySystemBackground)))
    }

    private var errorCard: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.red)
            Text(errorMessage).font(.caption).foregroundColor(.red)
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.red.opacity(0.1)))
    }

    private var signButton: some View {
        Button { startSigning() } label: {
            Label("Sign & Install", systemImage: "flame.fill")
                .font(.headline)
                .frame(maxWidth: .infinity)
                .padding()
                .background(LinearGradient(colors: [.orange, .red], startPoint: .leading, endPoint: .trailing))
                .foregroundColor(.white)
                .clipShape(RoundedRectangle(cornerRadius: 14))
        }
        .disabled(!canSign)
        .opacity(canSign ? 1 : 0.5)
    }

    private var canSign: Bool {
        useCustomProfile ? profileData != nil : (!appleID.isEmpty && !password.isEmpty)
    }

    private var signingProgressCard: some View {
        VStack(spacing: 20) {
            ProgressView().scaleEffect(1.5).tint(.orange)
            Text("Signing IPA...").font(.headline)
            Text("This may take a moment").font(.caption).foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(40)
        .background(RoundedRectangle(cornerRadius: 16).fill(Color(.secondarySystemBackground)))
    }

    private var successCard: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 56))
                .foregroundStyle(LinearGradient(colors: [.orange, .red], startPoint: .top, endPoint: .bottom))
            Text("Signed & Installing!").font(.title2.bold())
            Text("Check your Home Screen in a moment.")
                .font(.subheadline).foregroundColor(.secondary).multilineTextAlignment(.center)
            Button("Done") { dismiss() }
                .font(.headline)
                .frame(maxWidth: .infinity)
                .padding()
                .background(LinearGradient(colors: [.orange, .red], startPoint: .leading, endPoint: .trailing))
                .foregroundColor(.white)
                .clipShape(RoundedRectangle(cornerRadius: 14))
        }
        .frame(maxWidth: .infinity)
        .padding(32)
        .background(RoundedRectangle(cornerRadius: 16).fill(Color(.secondarySystemBackground)))
    }

    private func startSigning() {
        signingState = .signing
        let finalBundleID = overrideBundleID.isEmpty ? bundleID : overrideBundleID
        let finalName = overrideName.isEmpty ? appName : overrideName

        SigningService.shared.sign(
            ipaURL: ipaURL,
            appleID: useCustomProfile ? nil : appleID,
            password: useCustomProfile ? nil : password,
            provisioningProfile: profileData,
            bundleID: finalBundleID,
            appName: finalName
        ) { result in
            DispatchQueue.main.async {
                switch result {
                case .success(let signedURL):
                    let app = SignedApp(name: finalName, bundleID: finalBundleID, version: version,
                                       signedDate: Date(),
                                       expiryDate: Calendar.current.date(byAdding: .day, value: 7, to: Date()) ?? Date())
                    appState.addInstalledApp(app)
                    OTAInstallService.shared.install(ipaURL: signedURL, bundleID: finalBundleID, appName: finalName)
                    signingState = .success
                case .failure(let error):
                    errorMessage = error.localizedDescription
                    signingState = .failed
                }
            }
        }
    }
}
