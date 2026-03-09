import SwiftUI
import UniformTypeIdentifiers

enum SigningMethod: String, CaseIterable {
    case appleID = "Apple ID"
    case customP12 = "Custom Certificate"
}

struct SigningView: View {
    let ipaURL: URL
    @Binding var appName: String
    @Binding var bundleID: String
    let version: String
    let iconData: Data?

    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss

    @StateObject private var config = SigningConfig()
    @State private var signingMethod: SigningMethod = .appleID
    @State private var p12Data: Data?
    @State private var p12Password = ""
    @State private var provisionData: Data?
    @State private var showingP12Picker = false
    @State private var showingProvisionPicker = false
    @State private var signingState: SigningState = .idle
    @State private var progressMessage = ""
    @State private var showingTwoFactor = false
    @State private var twoFactorCode = ""
    @State private var twoFactorContinuation: ((String) -> Void)?
    @State private var showAdvanced = false

    enum SigningState { case idle, signing, success, failed(String) }

    var body: some View {
        NavigationView {
            ZStack {
                Color(.systemBackground).ignoresSafeArea()
                ScrollView {
                    VStack(spacing: 20) {
                        Picker("Method", selection: $signingMethod) {
                            ForEach(SigningMethod.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                        }
                        .pickerStyle(.segmented)
                        .padding(.horizontal)

                        if signingMethod == .appleID { appleIDSection } else { customCertSection }
                        advancedSection
                        signButton
                    }
                    .padding(.vertical)
                }
            }
            .navigationTitle("Sign IPA")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
            .sheet(isPresented: $showingTwoFactor) { twoFactorSheet }
        }
    }

    var appleIDSection: some View {
        VStack(spacing: 12) {
            GroupBox {
                VStack(spacing: 12) {
                    TextField("Apple ID", text: $config.appleID)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.emailAddress)
                        .autocorrectionDisabled()
                    Divider()
                    SecureField("Password", text: $config.password)
                }
                .padding(4)
            } label: {
                Label("Apple ID Credentials", systemImage: "person.circle").foregroundColor(.orange)
            }
            .padding(.horizontal)
            Text("Uses a free 7-day developer certificate via anisette server.")
                .font(.caption).foregroundColor(.secondary).multilineTextAlignment(.center).padding(.horizontal)
        }
    }

    var customCertSection: some View {
        VStack(spacing: 12) {
            GroupBox {
                VStack(spacing: 12) {
                    Button { showingP12Picker = true } label: {
                        HStack {
                            Image(systemName: p12Data != nil ? "checkmark.circle.fill" : "doc.badge.plus")
                                .foregroundColor(p12Data != nil ? .green : .orange)
                            Text(p12Data != nil ? "P12 loaded" : "Select .p12 certificate")
                                .foregroundColor(p12Data != nil ? .primary : .orange)
                            Spacer()
                        }
                    }
                    if p12Data != nil {
                        Divider()
                        SecureField("P12 Password (if any)", text: $p12Password)
                    }
                    Divider()
                    Button { showingProvisionPicker = true } label: {
                        HStack {
                            Image(systemName: provisionData != nil ? "checkmark.circle.fill" : "doc.badge.plus")
                                .foregroundColor(provisionData != nil ? .green : .orange)
                            Text(provisionData != nil ? "Profile loaded" : "Select .mobileprovision")
                                .foregroundColor(provisionData != nil ? .primary : .orange)
                            Spacer()
                        }
                    }
                }
                .padding(4)
            } label: {
                Label("Certificate & Profile", systemImage: "lock.shield").foregroundColor(.orange)
            }
            .padding(.horizontal)
        }
        .fileImporter(isPresented: $showingP12Picker,
                      allowedContentTypes: [UTType(filenameExtension: "p12") ?? .data],
                      allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let url = urls.first {
                _ = url.startAccessingSecurityScopedResource()
                p12Data = try? Data(contentsOf: url)
            }
        }
        .fileImporter(isPresented: $showingProvisionPicker,
                      allowedContentTypes: [UTType(filenameExtension: "mobileprovision") ?? .data],
                      allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let url = urls.first {
                _ = url.startAccessingSecurityScopedResource()
                provisionData = try? Data(contentsOf: url)
            }
        }
    }

    var advancedSection: some View {
        GroupBox {
            VStack(spacing: 10) {
                Button { withAnimation { showAdvanced.toggle() } } label: {
                    HStack {
                        Text("Advanced Options").font(.subheadline.bold()).foregroundColor(.primary)
                        Spacer()
                        Image(systemName: showAdvanced ? "chevron.up" : "chevron.down").foregroundColor(.secondary)
                    }
                }
                if showAdvanced {
                    Divider()
                    TextField("Bundle ID override", text: $bundleID)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .font(.system(.body, design: .monospaced))
                    Divider()
                    TextField("App name override", text: $appName)
                }
            }
            .padding(4)
        }
        .padding(.horizontal)
    }

    var signButton: some View {
        VStack(spacing: 12) {
            switch signingState {
            case .idle:
                Button { startSigning() } label: {
                    Label("Sign & Install", systemImage: "flame.fill")
                        .font(.headline).frame(maxWidth: .infinity).padding()
                        .background(canSign
                            ? LinearGradient(colors: [.orange, .red], startPoint: .leading, endPoint: .trailing)
                            : LinearGradient(colors: [.gray], startPoint: .leading, endPoint: .trailing))
                        .foregroundColor(.white).clipShape(RoundedRectangle(cornerRadius: 14))
                }
                .disabled(!canSign).padding(.horizontal)
            case .signing:
                VStack(spacing: 8) {
                    ProgressView()
                    Text(progressMessage.isEmpty ? "Signing..." : progressMessage)
                        .font(.subheadline).foregroundColor(.secondary)
                }.padding()
            case .success:
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.circle.fill").font(.largeTitle).foregroundColor(.green)
                    Text("Signed & installing!").font(.headline)
                    Button("Done") { dismiss() }.foregroundColor(.orange)
                }.padding()
            case .failed(let msg):
                VStack(spacing: 8) {
                    Image(systemName: "xmark.circle.fill").font(.largeTitle).foregroundColor(.red)
                    Text("Signing failed").font(.headline)
                    Text(msg).font(.caption).foregroundColor(.secondary).multilineTextAlignment(.center)
                    Button("Try Again") { signingState = .idle }.foregroundColor(.orange)
                }.padding()
            }
        }
    }

    var twoFactorSheet: some View {
        NavigationView {
            VStack(spacing: 20) {
                Image(systemName: "lock.shield.fill").font(.system(size: 48))
                    .foregroundStyle(LinearGradient(colors: [.orange, .red], startPoint: .top, endPoint: .bottom))
                Text("Two-Factor Authentication").font(.title2.bold())
                Text("Enter the 6-digit code sent to your trusted devices.")
                    .font(.subheadline).foregroundColor(.secondary).multilineTextAlignment(.center)
                TextField("000000", text: $twoFactorCode)
                    .keyboardType(.numberPad).multilineTextAlignment(.center)
                    .font(.system(size: 32, weight: .bold, design: .monospaced))
                    .frame(maxWidth: 160).padding()
                    .background(Color(.secondarySystemBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                Button {
                    showingTwoFactor = false
                    twoFactorContinuation?(twoFactorCode)
                    twoFactorCode = ""
                } label: {
                    Text("Submit").font(.headline).frame(maxWidth: .infinity).padding()
                        .background(LinearGradient(colors: [.orange, .red], startPoint: .leading, endPoint: .trailing))
                        .foregroundColor(.white).clipShape(RoundedRectangle(cornerRadius: 14))
                }
                .padding(.horizontal).disabled(twoFactorCode.count < 6)
            }
            .padding().navigationTitle("Verification").navigationBarTitleDisplayMode(.inline)
        }
    }

    var canSign: Bool {
        switch signingMethod {
        case .appleID: return !config.appleID.isEmpty && !config.password.isEmpty
        case .customP12: return p12Data != nil && provisionData != nil
        }
    }

    func startSigning() {
        signingState = .signing
        switch signingMethod {
        case .appleID:
            SigningService.shared.signWithAppleID(
                ipaURL: ipaURL, appleID: config.appleID, password: config.password,
                bundleID: bundleID, appName: appName,
                twoFactorHandler: { _, cont in
                    DispatchQueue.main.async { twoFactorContinuation = cont; showingTwoFactor = true }
                },
                progress: { msg in DispatchQueue.main.async { progressMessage = msg } },
                completion: handleSigningResult
            )
        case .customP12:
            guard let p12 = p12Data, let provision = provisionData else { return }
            SigningService.shared.signWithP12(
                ipaURL: ipaURL, p12Data: p12, p12Password: p12Password,
                provisionData: provision, bundleID: bundleID, appName: appName,
                completion: handleSigningResult
            )
        }
    }

    func handleSigningResult(_ result: Result<URL, Error>) {
        DispatchQueue.main.async {
            switch result {
            case .success(let signedURL):
                let expiry = Calendar.current.date(byAdding: .day, value: 7, to: Date())!
                let app = SignedApp(name: appName.isEmpty ? ipaURL.lastPathComponent : appName,
                                   bundleID: bundleID, version: version,
                                   signedDate: Date(), expiryDate: expiry, iconData: iconData)
                appState.installedApps.append(app)
                signingState = .success
                OTAInstallService.shared.install(ipaURL: signedURL, bundleID: bundleID)
            case .failure(let error):
                signingState = .failed(error.localizedDescription)
            }
        }
    }
}
