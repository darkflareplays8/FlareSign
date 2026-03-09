import Foundation
import Security

class SigningService {
    static let shared = SigningService()

    private let workDir: URL = {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("FlareSign")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }()

    func signWithAppleID(
        ipaURL: URL,
        appleID: String,
        password: String,
        bundleID: String,
        appName: String,
        twoFactorHandler: @escaping (String, @escaping (String) -> Void) -> Void,
        progress: @escaping (String) -> Void,
        completion: @escaping (Result<URL, Error>) -> Void
    ) {
        progress("Fetching anisette data...")
        AppleAuthService.shared.authenticate(
            appleID: appleID, password: password, bundleID: bundleID,
            twoFactorHandler: twoFactorHandler
        ) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let e): completion(.failure(e))
            case .success(let auth):
                progress("Signing IPA...")
                do {
                    let p12Data = try self.buildP12(cert: auth.certificate, privateKey: auth.privateKey)
                    self.signWithP12(ipaURL: ipaURL, p12Data: p12Data, p12Password: "",
                                     provisionData: auth.provisioningProfile,
                                     bundleID: bundleID, appName: appName,
                                     teamID: auth.teamID, completion: completion)
                } catch {
                    completion(.failure(error))
                }
            }
        }
    }

    func signWithP12(
        ipaURL: URL,
        p12Data: Data,
        p12Password: String,
        provisionData: Data,
        bundleID: String,
        appName: String,
        teamID: String = "",
        completion: @escaping (Result<URL, Error>) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let outputURL = self.workDir.appendingPathComponent("signed_\(UUID().uuidString).ipa")
                let p12URL = self.workDir.appendingPathComponent("cert_\(UUID().uuidString).p12")
                let provURL = self.workDir.appendingPathComponent("profile_\(UUID().uuidString).mobileprovision")

                try p12Data.write(to: p12URL)
                try provisionData.write(to: provURL)
                defer {
                    try? FileManager.default.removeItem(at: p12URL)
                    try? FileManager.default.removeItem(at: provURL)
                }

                guard let ldidPath = Bundle.main.path(forResource: "ldid", ofType: nil) else {
                    throw SigningError.ldidNotFound
                }

                try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: ldidPath)

                let unpackDir = self.workDir.appendingPathComponent("unpack_\(UUID().uuidString)")
                try FileManager.default.createDirectory(at: unpackDir, withIntermediateDirectories: true)
                defer { try? FileManager.default.removeItem(at: unpackDir) }

                try self.run("/usr/bin/unzip", args: ["-o", ipaURL.path, "-d", unpackDir.path])

                let payloadDir = unpackDir.appendingPathComponent("Payload")
                let apps = (try? FileManager.default.contentsOfDirectory(at: payloadDir, includingPropertiesForKeys: nil)) ?? []
                guard let appDir = apps.first(where: { $0.pathExtension == "app" }) else {
                    throw SigningError.noAppBundle
                }

                let infoPlistURL = appDir.appendingPathComponent("Info.plist")
                if var plist = (try? Data(contentsOf: infoPlistURL)).flatMap({
                    try? PropertyListSerialization.propertyList(from: $0, format: nil) as? [String: Any]
                }) {
                    if !bundleID.isEmpty { plist["CFBundleIdentifier"] = bundleID }
                    if !appName.isEmpty { plist["CFBundleDisplayName"] = appName }
                    if let patched = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0) {
                        try patched.write(to: infoPlistURL)
                    }
                }

                try provisionData.write(to: appDir.appendingPathComponent("embedded.mobileprovision"))

                let entURL = self.workDir.appendingPathComponent("ent_\(UUID().uuidString).plist")
                if let entData = self.extractEntitlements(from: provisionData) {
                    try entData.write(to: entURL)
                }
                defer { try? FileManager.default.removeItem(at: entURL) }

                var ldidArgs = ["-S\(entURL.path)", "-K\(p12URL.path)"]
                if !p12Password.isEmpty { ldidArgs.append("-U\(p12Password)") }
                ldidArgs.append(appDir.path)
                try self.run(ldidPath, args: ldidArgs)

                let repackPayload = self.workDir.appendingPathComponent("Payload")
                try? FileManager.default.removeItem(at: repackPayload)
                try FileManager.default.copyItem(at: payloadDir, to: repackPayload)
                defer { try? FileManager.default.removeItem(at: repackPayload) }

                try self.run("/usr/bin/zip", args: ["-r", outputURL.path, "Payload"], cwd: self.workDir)

                guard FileManager.default.fileExists(atPath: outputURL.path) else {
                    throw SigningError.outputNotFound
                }

                completion(.success(outputURL))
            } catch {
                completion(.failure(error))
            }
        }
    }

    private func run(_ path: String, args: [String], cwd: URL? = nil) throws {
        var pid: pid_t = 0
        let all = [path] + args
        var cArgs = all.map { strdup($0) }
        cArgs.append(nil)

        var fa: posix_spawn_file_actions_t?
        var sa: posix_spawnattr_t?
        posix_spawn_file_actions_init(&fa)
        posix_spawnattr_init(&sa)

        let rc = posix_spawn(&pid, path, &fa, &sa, &cArgs, nil)
        posix_spawn_file_actions_destroy(&fa)
        posix_spawnattr_destroy(&sa)
        cArgs.dropLast().forEach { free($0) }

        guard rc == 0 else { throw SigningError.spawnFailed(path) }
        var status: Int32 = 0
        waitpid(pid, &status, 0)
        guard status == 0 else { throw SigningError.nonZeroExit(path, status) }
    }

    private func extractEntitlements(from provisionData: Data) -> Data? {
        guard let str = String(data: provisionData, encoding: .ascii),
              let start = str.range(of: "<?xml"),
              let end = str.range(of: "</plist>") else { return nil }
        let plistStr = String(str[start.lowerBound...end.upperBound])
        guard let plistData = plistStr.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any],
              let ent = plist["Entitlements"] as? [String: Any] else { return nil }
        return try? PropertyListSerialization.data(fromPropertyList: ent, format: .xml, options: 0)
    }

    private func buildP12(cert: Data, privateKey: SecKey) throws -> Data {
        // Wrap cert + key into PKCS12 using raw DER concatenation for ldid
        // ldid accepts DER cert + private key separately via -K flag with PEM
        guard let keyData = SecKeyCopyExternalRepresentation(privateKey, nil) as Data? else {
            throw SigningError.certExportFailed
        }
        // Build a minimal PEM-style p12 by combining cert DER + key DER
        // ldid -K accepts .p12 files — use Security framework to create one
        let certPEM = "-----BEGIN CERTIFICATE-----\n\(cert.base64EncodedString())\n-----END CERTIFICATE-----\n"
        let keyPEM = "-----BEGIN RSA PRIVATE KEY-----\n\(keyData.base64EncodedString())\n-----END RSA PRIVATE KEY-----\n"
        guard let combined = (certPEM + keyPEM).data(using: .utf8) else {
            throw SigningError.certExportFailed
        }
        return combined
    }
}

enum SigningError: LocalizedError {
    case ldidNotFound
    case noAppBundle
    case spawnFailed(String)
    case nonZeroExit(String, Int32)
    case outputNotFound
    case certExportFailed

    var errorDescription: String? {
        switch self {
        case .ldidNotFound: return "ldid binary not found in app bundle."
        case .noAppBundle: return "No .app bundle found in IPA."
        case .spawnFailed(let p): return "Failed to launch \(p)."
        case .nonZeroExit(let p, let c): return "\(p) exited with code \(c)."
        case .outputNotFound: return "Signed IPA was not produced."
        case .certExportFailed: return "Failed to export certificate."
        }
    }
}
