import Foundation
import Security

class SigningService {
    static let shared = SigningService()

    private let workDir: URL = {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("FlareSign")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }()

    // MARK: Sign with Apple ID (gets cert+provision automatically)
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
            appleID: appleID,
            password: password,
            bundleID: bundleID,
            twoFactorHandler: twoFactorHandler
        ) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let e):
                completion(.failure(e))
            case .success(let auth):
                progress("Signing IPA...")
                // Export p12 from cert + private key
                do {
                    let p12Data = try self.exportP12(cert: auth.certificate, privateKey: auth.privateKey)
                    self.signWithP12(
                        ipaURL: ipaURL,
                        p12Data: p12Data,
                        p12Password: "",
                        provisionData: auth.provisioningProfile,
                        bundleID: bundleID,
                        appName: appName,
                        teamID: auth.teamID,
                        completion: completion
                    )
                } catch {
                    completion(.failure(error))
                }
            }
        }
    }

    // MARK: Sign with custom p12 + mobileprovision
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

                // Make ldid executable
                var attrs = try FileManager.default.attributesOfItem(atPath: ldidPath)
                attrs[.posixPermissions] = 0o755
                try FileManager.default.setAttributes(attrs, ofItemAtPath: ldidPath)

                // Unpack IPA
                let unpackDir = self.workDir.appendingPathComponent("unpack_\(UUID().uuidString)")
                try FileManager.default.createDirectory(at: unpackDir, withIntermediateDirectories: true)
                defer { try? FileManager.default.removeItem(at: unpackDir) }

                try self.run("/usr/bin/unzip", args: ["-o", ipaURL.path, "-d", unpackDir.path])

                let payloadDir = unpackDir.appendingPathComponent("Payload")
                let apps = (try? FileManager.default.contentsOfDirectory(at: payloadDir, includingPropertiesForKeys: nil)) ?? []
                guard let appDir = apps.first(where: { $0.pathExtension == "app" }) else {
                    throw SigningError.noAppBundle
                }

                // Patch Info.plist
                let infoPlistURL = appDir.appendingPathComponent("Info.plist")
                if var plist = try? PropertyListSerialization.propertyList(from: Data(contentsOf: infoPlistURL), format: nil) as? [String: Any] {
                    if !bundleID.isEmpty { plist["CFBundleIdentifier"] = bundleID }
                    if !appName.isEmpty { plist["CFBundleDisplayName"] = appName }
                    if let patched = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0) {
                        try patched.write(to: infoPlistURL)
                    }
                }

                // Copy provisioning profile
                let embeddedProvURL = appDir.appendingPathComponent("embedded.mobileprovision")
                try provisionData.write(to: embeddedProvURL)

                // Build entitlements from provision
                let entitlementsURL = self.workDir.appendingPathComponent("ent_\(UUID().uuidString).plist")
                if let entitlements = self.extractEntitlements(from: provisionData) {
                    try entitlements.write(to: entitlementsURL)
                }
                defer { try? FileManager.default.removeItem(at: entitlementsURL) }

                // Sign with ldid using p12
                var ldidArgs = ["-S\(entitlementsURL.path)", "-K\(p12URL.path)"]
                if !p12Password.isEmpty { ldidArgs.append("-U\(p12Password)") }
                ldidArgs.append(appDir.path)
                try self.run(ldidPath, args: ldidArgs)

                // Repack IPA
                let payloadOutput = self.workDir.appendingPathComponent("Payload")
                try? FileManager.default.removeItem(at: payloadOutput)
                try FileManager.default.copyItem(at: payloadDir, to: payloadOutput)
                defer { try? FileManager.default.removeItem(at: payloadOutput) }

                let zipDir = self.workDir
                try self.run("/usr/bin/zip", args: ["-r", outputURL.path, "Payload"], cwd: zipDir)

                guard FileManager.default.fileExists(atPath: outputURL.path) else {
                    throw SigningError.outputNotFound
                }

                completion(.success(outputURL))
            } catch {
                completion(.failure(error))
            }
        }
    }

    // MARK: Helpers
    private func run(_ path: String, args: [String], cwd: URL? = nil) throws {
        var pid: pid_t = 0
        let allArgs = [path] + args
        var cArgs = allArgs.map { strdup($0) }
        cArgs.append(nil)

        var fileActions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fileActions)

        var spawnAttr: posix_spawnattr_t?
        posix_spawnattr_init(&spawnAttr)

        let result = posix_spawn(&pid, path, &fileActions, &spawnAttr, &cArgs, nil)
        posix_spawn_file_actions_destroy(&fileActions)
        posix_spawnattr_destroy(&spawnAttr)
        cArgs.dropLast().forEach { free($0) }

        guard result == 0 else { throw SigningError.spawnFailed(path) }

        var status: Int32 = 0
        waitpid(pid, &status, 0)
        guard status == 0 else { throw SigningError.nonZeroExit(path, status) }
    }

    private func extractEntitlements(from provisionData: Data) -> Data? {
        // Extract plist from CMS-wrapped mobileprovision
        guard let str = String(data: provisionData, encoding: .ascii),
              let start = str.range(of: "<?xml"),
              let end = str.range(of: "</plist>") else { return nil }
        let plistStr = String(str[start.lowerBound...end.upperBound])
        guard let plistData = plistStr.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any],
              let entitlements = plist["Entitlements"] as? [String: Any],
              let entData = try? PropertyListSerialization.data(fromPropertyList: entitlements, format: .xml, options: 0) else {
            return nil
        }
        return entData
    }

    private func exportP12(cert: Data, privateKey: SecKey) throws -> Data {
        // Import cert
        var certRef: SecCertificate?
        cert.withUnsafeBytes { ptr in
            let cfData = CFDataCreate(nil, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), cert.count)!
            certRef = SecCertificateCreateWithData(nil, cfData)
        }
        guard let certificate = certRef else { throw SigningError.certExportFailed }

        let exportItems: [Any] = [certificate]
        var exportData: CFData?
        let status = SecItemExport(exportItems as CFArray, .formatPKCS12, [], nil, &exportData)
        guard status == errSecSuccess, let data = exportData as Data? else {
            throw SigningError.certExportFailed
        }
        return data
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
