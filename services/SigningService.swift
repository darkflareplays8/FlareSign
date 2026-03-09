import Foundation

class SigningService {
    static let shared = SigningService()

    private let workDir: URL = {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("FlareSign")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }()

    func sign(
        ipaURL: URL,
        appleID: String?,
        password: String?,
        provisioningProfile: Data?,
        bundleID: String,
        appName: String,
        completion: @escaping (Result<URL, Error>) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let outputURL = self.workDir.appendingPathComponent("signed_\(UUID().uuidString).ipa")

                var profileURL: URL?
                if let profileData = provisioningProfile {
                    let pURL = self.workDir.appendingPathComponent("profile_\(UUID().uuidString).mobileprovision")
                    try profileData.write(to: pURL)
                    profileURL = pURL
                }

                guard let zsignPath = Bundle.main.path(forResource: "zsign", ofType: nil) else {
                    throw SigningError.zsignNotFound
                }

                var args = [zsignPath, "-z", "9", "-o", outputURL.path, "-b", bundleID, "-n", appName]
                if let profile = profileURL { args += ["-m", profile.path] }
                if let id = appleID, let pw = password, !id.isEmpty, !pw.isEmpty {
                    args += ["-a", id, "-p", pw]
                }
                args.append(ipaURL.path)

                var pid: pid_t = 0
                var cArgs = args.map { strdup($0) }
                cArgs.append(nil)

                let spawnResult = posix_spawn(&pid, args[0], nil, nil, &cArgs, nil)
                cArgs.dropLast().forEach { free($0) }

                guard spawnResult == 0 else {
                    throw SigningError.zsignFailed("Failed to launch zsign")
                }

                var status: Int32 = 0
                waitpid(pid, &status, 0)

                guard status == 0 else {
                    throw SigningError.zsignFailed("zsign exited with status \(status)")
                }

                guard FileManager.default.fileExists(atPath: outputURL.path) else {
                    throw SigningError.outputNotFound
                }

                completion(.success(outputURL))
            } catch {
                completion(.failure(error))
            }
        }
    }
}

enum SigningError: LocalizedError {
    case zsignNotFound
    case zsignFailed(String)
    case outputNotFound

    var errorDescription: String? {
        switch self {
        case .zsignNotFound: return "zsign binary not found in app bundle."
        case .zsignFailed(let msg): return "Signing failed: \(msg.isEmpty ? "Unknown error" : msg)"
        case .outputNotFound: return "Signed IPA was not produced."
        }
    }
}
