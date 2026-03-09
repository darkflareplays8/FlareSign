import Foundation
import Security
import CryptoKit

// MARK: - Anisette Data
struct AnisetteData: Codable {
    let machineID: String
    let oneTimePassword: String
    let localUserID: String
    let routingInfo: String
    let deviceDescription: String
    let date: String

    enum CodingKeys: String, CodingKey {
        case machineID = "X-Apple-I-MD-M"
        case oneTimePassword = "X-Apple-I-MD"
        case localUserID = "X-Apple-I-MD-LU"
        case routingInfo = "X-Apple-I-MD-RINFO"
        case deviceDescription = "X-MMe-Client-Info"
        case date = "X-Apple-I-Client-Time"
    }
}

// MARK: - Auth Result
struct AppleAuthResult {
    let adsid: String
    let token: String
    let certificate: Data
    let privateKey: SecKey
    let provisioningProfile: Data
    let teamID: String
}

enum AppleAuthError: LocalizedError {
    case anisetteUnavailable
    case authFailed(String)
    case certFailed(String)
    case provisionFailed(String)
    case twoFactorRequired(String, String, AnisetteData, ([String: Any]) -> Void)

    var errorDescription: String? {
        switch self {
        case .anisetteUnavailable: return "Anisette server unavailable. Check your connection."
        case .authFailed(let m): return "Authentication failed: \(m)"
        case .certFailed(let m): return "Certificate generation failed: \(m)"
        case .provisionFailed(let m): return "Provisioning profile failed: \(m)"
        case .twoFactorRequired: return "Two-factor authentication required."
        }
    }
}

// MARK: - Apple Auth Service
class AppleAuthService {
    static let shared = AppleAuthService()
    static let anisetteURL = "https://ani.sidestore.io"

    // MARK: Full auth + cert + provision flow
    func authenticate(
        appleID: String,
        password: String,
        bundleID: String,
        twoFactorHandler: @escaping (String, @escaping (String) -> Void) -> Void,
        completion: @escaping (Result<AppleAuthResult, Error>) -> Void
    ) {
        fetchAnisetteData { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let e): completion(.failure(e))
            case .success(let anisette):
                self.gsaAuthenticate(appleID: appleID, password: password, anisette: anisette,
                                     twoFactorHandler: twoFactorHandler) { authResult in
                    switch authResult {
                    case .failure(let e): completion(.failure(e))
                    case .success(let (adsid, token)):
                        self.fetchCertificateAndProvision(adsid: adsid, token: token,
                                                          bundleID: bundleID, anisette: anisette,
                                                          completion: completion)
                    }
                }
            }
        }
    }

    // MARK: Fetch Anisette
    func fetchAnisetteData(completion: @escaping (Result<AnisetteData, Error>) -> Void) {
        guard let url = URL(string: "\(Self.anisetteURL)/v3") else {
            completion(.failure(AppleAuthError.anisetteUnavailable)); return
        }
        URLSession.shared.dataTask(with: url) { data, _, error in
            if let error { completion(.failure(error)); return }
            guard let data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                completion(.failure(AppleAuthError.anisetteUnavailable)); return
            }
            // v3 server returns flat dict with headers
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime]
            let dateStr = formatter.string(from: Date())

            let anisette = AnisetteData(
                machineID: json["X-Apple-I-MD-M"] as? String ?? "",
                oneTimePassword: json["X-Apple-I-MD"] as? String ?? "",
                localUserID: json["X-Apple-I-MD-LU"] as? String ?? "",
                routingInfo: json["X-Apple-I-MD-RINFO"] as? String ?? "17106176",
                deviceDescription: json["X-MMe-Client-Info"] as? String
                    ?? "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
                date: dateStr
            )
            completion(.success(anisette))
        }.resume()
    }

    // MARK: GSA Authentication (SRP-6a via Apple GrandSlam)
    private func gsaAuthenticate(
        appleID: String,
        password: String,
        anisette: AnisetteData,
        twoFactorHandler: @escaping (String, @escaping (String) -> Void) -> Void,
        completion: @escaping (Result<(String, String), Error>) -> Void
    ) {
        // Step 1: Init SRP
        guard let url = URL(string: "https://gsa.apple.com/grandslam/GsService2/lookup") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
        req.setValue("application/x-apple-plist", forHTTPHeaderField: "Accept")
        applyAnisetteHeaders(anisette, to: &req)

        let initBody: [String: Any] = [
            "A2k": srpPublicKey(),
            "cpd": anisetteDict(anisette),
            "o": "init",
            "ps": ["s2k", "s2k_fo"],
            "u": appleID
        ]

        guard let plistData = try? PropertyListSerialization.data(fromPropertyList: initBody, format: .xml, options: 0) else {
            completion(.failure(AppleAuthError.authFailed("Failed to build init request"))); return
        }
        req.httpBody = plistData

        URLSession.shared.dataTask(with: req) { [weak self] data, _, error in
            guard let self else { return }
            if let error { completion(.failure(error)); return }
            guard let data,
                  let resp = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                completion(.failure(AppleAuthError.authFailed("Invalid init response"))); return
            }

            if let status = (resp["Status"] as? [String: Any])?["ec"] as? Int, status != 0 {
                let msg = (resp["Status"] as? [String: Any])?["em"] as? String ?? "Unknown error"
                completion(.failure(AppleAuthError.authFailed(msg))); return
            }

            guard let salt = resp["s"] as? Data,
                  let serverB = resp["B"] as? Data,
                  let iterations = resp["i"] as? Int,
                  let sessionKey = resp["c"] as? String else {
                completion(.failure(AppleAuthError.authFailed("Missing SRP parameters"))); return
            }

            self.completeSRP(appleID: appleID, password: password, salt: salt,
                             serverB: serverB, iterations: iterations, sessionKey: sessionKey,
                             anisette: anisette, twoFactorHandler: twoFactorHandler,
                             completion: completion)
        }.resume()
    }

    private func completeSRP(
        appleID: String, password: String, salt: Data, serverB: Data,
        iterations: Int, sessionKey: String, anisette: AnisetteData,
        twoFactorHandler: @escaping (String, @escaping (String) -> Void) -> Void,
        completion: @escaping (Result<(String, String), Error>) -> Void
    ) {
        guard let url = URL(string: "https://gsa.apple.com/grandslam/GsService2/complete") else { return }

        // Derive password key using PBKDF2
        let passwordKey = pbkdf2(password: password, salt: salt, iterations: iterations)
        let (M1, _) = srpClientProof(appleID: appleID, passwordKey: passwordKey, salt: salt, serverB: serverB)

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
        req.setValue("application/x-apple-plist", forHTTPHeaderField: "Accept")
        applyAnisetteHeaders(anisette, to: &req)

        let completeBody: [String: Any] = [
            "M1": M1,
            "c": sessionKey,
            "cpd": anisetteDict(anisette),
            "o": "complete",
            "u": appleID
        ]

        guard let plistData = try? PropertyListSerialization.data(fromPropertyList: completeBody, format: .xml, options: 0) else {
            completion(.failure(AppleAuthError.authFailed("Failed to build complete request"))); return
        }
        req.httpBody = plistData

        URLSession.shared.dataTask(with: req) { [weak self] data, _, error in
            guard let self else { return }
            if let error { completion(.failure(error)); return }
            guard let data,
                  let resp = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                completion(.failure(AppleAuthError.authFailed("Invalid complete response"))); return
            }

            let statusCode = (resp["Status"] as? [String: Any])?["ec"] as? Int ?? -1

            // 2FA required
            if statusCode == -22421 || statusCode == -22406 {
                let adsid = resp["adsid"] as? String ?? ""
                let idmsToken = resp["idms_token"] as? String ?? ""
                twoFactorHandler(appleID) { code in
                    self.submitTwoFactor(code: code, adsid: adsid, idmsToken: idmsToken,
                                         anisette: anisette, completion: completion)
                }
                return
            }

            if statusCode != 0 {
                let msg = (resp["Status"] as? [String: Any])?["em"] as? String ?? "Unknown"
                completion(.failure(AppleAuthError.authFailed(msg))); return
            }

            guard let adsid = resp["adsid"] as? String,
                  let token = resp["t"] as? [String: Any],
                  let mmeToken = (token["com.apple.gs.idms.pet"] as? [String: Any] ?? token.values.first as? [String: Any])?["token"] as? String else {
                completion(.failure(AppleAuthError.authFailed("Missing auth tokens"))); return
            }

            completion(.success((adsid, mmeToken)))
        }.resume()
    }

    private func submitTwoFactor(
        code: String, adsid: String, idmsToken: String,
        anisette: AnisetteData,
        completion: @escaping (Result<(String, String), Error>) -> Void
    ) {
        guard let url = URL(string: "https://gsa.apple.com/grandslam/GsService2/validate") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
        applyAnisetteHeaders(anisette, to: &req)
        req.setValue(idmsToken, forHTTPHeaderField: "X-Apple-IDMS-Token")
        req.setValue(adsid, forHTTPHeaderField: "X-Apple-DS-ID")

        let body: [String: Any] = ["code": code, "cpd": anisetteDict(anisette)]
        req.httpBody = try? PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0)

        URLSession.shared.dataTask(with: req) { data, _, error in
            if let error { completion(.failure(error)); return }
            guard let data,
                  let resp = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let token = (resp["t"] as? [String: Any])?.values.first as? [String: Any],
                  let mmeToken = token["token"] as? String else {
                completion(.failure(AppleAuthError.authFailed("2FA validation failed"))); return
            }
            completion(.success((adsid, mmeToken)))
        }.resume()
    }

    // MARK: Certificate + Provision
    private func fetchCertificateAndProvision(
        adsid: String, token: String, bundleID: String, anisette: AnisetteData,
        completion: @escaping (Result<AppleAuthResult, Error>) -> Void
    ) {
        // Generate key pair for CSR
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            completion(.failure(AppleAuthError.certFailed("Key generation failed"))); return
        }

        let csrData = generateCSR(privateKey: privateKey, publicKey: publicKey)

        // Apple developer API headers
        let serviceURL = "https://developerservices2.apple.com/services/QH65B2/ios"
        fetchTeamID(adsid: adsid, token: token, anisette: anisette, serviceURL: serviceURL) { [weak self] teamResult in
            guard let self else { return }
            switch teamResult {
            case .failure(let e): completion(.failure(e))
            case .success(let teamID):
                self.submitCSR(csrData: csrData, adsid: adsid, token: token, teamID: teamID,
                               anisette: anisette, serviceURL: serviceURL) { certResult in
                    switch certResult {
                    case .failure(let e): completion(.failure(e))
                    case .success(let certData):
                        self.createAppID(bundleID: bundleID, adsid: adsid, token: token,
                                         teamID: teamID, anisette: anisette, serviceURL: serviceURL) { appIDResult in
                            switch appIDResult {
                            case .failure(let e): completion(.failure(e))
                            case .success(let appIDIdentifier):
                                self.fetchProvisioningProfile(
                                    appIDIdentifier: appIDIdentifier, certData: certData,
                                    adsid: adsid, token: token, teamID: teamID,
                                    anisette: anisette, serviceURL: serviceURL
                                ) { provResult in
                                    switch provResult {
                                    case .failure(let e): completion(.failure(e))
                                    case .success(let provData):
                                        let result = AppleAuthResult(
                                            adsid: adsid, token: token,
                                            certificate: certData, privateKey: privateKey,
                                            provisioningProfile: provData, teamID: teamID
                                        )
                                        completion(.success(result))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private func fetchTeamID(adsid: String, token: String, anisette: AnisetteData,
                              serviceURL: String, completion: @escaping (Result<String, Error>) -> Void) {
        guard let url = URL(string: "\(serviceURL)/listTeams.action") else { return }
        var req = appleDevRequest(url: url, adsid: adsid, token: token, anisette: anisette)
        req.httpBody = try? PropertyListSerialization.data(fromPropertyList: ["clientId": "XABBG36SBA"], format: .xml, options: 0)

        URLSession.shared.dataTask(with: req) { data, _, error in
            if let error { completion(.failure(error)); return }
            guard let data,
                  let resp = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let teams = resp["teams"] as? [[String: Any]],
                  let teamID = teams.first?["teamId"] as? String else {
                completion(.failure(AppleAuthError.certFailed("No teams found"))); return
            }
            completion(.success(teamID))
        }.resume()
    }

    private func submitCSR(csrData: Data, adsid: String, token: String, teamID: String,
                            anisette: AnisetteData, serviceURL: String,
                            completion: @escaping (Result<Data, Error>) -> Void) {
        guard let url = URL(string: "\(serviceURL)/submitDevelopmentCSR.action") else { return }
        var req = appleDevRequest(url: url, adsid: adsid, token: token, anisette: anisette)
        let body: [String: Any] = ["csrContent": csrData.base64EncodedString(), "teamId": teamID]
        req.httpBody = try? PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0)

        URLSession.shared.dataTask(with: req) { data, _, error in
            if let error { completion(.failure(error)); return }
            guard let data,
                  let resp = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let certContent = resp["certContent"] as? String,
                  let certData = Data(base64Encoded: certContent) else {
                completion(.failure(AppleAuthError.certFailed("CSR submission failed"))); return
            }
            completion(.success(certData))
        }.resume()
    }

    private func createAppID(bundleID: String, adsid: String, token: String, teamID: String,
                              anisette: AnisetteData, serviceURL: String,
                              completion: @escaping (Result<String, Error>) -> Void) {
        // First try to find existing
        guard let listURL = URL(string: "\(serviceURL)/listAppIds.action") else { return }
        var listReq = appleDevRequest(url: listURL, adsid: adsid, token: token, anisette: anisette)
        listReq.httpBody = try? PropertyListSerialization.data(fromPropertyList: ["teamId": teamID], format: .xml, options: 0)

        URLSession.shared.dataTask(with: listReq) { [weak self] data, _, _ in
            guard let self else { return }
            if let data,
               let resp = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
               let appIDs = resp["appIds"] as? [[String: Any]],
               let existing = appIDs.first(where: { ($0["identifier"] as? String) == bundleID }),
               let identifier = existing["appIdId"] as? String {
                completion(.success(identifier)); return
            }

            // Create new
            guard let createURL = URL(string: "\(serviceURL)/addAppId.action") else { return }
            var createReq = self.appleDevRequest(url: createURL, adsid: adsid, token: token, anisette: anisette)
            let body: [String: Any] = ["identifier": bundleID, "name": bundleID.replacingOccurrences(of: ".", with: " "), "teamId": teamID]
            createReq.httpBody = try? PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0)

            URLSession.shared.dataTask(with: createReq) { data, _, error in
                if let error { completion(.failure(error)); return }
                guard let data,
                      let resp = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                      let appID = resp["appId"] as? [String: Any],
                      let identifier = appID["appIdId"] as? String else {
                    completion(.failure(AppleAuthError.certFailed("App ID creation failed"))); return
                }
                completion(.success(identifier))
            }.resume()
        }.resume()
    }

    private func fetchProvisioningProfile(
        appIDIdentifier: String, certData: Data, adsid: String, token: String,
        teamID: String, anisette: AnisetteData, serviceURL: String,
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        guard let url = URL(string: "\(serviceURL)/downloadTeamProvisioningProfile.action") else { return }
        var req = appleDevRequest(url: url, adsid: adsid, token: token, anisette: anisette)

        // Get device UDID for profile
        let udid = UIDevice.current.identifierForVendor?.uuidString.replacingOccurrences(of: "-", with: "") ?? ""
        let body: [String: Any] = ["appIdId": appIDIdentifier, "teamId": teamID, "deviceId": udid]
        req.httpBody = try? PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0)

        URLSession.shared.dataTask(with: req) { data, _, error in
            if let error { completion(.failure(error)); return }
            guard let data,
                  let resp = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let profContent = resp["provisioningProfileContent"] as? String,
                  let profData = Data(base64Encoded: profContent) else {
                completion(.failure(AppleAuthError.provisionFailed("Profile download failed"))); return
            }
            completion(.success(profData))
        }.resume()
    }

    // MARK: Helpers
    private func appleDevRequest(url: URL, adsid: String, token: String, anisette: AnisetteData) -> URLRequest {
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
        req.setValue("application/x-apple-plist", forHTTPHeaderField: "Accept")
        req.setValue("Xcode", forHTTPHeaderField: "X-Xcode-Version")
        applyAnisetteHeaders(anisette, to: &req)
        let auth = "\(adsid):\(token)".data(using: .utf8)!.base64EncodedString()
        req.setValue("Basic \(auth)", forHTTPHeaderField: "Authorization")
        return req
    }

    private func applyAnisetteHeaders(_ anisette: AnisetteData, to req: inout URLRequest) {
        req.setValue(anisette.machineID, forHTTPHeaderField: "X-Apple-I-MD-M")
        req.setValue(anisette.oneTimePassword, forHTTPHeaderField: "X-Apple-I-MD")
        req.setValue(anisette.localUserID, forHTTPHeaderField: "X-Apple-I-MD-LU")
        req.setValue(anisette.routingInfo, forHTTPHeaderField: "X-Apple-I-MD-RINFO")
        req.setValue(anisette.deviceDescription, forHTTPHeaderField: "X-MMe-Client-Info")
        req.setValue(anisette.date, forHTTPHeaderField: "X-Apple-I-Client-Time")
        req.setValue("en_US", forHTTPHeaderField: "X-Apple-Locale")
        req.setValue("com.apple.gs.xcode.auth", forHTTPHeaderField: "X-Apple-Widget-Key")
    }

    private func anisetteDict(_ anisette: AnisetteData) -> [String: Any] {
        return [
            "X-Apple-I-MD-M": anisette.machineID,
            "X-Apple-I-MD": anisette.oneTimePassword,
            "X-Apple-I-MD-LU": anisette.localUserID,
            "X-Apple-I-MD-RINFO": anisette.routingInfo,
            "X-MMe-Client-Info": anisette.deviceDescription,
            "X-Apple-I-Client-Time": anisette.date,
            "X-Apple-Locale": "en_US"
        ]
    }

    // MARK: SRP-6a helpers (simplified, Apple uses SHA-256 variant)
    private func srpPublicKey() -> Data {
        // 2048-bit SRP public key A = g^a mod N
        // For a real implementation this needs proper big-integer SRP
        // This is a placeholder - real SRP requires BigInt library
        var bytes = [UInt8](repeating: 0, count: 256)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        bytes[0] |= 0x80 // Ensure high bit set
        return Data(bytes)
    }

    private func srpClientProof(appleID: String, passwordKey: Data, salt: Data, serverB: Data) -> (Data, Data) {
        // Placeholder - real SRP-6a client proof M1 = H(H(N)^H(g), H(I), s, A, B, K)
        // Full implementation requires BigInt arithmetic
        var combined = Data()
        combined.append(passwordKey)
        combined.append(salt)
        combined.append(serverB)
        let M1 = Data(SHA256.hash(data: combined))
        let K = Data(SHA256.hash(data: serverB))
        return (M1, K)
    }

    private func pbkdf2(password: String, salt: Data, iterations: Int) -> Data {
        let passwordData = password.data(using: .utf8)!
        var derivedKey = Data(repeating: 0, count: 32)
        derivedKey.withUnsafeMutableBytes { derivedBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password, passwordData.count,
                    saltBytes.baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations),
                    derivedBytes.baseAddress, 32
                )
            }
        }
        return derivedKey
    }

    private func generateCSR(privateKey: SecKey, publicKey: SecKey) -> Data {
        // Simple CSR using Security framework
        guard let pubKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return Data()
        }
        // In practice, build a proper PKCS#10 CSR - this is a minimal placeholder
        return pubKeyData
    }
}
