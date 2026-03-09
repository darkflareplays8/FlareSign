import Foundation
import Security
import CryptoKit
import UIKit

struct AnisetteData {
    let machineID: String
    let oneTimePassword: String
    let localUserID: String
    let routingInfo: String
    let deviceDescription: String
    let date: String
}

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

    var errorDescription: String? {
        switch self {
        case .anisetteUnavailable: return "Anisette server unavailable."
        case .authFailed(let m): return "Authentication failed: \(m)"
        case .certFailed(let m): return "Certificate generation failed: \(m)"
        case .provisionFailed(let m): return "Provisioning profile failed: \(m)"
        }
    }
}

class AppleAuthService {
    static let shared = AppleAuthService()

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

    func fetchAnisetteData(completion: @escaping (Result<AnisetteData, Error>) -> Void) {
        guard let url = URL(string: "https://ani.sidestore.io/v3") else {
            completion(.failure(AppleAuthError.anisetteUnavailable)); return
        }
        URLSession.shared.dataTask(with: url) { data, _, error in
            if let error { completion(.failure(error)); return }
            guard let data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                completion(.failure(AppleAuthError.anisetteUnavailable)); return
            }
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime]
            let anisette = AnisetteData(
                machineID: json["X-Apple-I-MD-M"] as? String ?? "",
                oneTimePassword: json["X-Apple-I-MD"] as? String ?? "",
                localUserID: json["X-Apple-I-MD-LU"] as? String ?? "",
                routingInfo: json["X-Apple-I-MD-RINFO"] as? String ?? "17106176",
                deviceDescription: json["X-MMe-Client-Info"] as? String
                    ?? "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
                date: formatter.string(from: Date())
            )
            completion(.success(anisette))
        }.resume()
    }

    private func gsaAuthenticate(
        appleID: String, password: String, anisette: AnisetteData,
        twoFactorHandler: @escaping (String, @escaping (String) -> Void) -> Void,
        completion: @escaping (Result<(String, String), Error>) -> Void
    ) {
        guard let url = URL(string: "https://gsa.apple.com/grandslam/GsService2/lookup") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
        req.setValue("application/x-apple-plist", forHTTPHeaderField: "Accept")
        applyAnisetteHeaders(anisette, to: &req)

        var srpA = [UInt8](repeating: 0, count: 256)
        _ = SecRandomCopyBytes(kSecRandomDefault, srpA.count, &srpA)
        srpA[0] |= 0x80
        let srpAData = Data(srpA)

        let initBody: [String: Any] = [
            "A2k": srpAData,
            "cpd": anisetteDict(anisette),
            "o": "init",
            "ps": ["s2k", "s2k_fo"],
            "u": appleID
        ]
        req.httpBody = try? PropertyListSerialization.data(fromPropertyList: initBody, format: .xml, options: 0)

        URLSession.shared.dataTask(with: req) { [weak self] data, _, error in
            guard let self else { return }
            if let error { completion(.failure(error)); return }
            guard let data,
                  let resp = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                completion(.failure(AppleAuthError.authFailed("Invalid init response"))); return
            }
            if let ec = (resp["Status"] as? [String: Any])?["ec"] as? Int, ec != 0 {
                let msg = (resp["Status"] as? [String: Any])?["em"] as? String ?? "Error \(ec)"
                completion(.failure(AppleAuthError.authFailed(msg))); return
            }
            guard let salt = resp["s"] as? Data,
                  let serverB = resp["B"] as? Data,
                  let iterations = resp["i"] as? Int,
                  let sessionKey = resp["c"] as? String else {
                completion(.failure(AppleAuthError.authFailed("Missing SRP params"))); return
            }
            self.completeSRP(appleID: appleID, password: password, salt: salt,
                             serverB: serverB, iterations: iterations, sessionKey: sessionKey,
                             srpA: srpAData, anisette: anisette,
                             twoFactorHandler: twoFactorHandler, completion: completion)
        }.resume()
    }

    private func completeSRP(
        appleID: String, password: String, salt: Data, serverB: Data,
        iterations: Int, sessionKey: String, srpA: Data, anisette: AnisetteData,
        twoFactorHandler: @escaping (String, @escaping (String) -> Void) -> Void,
        completion: @escaping (Result<(String, String), Error>) -> Void
    ) {
        guard let url = URL(string: "https://gsa.apple.com/grandslam/GsService2/complete") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
        req.setValue("application/x-apple-plist", forHTTPHeaderField: "Accept")
        applyAnisetteHeaders(anisette, to: &req)

        // PBKDF2 using CryptoKit-compatible approach
        let passwordKey = pbkdf2SHA256(password: password, salt: salt, iterations: iterations)
        var combined = Data()
        combined.append(passwordKey)
        combined.append(salt)
        combined.append(serverB)
        let M1 = Data(SHA256.hash(data: combined))

        let completeBody: [String: Any] = [
            "M1": M1,
            "c": sessionKey,
            "cpd": anisetteDict(anisette),
            "o": "complete",
            "u": appleID
        ]
        req.httpBody = try? PropertyListSerialization.data(fromPropertyList: completeBody, format: .xml, options: 0)

        URLSession.shared.dataTask(with: req) { [weak self] data, _, error in
            guard let self else { return }
            if let error { completion(.failure(error)); return }
            guard let data,
                  let resp = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                completion(.failure(AppleAuthError.authFailed("Invalid complete response"))); return
            }
            let ec = (resp["Status"] as? [String: Any])?["ec"] as? Int ?? -1
            if ec == -22421 || ec == -22406 {
                let adsid = resp["adsid"] as? String ?? ""
                let idmsToken = resp["idms_token"] as? String ?? ""
                twoFactorHandler(appleID) { code in
                    self.submitTwoFactor(code: code, adsid: adsid, idmsToken: idmsToken,
                                         anisette: anisette, completion: completion)
                }
                return
            }
            if ec != 0 {
                let msg = (resp["Status"] as? [String: Any])?["em"] as? String ?? "Error \(ec)"
                completion(.failure(AppleAuthError.authFailed(msg))); return
            }
            guard let adsid = resp["adsid"] as? String,
                  let tDict = resp["t"] as? [String: Any],
                  let petDict = (tDict["com.apple.gs.idms.pet"] as? [String: Any]) ?? tDict.values.first as? [String: Any],
                  let mmeToken = petDict["token"] as? String else {
                completion(.failure(AppleAuthError.authFailed("Missing tokens"))); return
            }
            completion(.success((adsid, mmeToken)))
        }.resume()
    }

    private func submitTwoFactor(
        code: String, adsid: String, idmsToken: String, anisette: AnisetteData,
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
                  let tDict = resp["t"] as? [String: Any],
                  let first = tDict.values.first as? [String: Any],
                  let token = first["token"] as? String else {
                completion(.failure(AppleAuthError.authFailed("2FA failed"))); return
            }
            completion(.success((adsid, token)))
        }.resume()
    }

    private func fetchCertificateAndProvision(
        adsid: String, token: String, bundleID: String, anisette: AnisetteData,
        completion: @escaping (Result<AppleAuthResult, Error>) -> Void
    ) {
        let keyAttrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                        kSecAttrKeySizeInBits as String: 2048]
        var cfError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(keyAttrs as CFDictionary, &cfError),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            completion(.failure(AppleAuthError.certFailed("Key gen failed"))); return
        }
        guard let pubKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            completion(.failure(AppleAuthError.certFailed("Key export failed"))); return
        }

        let serviceURL = "https://developerservices2.apple.com/services/QH65B2/ios"
        fetchTeamID(adsid: adsid, token: token, anisette: anisette, serviceURL: serviceURL) { [weak self] tr in
            guard let self else { return }
            switch tr {
            case .failure(let e): completion(.failure(e))
            case .success(let teamID):
                self.submitCSR(pubKeyData: pubKeyData, adsid: adsid, token: token, teamID: teamID,
                               anisette: anisette, serviceURL: serviceURL) { cr in
                    switch cr {
                    case .failure(let e): completion(.failure(e))
                    case .success(let certData):
                        self.createAppID(bundleID: bundleID, adsid: adsid, token: token,
                                         teamID: teamID, anisette: anisette, serviceURL: serviceURL) { ar in
                            switch ar {
                            case .failure(let e): completion(.failure(e))
                            case .success(let appIDId):
                                self.fetchProvisioningProfile(appIDId: appIDId, adsid: adsid, token: token,
                                                              teamID: teamID, anisette: anisette,
                                                              serviceURL: serviceURL) { pr in
                                    switch pr {
                                    case .failure(let e): completion(.failure(e))
                                    case .success(let provData):
                                        completion(.success(AppleAuthResult(
                                            adsid: adsid, token: token, certificate: certData,
                                            privateKey: privateKey, provisioningProfile: provData, teamID: teamID
                                        )))
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
        var req = devRequest(url: url, adsid: adsid, token: token, anisette: anisette)
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

    private func submitCSR(pubKeyData: Data, adsid: String, token: String, teamID: String,
                            anisette: AnisetteData, serviceURL: String,
                            completion: @escaping (Result<Data, Error>) -> Void) {
        guard let url = URL(string: "\(serviceURL)/submitDevelopmentCSR.action") else { return }
        var req = devRequest(url: url, adsid: adsid, token: token, anisette: anisette)
        let body: [String: Any] = ["csrContent": pubKeyData.base64EncodedString(), "teamId": teamID]
        req.httpBody = try? PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0)
        URLSession.shared.dataTask(with: req) { data, _, error in
            if let error { completion(.failure(error)); return }
            guard let data,
                  let resp = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let b64 = resp["certContent"] as? String,
                  let certData = Data(base64Encoded: b64) else {
                completion(.failure(AppleAuthError.certFailed("CSR failed"))); return
            }
            completion(.success(certData))
        }.resume()
    }

    private func createAppID(bundleID: String, adsid: String, token: String, teamID: String,
                              anisette: AnisetteData, serviceURL: String,
                              completion: @escaping (Result<String, Error>) -> Void) {
        guard let listURL = URL(string: "\(serviceURL)/listAppIds.action") else { return }
        var listReq = devRequest(url: listURL, adsid: adsid, token: token, anisette: anisette)
        listReq.httpBody = try? PropertyListSerialization.data(fromPropertyList: ["teamId": teamID], format: .xml, options: 0)
        URLSession.shared.dataTask(with: listReq) { [weak self] data, _, _ in
            guard let self else { return }
            if let data,
               let resp = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
               let appIDs = resp["appIds"] as? [[String: Any]],
               let existing = appIDs.first(where: { ($0["identifier"] as? String) == bundleID }),
               let id = existing["appIdId"] as? String {
                completion(.success(id)); return
            }
            guard let createURL = URL(string: "\(serviceURL)/addAppId.action") else { return }
            var createReq = self.devRequest(url: createURL, adsid: adsid, token: token, anisette: anisette)
            let body: [String: Any] = ["identifier": bundleID,
                                       "name": bundleID.replacingOccurrences(of: ".", with: " "),
                                       "teamId": teamID]
            createReq.httpBody = try? PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0)
            URLSession.shared.dataTask(with: createReq) { data, _, error in
                if let error { completion(.failure(error)); return }
                guard let data,
                      let resp = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                      let appID = resp["appId"] as? [String: Any],
                      let id = appID["appIdId"] as? String else {
                    completion(.failure(AppleAuthError.certFailed("App ID creation failed"))); return
                }
                completion(.success(id))
            }.resume()
        }.resume()
    }

    private func fetchProvisioningProfile(appIDId: String, adsid: String, token: String,
                                           teamID: String, anisette: AnisetteData, serviceURL: String,
                                           completion: @escaping (Result<Data, Error>) -> Void) {
        guard let url = URL(string: "\(serviceURL)/downloadTeamProvisioningProfile.action") else { return }
        var req = devRequest(url: url, adsid: adsid, token: token, anisette: anisette)
        let udid = UIDevice.current.identifierForVendor?.uuidString.replacingOccurrences(of: "-", with: "") ?? ""
        let body: [String: Any] = ["appIdId": appIDId, "teamId": teamID, "deviceId": udid]
        req.httpBody = try? PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0)
        URLSession.shared.dataTask(with: req) { data, _, error in
            if let error { completion(.failure(error)); return }
            guard let data,
                  let resp = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let b64 = resp["provisioningProfileContent"] as? String,
                  let profData = Data(base64Encoded: b64) else {
                completion(.failure(AppleAuthError.provisionFailed("Profile download failed"))); return
            }
            completion(.success(profData))
        }.resume()
    }

    private func devRequest(url: URL, adsid: String, token: String, anisette: AnisetteData) -> URLRequest {
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
        req.setValue("application/x-apple-plist", forHTTPHeaderField: "Accept")
        applyAnisetteHeaders(anisette, to: &req)
        let auth = "\(adsid):\(token)".data(using: .utf8)!.base64EncodedString()
        req.setValue("Basic \(auth)", forHTTPHeaderField: "Authorization")
        return req
    }

    private func applyAnisetteHeaders(_ a: AnisetteData, to req: inout URLRequest) {
        req.setValue(a.machineID, forHTTPHeaderField: "X-Apple-I-MD-M")
        req.setValue(a.oneTimePassword, forHTTPHeaderField: "X-Apple-I-MD")
        req.setValue(a.localUserID, forHTTPHeaderField: "X-Apple-I-MD-LU")
        req.setValue(a.routingInfo, forHTTPHeaderField: "X-Apple-I-MD-RINFO")
        req.setValue(a.deviceDescription, forHTTPHeaderField: "X-MMe-Client-Info")
        req.setValue(a.date, forHTTPHeaderField: "X-Apple-I-Client-Time")
        req.setValue("en_US", forHTTPHeaderField: "X-Apple-Locale")
        req.setValue("com.apple.gs.xcode.auth", forHTTPHeaderField: "X-Apple-Widget-Key")
    }

    private func anisetteDict(_ a: AnisetteData) -> [String: Any] {
        ["X-Apple-I-MD-M": a.machineID, "X-Apple-I-MD": a.oneTimePassword,
         "X-Apple-I-MD-LU": a.localUserID, "X-Apple-I-MD-RINFO": a.routingInfo,
         "X-MMe-Client-Info": a.deviceDescription, "X-Apple-I-Client-Time": a.date,
         "X-Apple-Locale": "en_US"]
    }

    // PBKDF2-SHA256 using pure Swift / CommonCrypto via bridging — use manual HMAC approach
    private func pbkdf2SHA256(password: String, salt: Data, iterations: Int) -> Data {
        guard let passwordData = password.data(using: .utf8) else { return Data() }
        // Use HKDF as a substitute since CommonCrypto isn't available without bridging header
        // For production, add CommonCrypto via a system framework reference
        var result = Data()
        var block = Data()
        block.append(salt)
        block.append(contentsOf: [0, 0, 0, 1]) // block index 1
        var u = Data(HMAC<SHA256>.authenticationCode(for: block, using: SymmetricKey(data: passwordData)))
        result = u
        for _ in 1..<iterations {
            u = Data(HMAC<SHA256>.authenticationCode(for: u, using: SymmetricKey(data: passwordData)))
            result = Data(zip(result, u).map { $0 ^ $1 })
        }
        return Data(result.prefix(32))
    }
}
