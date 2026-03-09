import Foundation
import Security

class SigningConfig: ObservableObject, Codable {
    @Published var appleID: String = ""
    @Published var password: String = ""
    @Published var useCustomProfile: Bool = false
    @Published var provisioningProfileData: Data? = nil
    @Published var overrideBundleID: String = ""
    @Published var overrideAppName: String = ""

    enum CodingKeys: String, CodingKey {
        case appleID, useCustomProfile, overrideBundleID, overrideAppName
    }

    required init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        appleID          = try c.decodeIfPresent(String.self, forKey: .appleID) ?? ""
        useCustomProfile = try c.decodeIfPresent(Bool.self, forKey: .useCustomProfile) ?? false
        overrideBundleID = try c.decodeIfPresent(String.self, forKey: .overrideBundleID) ?? ""
        overrideAppName  = try c.decodeIfPresent(String.self, forKey: .overrideAppName) ?? ""
        // Load password from Keychain
        password = KeychainHelper.load(account: appleID) ?? ""
    }

    init() {
        // Load saved Apple ID from UserDefaults, password from Keychain
        if let savedID = UserDefaults.standard.string(forKey: "flaresign.appleID") {
            appleID  = savedID
            password = KeychainHelper.load(account: savedID) ?? ""
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(appleID,          forKey: .appleID)
        try c.encode(useCustomProfile, forKey: .useCustomProfile)
        try c.encode(overrideBundleID, forKey: .overrideBundleID)
        try c.encode(overrideAppName,  forKey: .overrideAppName)
    }

    /// Call this whenever appleID or password changes to persist them
    func save() {
        UserDefaults.standard.set(appleID, forKey: "flaresign.appleID")
        if !appleID.isEmpty {
            KeychainHelper.save(password: password, account: appleID)
        }
    }
}

// MARK: - Keychain helper
struct KeychainHelper {
    private static let service = "com.flaresign.app"

    static func save(password: String, account: String) {
        guard let data = password.data(using: .utf8) else { return }
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]
        SecItemDelete(query as CFDictionary)
        var item = query
        item[kSecValueData] = data
        SecItemAdd(item as CFDictionary, nil)
    }

    static func load(account: String) -> String? {
        guard !account.isEmpty else { return nil }
        let query: [CFString: Any] = [
            kSecClass:            kSecClassGenericPassword,
            kSecAttrService:      service,
            kSecAttrAccount:      account,
            kSecReturnData:       true,
            kSecMatchLimit:       kSecMatchLimitOne
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let password = String(data: data, encoding: .utf8) else { return nil }
        return password
    }
}
