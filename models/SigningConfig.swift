import Foundation

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
        appleID = try c.decodeIfPresent(String.self, forKey: .appleID) ?? ""
        useCustomProfile = try c.decodeIfPresent(Bool.self, forKey: .useCustomProfile) ?? false
        overrideBundleID = try c.decodeIfPresent(String.self, forKey: .overrideBundleID) ?? ""
        overrideAppName = try c.decodeIfPresent(String.self, forKey: .overrideAppName) ?? ""
    }

    init() {}

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(appleID, forKey: .appleID)
        try c.encode(useCustomProfile, forKey: .useCustomProfile)
        try c.encode(overrideBundleID, forKey: .overrideBundleID)
        try c.encode(overrideAppName, forKey: .overrideAppName)
    }
}
