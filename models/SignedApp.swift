import Foundation

struct SignedApp: Identifiable, Codable, Equatable {
    var id: UUID = UUID()
    var name: String
    var bundleID: String
    var version: String
    var signedDate: Date
    var expiryDate: Date
    var iconData: Data?

    var daysUntilExpiry: Int {
        Calendar.current.dateComponents([.day], from: Date(), to: expiryDate).day ?? 0
    }

    var isExpired: Bool { Date() >= expiryDate }

    var expiryStatus: ExpiryStatus {
        if isExpired { return .expired }
        if daysUntilExpiry <= 1 { return .critical }
        if daysUntilExpiry <= 3 { return .warning }
        return .good
    }

    enum ExpiryStatus { case good, warning, critical, expired }
}
