import Foundation
import UIKit

struct IPAInfo {
    var name: String = ""
    var bundleID: String = ""
    var version: String = ""
    var iconData: Data?
}

class IPAParser {
    static func parse(url: URL, completion: @escaping (IPAInfo) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            var info = IPAInfo()
            let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)

            do {
                try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
                defer { try? FileManager.default.removeItem(at: tmp) }

                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
                process.arguments = ["-o", url.path, "Payload/*.app/Info.plist", "Payload/*.app/AppIcon*", "-d", tmp.path]
                try process.run()
                process.waitUntilExit()

                let payload = tmp.appendingPathComponent("Payload")
                let apps = try FileManager.default.contentsOfDirectory(at: payload, includingPropertiesForKeys: nil)
                guard let appDir = apps.first(where: { $0.pathExtension == "app" }) else {
                    completion(info); return
                }

                let plistURL = appDir.appendingPathComponent("Info.plist")
                if let plistData = try? Data(contentsOf: plistURL),
                   let plist = try? PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any] {
                    info.name = plist["CFBundleDisplayName"] as? String ?? plist["CFBundleName"] as? String ?? ""
                    info.bundleID = plist["CFBundleIdentifier"] as? String ?? ""
                    info.version = plist["CFBundleShortVersionString"] as? String ?? ""

                    let iconFiles = (plist["CFBundleIcons"] as? [String: Any])?["CFBundlePrimaryIcon"] as? [String: Any]
                    let iconName = (iconFiles?["CFBundleIconFiles"] as? [String])?.last
                        ?? (plist["CFBundleIconFiles"] as? [String])?.last

                    if let name = iconName {
                        for ext in ["@3x", "@2x", ""] {
                            let iconURL = appDir.appendingPathComponent("\(name)\(ext).png")
                            if let data = try? Data(contentsOf: iconURL) {
                                info.iconData = data; break
                            }
                        }
                    }
                }
            } catch {}

            completion(info)
        }
    }
}
