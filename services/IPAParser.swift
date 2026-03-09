import Foundation
import UIKit
import zlib

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
            let tmp = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString)
            do {
                try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
                defer { try? FileManager.default.removeItem(at: tmp) }

                guard let zipData = try? Data(contentsOf: url) else {
                    completion(info); return
                }

                // Parse ZIP central directory and extract only what we need
                guard let entries = parseZipEntries(data: zipData) else {
                    completion(info); return
                }

                let extractDir = tmp.appendingPathComponent("x")
                try FileManager.default.createDirectory(at: extractDir, withIntermediateDirectories: true)

                for entry in entries {
                    let lower = entry.name.lowercased()
                    let parts = lower.components(separatedBy: "/")
                    // Only care about files directly inside Payload/App.app/
                    guard parts.count == 3, parts[0] == "payload",
                          parts[1].hasSuffix(".app") else { continue }
                    let isInfoPlist = parts[2] == "info.plist"
                    let isIcon = parts[2].hasSuffix(".png") &&
                                 (parts[2].contains("appicon") || parts[2].contains("icon"))
                    guard isInfoPlist || isIcon else { continue }

                    if let fileData = extractEntry(entry, from: zipData) {
                        let dest = extractDir.appendingPathComponent(entry.name)
                        try? FileManager.default.createDirectory(
                            at: dest.deletingLastPathComponent(),
                            withIntermediateDirectories: true)
                        try? fileData.write(to: dest)
                    }
                }

                // Find .app directory
                let payloadDir = extractDir.appendingPathComponent("Payload")
                let apps = (try? FileManager.default.contentsOfDirectory(
                    at: payloadDir, includingPropertiesForKeys: nil)) ?? []
                guard let appDir = apps.first(where: { $0.pathExtension == "app" }) else {
                    completion(info); return
                }

                // Parse Info.plist
                let plistURL = appDir.appendingPathComponent("Info.plist")
                guard let plistData = try? Data(contentsOf: plistURL),
                      let plist = try? PropertyListSerialization.propertyList(
                          from: plistData, format: nil) as? [String: Any] else {
                    completion(info); return
                }

                info.name      = plist["CFBundleDisplayName"] as? String
                               ?? plist["CFBundleName"] as? String ?? ""
                info.bundleID  = plist["CFBundleIdentifier"] as? String ?? ""
                info.version   = plist["CFBundleShortVersionString"] as? String ?? ""

                // Find icon name from plist
                let iconsDict = plist["CFBundleIcons"] as? [String: Any]
                let primaryIcon = iconsDict?["CFBundlePrimaryIcon"] as? [String: Any]
                let iconName = (primaryIcon?["CFBundleIconFiles"] as? [String])?.last
                    ?? (plist["CFBundleIconFiles"] as? [String])?.last

                // Try plist-specified icon first
                if let name = iconName {
                    for suffix in ["@3x", "@2x", ""] {
                        let iconURL = appDir.appendingPathComponent("\(name)\(suffix).png")
                        if let data = try? Data(contentsOf: iconURL) {
                            info.iconData = data; break
                        }
                    }
                }

                // Fallback: any AppIcon png in the .app
                if info.iconData == nil {
                    let contents = (try? FileManager.default.contentsOfDirectory(
                        at: appDir, includingPropertiesForKeys: nil)) ?? []
                    info.iconData = contents
                        .filter { $0.pathExtension == "png" &&
                                  $0.lastPathComponent.lowercased().contains("icon") }
                        .sorted { $0.lastPathComponent > $1.lastPathComponent }
                        .compactMap { try? Data(contentsOf: $0) }
                        .first
                }

            } catch {}

            completion(info)
        }
    }

    // MARK: - ZIP parsing

    struct ZipEntry {
        let name: String
        let localOffset: Int
        let compressedSize: Int
        let uncompressedSize: Int
        let method: UInt16
    }

    static func parseZipEntries(data: Data) -> [ZipEntry]? {
        let bytes = data
        guard bytes.count > 22 else { return nil }

        // Locate End of Central Directory
        var eocd = -1
        let minSearch = max(0, bytes.count - 65557)
        for i in stride(from: bytes.count - 22, through: minSearch, by: -1) {
            if bytes[i] == 0x50, bytes[i+1] == 0x4B,
               bytes[i+2] == 0x05, bytes[i+3] == 0x06 {
                eocd = i; break
            }
        }
        guard eocd >= 0 else { return nil }

        let cdCount  = Int(bytes.le16(eocd + 8))
        let cdOffset = Int(bytes.le32(eocd + 16))

        var entries: [ZipEntry] = []
        var pos = cdOffset
        for _ in 0..<cdCount {
            guard pos + 46 <= bytes.count,
                  bytes[pos] == 0x50, bytes[pos+1] == 0x4B,
                  bytes[pos+2] == 0x01, bytes[pos+3] == 0x02 else { break }

            let method     = bytes.le16(pos + 10)
            let compSize   = Int(bytes.le32(pos + 20))
            let uncompSize = Int(bytes.le32(pos + 24))
            let nameLen    = Int(bytes.le16(pos + 28))
            let extraLen   = Int(bytes.le16(pos + 30))
            let commentLen = Int(bytes.le16(pos + 32))
            let localOff   = Int(bytes.le32(pos + 42))

            if nameLen > 0, pos + 46 + nameLen <= bytes.count,
               let name = String(data: bytes.subdata(in: (pos+46)..<(pos+46+nameLen)),
                                 encoding: .utf8) {
                entries.append(ZipEntry(name: name, localOffset: localOff,
                                        compressedSize: compSize,
                                        uncompressedSize: uncompSize, method: method))
            }
            pos += 46 + nameLen + extraLen + commentLen
        }
        return entries
    }

    static func extractEntry(_ entry: ZipEntry, from data: Data) -> Data? {
        let base = entry.localOffset
        guard base + 30 <= data.count else { return nil }
        let nameLen  = Int(data.le16(base + 26))
        let extraLen = Int(data.le16(base + 28))
        let start    = base + 30 + nameLen + extraLen
        guard start + entry.compressedSize <= data.count else { return nil }

        let compressed = data.subdata(in: start..<(start + entry.compressedSize))

        switch entry.method {
        case 0: // stored
            return compressed
        case 8: // deflate
            return inflateDeflate(compressed, expectedSize: entry.uncompressedSize)
        default:
            return nil
        }
    }

    static func inflateDeflate(_ data: Data, expectedSize: Int) -> Data? {
        var output = Data(count: max(expectedSize, 1))
        let result = output.withUnsafeMutableBytes { outBuf in
            data.withUnsafeBytes { inBuf -> Bool in
                var stream = z_stream()
                stream.next_in   = UnsafeMutablePointer(mutating: inBuf.bindMemory(to: UInt8.self).baseAddress!)
                stream.avail_in  = uInt(data.count)
                stream.next_out  = outBuf.bindMemory(to: UInt8.self).baseAddress!
                stream.avail_out = uInt(expectedSize)
                guard inflateInit2_(&stream, -15, ZLIB_VERSION,
                                    Int32(MemoryLayout<z_stream>.size)) == Z_OK else { return false }
                let status = inflate(&stream, Z_FINISH)
                inflateEnd(&stream)
                return status == Z_STREAM_END || status == Z_OK
            }
        }
        return result ? output : nil
    }
}

private extension Data {
    func le16(_ i: Int) -> UInt16 {
        UInt16(self[i]) | (UInt16(self[i+1]) << 8)
    }
    func le32(_ i: Int) -> UInt32 {
        UInt32(self[i]) | (UInt32(self[i+1]) << 8) |
        (UInt32(self[i+2]) << 16) | (UInt32(self[i+3]) << 24)
    }
}
