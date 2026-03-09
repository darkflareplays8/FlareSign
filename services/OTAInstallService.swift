import Foundation
import UIKit

class OTAInstallService {
    static let shared = OTAInstallService()
    private var server: LocalHTTPServer?

    func install(ipaURL: URL, bundleID: String) {
        do {
            let port = 8765
            server = try LocalHTTPServer(ipaURL: ipaURL, bundleID: bundleID, port: port)
            let manifestURL = "http://127.0.0.1:\(port)/manifest.plist"
            let installURL = "itms-services://?action=download-manifest&url=\(manifestURL)"
            guard let url = URL(string: installURL.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? installURL) else { return }
            DispatchQueue.main.async {
                UIApplication.shared.open(url)
            }
        } catch {
            print("OTA install error: \(error)")
        }
    }
}

class LocalHTTPServer {
    private var thread: Thread?
    private var serverSocket: Int32 = -1
    private let ipaURL: URL
    private let bundleID: String
    private let port: Int

    init(ipaURL: URL, bundleID: String, port: Int) throws {
        self.ipaURL = ipaURL
        self.bundleID = bundleID
        self.port = port

        serverSocket = socket(AF_INET, SOCK_STREAM, 0)
        guard serverSocket >= 0 else { throw NSError(domain: "LocalHTTPServer", code: 1) }

        var opt: Int32 = 1
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        addr.sin_addr.s_addr = INADDR_ANY

        let bindResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(serverSocket, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else { throw NSError(domain: "LocalHTTPServer", code: 2) }
        listen(serverSocket, 5)

        thread = Thread { [weak self] in self?.acceptLoop() }
        thread?.start()
    }

    private func acceptLoop() {
        var clientAddr = sockaddr_in()
        var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        for _ in 0..<10 {
            let client = withUnsafeMutablePointer(to: &clientAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(serverSocket, $0, &addrLen)
                }
            }
            guard client >= 0 else { break }
            handleClient(client)
        }
        close(serverSocket)
    }

    private func handleClient(_ client: Int32) {
        var buf = [UInt8](repeating: 0, count: 4096)
        read(client, &buf, buf.count)
        let request = String(bytes: buf, encoding: .utf8) ?? ""

        let response: Data
        if request.contains("GET /manifest.plist") {
            let manifest = buildManifest()
            response = httpResponse(body: manifest, contentType: "text/xml")
        } else if request.contains("GET /app.ipa") {
            response = (try? Data(contentsOf: ipaURL)) ?? Data()
            let header = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: \(response.count)\r\n\r\n"
            let headerData = header.data(using: .utf8)!
            headerData.withUnsafeBytes { write(client, $0.baseAddress, headerData.count) }
            response.withUnsafeBytes { write(client, $0.baseAddress, response.count) }
            close(client)
            return
        } else {
            response = httpResponse(body: Data(), contentType: "text/plain")
        }

        response.withUnsafeBytes { write(client, $0.baseAddress, response.count) }
        close(client)
    }

    private func buildManifest() -> Data {
        let ipaSize = (try? ipaURL.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>items</key>
            <array>
                <dict>
                    <key>assets</key>
                    <array>
                        <dict>
                            <key>kind</key><string>software-package</string>
                            <key>url</key><string>http://127.0.0.1:\(port)/app.ipa</string>
                            <key>md5-size</key><integer>\(ipaSize)</integer>
                        </dict>
                    </array>
                    <key>metadata</key>
                    <dict>
                        <key>bundle-identifier</key><string>\(bundleID)</string>
                        <key>bundle-version</key><string>1.0</string>
                        <key>kind</key><string>software</string>
                        <key>title</key><string>App</string>
                    </dict>
                </dict>
            </array>
        </dict>
        </plist>
        """
        return xml.data(using: .utf8) ?? Data()
    }

    private func httpResponse(body: Data, contentType: String) -> Data {
        let header = "HTTP/1.1 200 OK\r\nContent-Type: \(contentType)\r\nContent-Length: \(body.count)\r\n\r\n"
        var data = header.data(using: .utf8)!
        data.append(body)
        return data
    }
}
