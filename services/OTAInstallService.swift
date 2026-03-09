import Foundation
import UIKit

class OTAInstallService {
    static let shared = OTAInstallService()
    private let port = 8765
    private var server: LocalHTTPServer?

    func install(ipaURL: URL, bundleID: String, appName: String) {
        server?.stop()
        server = LocalHTTPServer(port: port)

        let manifest = buildManifest(bundleID: bundleID, appName: appName)

        server?.addRoute("/manifest.plist") { _ in HTTPResponse(body: manifest, contentType: "text/xml") }
        server?.addRoute("/app.ipa") { _ in
            HTTPResponse(body: (try? Data(contentsOf: ipaURL)) ?? Data(), contentType: "application/octet-stream")
        }
        server?.start()

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            let urlStr = "itms-services://?action=download-manifest&url=http://localhost:\(self.port)/manifest.plist"
            if let url = URL(string: urlStr) { UIApplication.shared.open(url) }
        }
    }

    private func buildManifest(bundleID: String, appName: String) -> Data {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>items</key><array><dict>
                <key>assets</key><array><dict>
                    <key>kind</key><string>software-package</string>
                    <key>url</key><string>http://localhost:\(port)/app.ipa</string>
                </dict></array>
                <key>metadata</key><dict>
                    <key>bundle-identifier</key><string>\(bundleID)</string>
                    <key>bundle-version</key><string>1.0</string>
                    <key>kind</key><string>software</string>
                    <key>title</key><string>\(appName)</string>
                </dict>
            </dict></array>
        </dict></plist>
        """.data(using: .utf8) ?? Data()
    }
}

struct HTTPResponse { let body: Data; let contentType: String }

class LocalHTTPServer {
    private let port: Int
    private var routes: [String: (String) -> HTTPResponse] = [:]
    private var running = false

    init(port: Int) { self.port = port }
    func addRoute(_ path: String, handler: @escaping (String) -> HTTPResponse) { routes[path] = handler }
    func start() { running = true; DispatchQueue.global(qos: .background).async { self.runLoop() } }
    func stop() { running = false }

    private func runLoop() {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return }
        defer { close(fd) }
        var opt: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        addr.sin_addr.s_addr = INADDR_ANY
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else { return }
        listen(fd, 5)
        while running {
            let client = accept(fd, nil, nil)
            guard client >= 0 else { continue }
            handleClient(fd: client)
        }
    }

    private func handleClient(fd: Int32) {
        defer { close(fd) }
        var buf = [UInt8](repeating: 0, count: 4096)
        let n = read(fd, &buf, buf.count)
        guard n > 0 else { return }
        let req = String(bytes: buf.prefix(n), encoding: .utf8) ?? ""
        let path = req.components(separatedBy: " ").dropFirst().first ?? "/"
        if let handler = routes[path] {
            let res = handler(req)
            let header = "HTTP/1.1 200 OK\r\nContent-Type: \(res.contentType)\r\nContent-Length: \(res.body.count)\r\nConnection: close\r\n\r\n"
            _ = header.withCString { write(fd, $0, strlen($0)) }
            res.body.withUnsafeBytes { _ = write(fd, $0.baseAddress!, res.body.count) }
        } else {
            _ = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".withCString { write(fd, $0, strlen($0)) }
        }
    }
}
