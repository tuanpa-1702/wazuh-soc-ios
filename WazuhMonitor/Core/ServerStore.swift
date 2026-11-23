import Foundation
import Security

struct ServerConfig: Codable, Identifiable, Hashable {
    var id = UUID()
    var name: String
    /// Wazuh server API, ví dụ https://192.168.1.10:55000
    var url: String
    var username: String
    /// Wazuh Indexer (OpenSearch), ví dụ https://192.168.1.10:9200 — để trống nếu không dùng.
    var indexerURL: String = ""
    var indexerUsername: String = "admin"
    var allowInsecure: Bool = true
    /// Cloudflare Access service token (Client ID); Client Secret lưu trong Keychain.
    var cfClientID: String = ""

    var displayName: String { name.trimmed.isEmpty ? url : name }

    init(name: String, url: String, username: String) {
        self.name = name
        self.url = url
        self.username = username
    }

    // Đọc mềm dẻo để cấu hình đã lưu từ bản cũ vẫn dùng được khi thêm trường mới.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        url = try c.decodeIfPresent(String.self, forKey: .url) ?? ""
        username = try c.decodeIfPresent(String.self, forKey: .username) ?? ""
        indexerURL = try c.decodeIfPresent(String.self, forKey: .indexerURL) ?? ""
        indexerUsername = try c.decodeIfPresent(String.self, forKey: .indexerUsername) ?? "admin"
        allowInsecure = try c.decodeIfPresent(Bool.self, forKey: .allowInsecure) ?? true
        cfClientID = try c.decodeIfPresent(String.self, forKey: .cfClientID) ?? ""
    }
}

/// Lưu mật khẩu vào Keychain của iPhone.
enum Keychain {
    private static let service = "WazuhMonitor"

    private static func baseQuery(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    static func set(_ value: String, for account: String) {
        SecItemDelete(baseQuery(account) as CFDictionary)
        var add = baseQuery(account)
        add[kSecValueData as String] = Data(value.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        SecItemAdd(add as CFDictionary, nil)
    }

    static func get(_ account: String) -> String? {
        var q = baseQuery(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func delete(_ account: String) {
        SecItemDelete(baseQuery(account) as CFDictionary)
    }
}

@MainActor
final class ServerStore: ObservableObject {
    @Published private(set) var servers: [ServerConfig] = []
    @Published private(set) var client: WazuhClient?
    /// Đổi mỗi khi kết nối thay đổi để các màn hình tải lại dữ liệu.
    @Published private(set) var connectionToken = UUID()
    @Published var activeID: UUID? {
        didSet {
            UserDefaults.standard.set(activeID?.uuidString, forKey: Self.activeKey)
            rebuildClient()
        }
    }

    private static let serversKey = "servers.v1"
    private static let activeKey = "activeServer.v1"

    init() {
        if let data = UserDefaults.standard.data(forKey: Self.serversKey),
           let list = try? JSONDecoder().decode([ServerConfig].self, from: data) {
            servers = list
        }
        let saved = UserDefaults.standard.string(forKey: Self.activeKey).flatMap(UUID.init(uuidString:))
        activeID = servers.first(where: { $0.id == saved })?.id ?? servers.first?.id
        rebuildClient()
        #if DEBUG
        // Kiểm thử: -debug.server "apiURL|indexerURL|user|pass"
        if let spec = UserDefaults.standard.string(forKey: "debug.server") {
            let p = spec.components(separatedBy: "|")
            if p.count >= 4 {
                var s = servers.first(where: { $0.name == "Mock" }) ?? ServerConfig(name: "Mock", url: p[0], username: p[2])
                s.url = p[0]; s.indexerURL = p[1]; s.username = p[2]; s.indexerUsername = p[2]; s.allowInsecure = true
                upsert(s, password: p[3], indexerPassword: p[3], cfSecret: "")
                activeID = s.id
            }
        }
        #endif
    }

    var activeServer: ServerConfig? { servers.first { $0.id == activeID } }

    static func indexerAccount(_ id: UUID) -> String { id.uuidString + ".indexer" }
    static func cfAccount(_ id: UUID) -> String { id.uuidString + ".cfsecret" }

    func cfSecret(for server: ServerConfig) -> String {
        Keychain.get(Self.cfAccount(server.id)) ?? ""
    }

    func password(for server: ServerConfig) -> String {
        Keychain.get(server.id.uuidString) ?? ""
    }

    func indexerPassword(for server: ServerConfig) -> String {
        Keychain.get(Self.indexerAccount(server.id)) ?? ""
    }

    func upsert(_ server: ServerConfig, password: String, indexerPassword: String, cfSecret: String) {
        if let i = servers.firstIndex(where: { $0.id == server.id }) {
            servers[i] = server
        } else {
            servers.append(server)
        }
        Keychain.set(password, for: server.id.uuidString)
        Keychain.set(indexerPassword, for: Self.indexerAccount(server.id))
        Keychain.set(cfSecret, for: Self.cfAccount(server.id))
        persist()
        if activeID == nil || activeID == server.id {
            activeID = server.id
        }
    }

    func delete(_ server: ServerConfig) {
        servers.removeAll { $0.id == server.id }
        Keychain.delete(server.id.uuidString)
        Keychain.delete(Self.indexerAccount(server.id))
        Keychain.delete(Self.cfAccount(server.id))
        persist()
        if activeID == server.id { activeID = servers.first?.id }
    }

    private func persist() {
        if let data = try? JSONEncoder().encode(servers) {
            UserDefaults.standard.set(data, forKey: Self.serversKey)
        }
    }

    private func rebuildClient() {
        client = activeServer.map {
            WazuhClient(server: $0, password: password(for: $0), indexerPassword: indexerPassword(for: $0), cfSecret: cfSecret(for: $0))
        }
        connectionToken = UUID()
    }
}
