import SwiftUI

enum ModuleSection: String, CaseIterable, Identifiable {
    case security = "Bảo mật & phát hiện"
    case system = "Hệ thống & tuân thủ"
    case network = "Mạng & syslog"
    case cloud = "Cloud & ứng dụng"
    var id: String { rawValue }
}

struct ModuleField: Hashable {
    let field: String
    let title: String
}

/// Một "dashboard" theo module của Wazuh — định nghĩa bằng bộ lọc cảnh báo và các trường cần thống kê.
struct WazuhModule: Identifiable, Hashable {
    let id: String
    let title: String
    let subtitle: String
    let icon: String
    let color: Color
    /// Mệnh đề lọc OpenSearch; nil = tất cả cảnh báo.
    let filter: JSONValue?
    let fields: [ModuleField]
    var section: ModuleSection = .security

    var extraFilters: [JSONValue] { filter.map { [$0] } ?? [] }
}

private func groups(_ g: [String]) -> JSONValue {
    ["terms": ["rule.groups": .array(g.map { .string($0) })]]
}

private func exists(_ field: String) -> JSONValue {
    ["exists": ["field": .string(field)]]
}

extension WazuhModule {
    /// Log syslog từ thiết bị mạng gửi thẳng tới manager (cổng 514/UDP-TCP):
    /// cảnh báo thuộc agent 000 và `location` là địa chỉ IP của thiết bị gửi.
    static let syslogFilter: JSONValue = [
        "bool": ["filter": [
            ["term": ["agent.id": "000"]],
            ["regexp": ["location": "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+"]],
        ]],
    ]

    static var all: [WazuhModule] { [
        WazuhModule(id: "events", title: L("Sự kiện bảo mật"), subtitle: L("Mọi cảnh báo"), icon: "shield.lefthalf.filled",
                    color: .neonCyan, filter: nil,
                    fields: [.init(field: "rule.description", title: "Rule"), .init(field: "agent.name", title: "Agent"),
                             .init(field: "rule.groups", title: L("Nhóm rule")), .init(field: "data.srcip", title: L("IP nguồn"))]),
        WazuhModule(id: "auth", title: L("Xác thực"), subtitle: L("Đăng nhập thành công / thất bại"), icon: "person.badge.key.fill",
                    color: .neonPink,
                    filter: groups(["authentication_failed", "authentication_success", "authentication_failures",
                                    "win_authentication_failed", "invalid_login"]),
                    fields: [.init(field: "rule.description", title: L("Sự kiện")), .init(field: "data.srcip", title: L("IP nguồn")),
                             .init(field: "data.srcuser", title: L("Người dùng")), .init(field: "data.dstuser", title: L("Tài khoản đích")),
                             .init(field: "data.win.eventdata.targetUserName", title: L("Tài khoản Windows")),
                             .init(field: "agent.name", title: "Agent")]),
        WazuhModule(id: "mitre", title: "MITRE ATT&CK", subtitle: L("Chiến thuật & kỹ thuật tấn công"), icon: "target",
                    color: .neonRed, filter: exists("rule.mitre.id"),
                    fields: [.init(field: "rule.mitre.tactic", title: L("Chiến thuật")), .init(field: "rule.mitre.technique", title: L("Kỹ thuật")),
                             .init(field: "rule.mitre.id", title: L("Mã kỹ thuật")), .init(field: "agent.name", title: "Agent")]),
        WazuhModule(id: "malware", title: L("Phát hiện mã độc"), subtitle: "VirusTotal, YARA, rootkit", icon: "ladybug.fill",
                    color: .neonOrange, filter: groups(["virustotal", "yara", "rootcheck", "malware", "clamd", "freshclam"]),
                    fields: [.init(field: "rule.description", title: L("Phát hiện")), .init(field: "agent.name", title: "Agent"),
                             .init(field: "data.virustotal.source.file", title: L("Tệp")), .init(field: "data.title", title: "Rootcheck")]),
        WazuhModule(id: "fim", title: L("Toàn vẹn tệp (FIM)"), subtitle: L("Thêm / sửa / xoá tệp & registry"), icon: "doc.badge.gearshape.fill",
                    color: .neonPurple, filter: groups(["syscheck"]),
                    fields: [.init(field: "syscheck.event", title: L("Hành động")), .init(field: "syscheck.path", title: L("Đường dẫn")),
                             .init(field: "agent.name", title: "Agent"), .init(field: "syscheck.uname_after", title: L("Người sở hữu"))],
                    section: .system),
        WazuhModule(id: "sca", title: L("Đánh giá cấu hình (SCA)"), subtitle: L("Kết quả kiểm tra CIS"), icon: "checklist",
                    color: .neonGreen, filter: groups(["sca"]),
                    fields: [.init(field: "data.sca.check.result", title: L("Kết quả")), .init(field: "data.sca.policy", title: L("Chính sách")),
                             .init(field: "data.sca.check.title", title: L("Mục kiểm tra")), .init(field: "agent.name", title: "Agent")],
                    section: .system),
        WazuhModule(id: "audit", title: "Linux audit", subtitle: L("Lệnh & tiến trình (auditd)"), icon: "terminal.fill",
                    color: .neonYellow, filter: groups(["audit"]),
                    fields: [.init(field: "data.audit.command", title: L("Lệnh")), .init(field: "data.audit.exe", title: L("Chương trình")),
                             .init(field: "data.audit.auid", title: "User ID"), .init(field: "agent.name", title: "Agent")],
                    section: .system),
        WazuhModule(id: "windows", title: "Windows", subtitle: "Event log & Sysmon", icon: "pc",
                    color: .neonCyan, filter: groups(["windows", "sysmon"]),
                    fields: [.init(field: "data.win.system.eventID", title: "Event ID"), .init(field: "rule.description", title: L("Sự kiện")),
                             .init(field: "data.win.system.providerName", title: L("Nguồn")), .init(field: "agent.name", title: "Agent")],
                    section: .system),
        WazuhModule(id: "syslog", title: "Syslog 514", subtitle: L("Thiết bị mạng gửi log tới manager"), icon: "antenna.radiowaves.left.and.right",
                    color: .neonGreen, filter: syslogFilter,
                    fields: [.init(field: "location", title: L("Thiết bị gửi (IP)")), .init(field: "predecoder.hostname", title: L("Tên thiết bị")),
                             .init(field: "predecoder.program_name", title: L("Chương trình")), .init(field: "decoder.name", title: "Decoder"),
                             .init(field: "rule.description", title: L("Sự kiện")), .init(field: "data.srcip", title: L("IP nguồn"))],
                    section: .network),
        WazuhModule(id: "firewall", title: L("Tường lửa"), subtitle: L("pfSense, FortiGate, iptables…"), icon: "flame.fill",
                    color: .neonOrange, filter: groups(["firewall", "pfsense", "fortigate", "iptables", "cisco_asa", "sonicwall", "mikrotik"]),
                    fields: [.init(field: "data.srcip", title: L("IP nguồn")), .init(field: "data.dstip", title: L("IP đích")),
                             .init(field: "data.dstport", title: L("Cổng đích")), .init(field: "data.action", title: L("Hành động")),
                             .init(field: "location", title: L("Thiết bị"))],
                    section: .network),
        WazuhModule(id: "web", title: "Web", subtitle: L("Truy cập & tấn công web"), icon: "globe",
                    color: .neonPurple, filter: groups(["web", "accesslog", "attack", "web_scan"]),
                    fields: [.init(field: "data.srcip", title: L("IP nguồn")), .init(field: "data.url", title: "URL"),
                             .init(field: "data.id", title: L("Mã HTTP")), .init(field: "rule.description", title: L("Sự kiện"))],
                    section: .network),
        WazuhModule(id: "ids", title: "IDS / Suricata", subtitle: L("Cảnh báo xâm nhập mạng"), icon: "eye.trianglebadge.exclamationmark.fill",
                    color: .neonRed, filter: groups(["ids", "suricata", "snort"]),
                    fields: [.init(field: "data.alert.signature", title: L("Chữ ký")), .init(field: "data.src_ip", title: L("IP nguồn")),
                             .init(field: "data.dest_ip", title: L("IP đích")), .init(field: "data.alert.category", title: L("Loại"))],
                    section: .network),
        WazuhModule(id: "docker", title: "Docker", subtitle: L("Sự kiện container"), icon: "shippingbox.fill",
                    color: .neonCyan, filter: groups(["docker"]),
                    fields: [.init(field: "data.docker.Action", title: L("Hành động")), .init(field: "data.docker.Actor.Attributes.name", title: "Container"),
                             .init(field: "data.docker.Actor.Attributes.image", title: "Image"), .init(field: "agent.name", title: "Agent")],
                    section: .cloud),
        WazuhModule(id: "aws", title: "Amazon AWS", subtitle: L("CloudTrail, GuardDuty…"), icon: "cloud.fill",
                    color: .neonOrange, filter: groups(["amazon", "aws"]),
                    fields: [.init(field: "data.aws.source", title: L("Dịch vụ")), .init(field: "data.aws.eventName", title: L("Sự kiện")),
                             .init(field: "data.aws.region", title: L("Vùng")), .init(field: "rule.description", title: "Rule")],
                    section: .cloud),
        WazuhModule(id: "o365", title: "Microsoft 365", subtitle: L("Hoạt động Office 365"), icon: "envelope.badge.shield.half.filled",
                    color: .neonPink, filter: groups(["office365"]),
                    fields: [.init(field: "data.office365.Operation", title: L("Thao tác")), .init(field: "data.office365.UserId", title: L("Người dùng")),
                             .init(field: "data.office365.ClientIP", title: "IP"), .init(field: "rule.description", title: "Rule")],
                    section: .cloud),
        WazuhModule(id: "gcp", title: "Google Cloud", subtitle: "Pub/Sub & audit log", icon: "cloud.bolt.fill",
                    color: .neonYellow, filter: groups(["gcp"]),
                    fields: [.init(field: "data.gcp.resource.type", title: L("Tài nguyên")), .init(field: "data.gcp.severity", title: L("Mức độ")),
                             .init(field: "rule.description", title: "Rule")],
                    section: .cloud),
        WazuhModule(id: "github", title: "GitHub", subtitle: L("Audit log tổ chức"), icon: "chevron.left.forwardslash.chevron.right",
                    color: .neonPurple, filter: groups(["github"]),
                    fields: [.init(field: "data.github.action", title: L("Hành động")), .init(field: "data.github.actor", title: L("Người thực hiện")),
                             .init(field: "data.github.repo", title: "Repository"), .init(field: "rule.description", title: "Rule")],
                    section: .cloud),
    ] }
}

// MARK: - Thiết bị cuối

enum DeviceType: String, CaseIterable, Identifiable, Codable {
    case firewall, router, switchDevice, wifi, nas, server, pc, camera, other
    var id: String { rawValue }

    var title: String {
        switch self {
        case .firewall: return L("Tường lửa")
        case .router: return L("Router")
        case .switchDevice: return L("Switch")
        case .wifi: return L("Wi-Fi / AP")
        case .nas: return L("NAS / Lưu trữ")
        case .server: return AppLanguage.current == .en ? "Server" : "Máy chủ"
        case .pc: return L("Máy trạm")
        case .camera: return L("Camera")
        case .other: return L("Khác")
        }
    }

    var icon: String {
        switch self {
        case .firewall: return "flame.fill"
        case .router: return "point.3.connected.trianglepath.dotted"
        case .switchDevice: return "rectangle.connected.to.line.below"
        case .wifi: return "wifi.router.fill"
        case .nas: return "externaldrive.fill.badge.wifi"
        case .server: return "server.rack"
        case .pc: return "desktopcomputer"
        case .camera: return "video.fill"
        case .other: return "cube.fill"
        }
    }

    var color: Color {
        switch self {
        case .firewall: return .neonOrange
        case .router, .switchDevice, .wifi: return .neonCyan
        case .nas: return .neonPurple
        case .server, .pc: return .neonCyan
        case .camera: return .neonRed
        case .other: return .gray
        }
    }

    /// Đoán loại thiết bị: ưu tiên tên thiết bị, sau đó mới tới decoder / hệ điều hành.
    static func guess(name: String, hint: String, isAgent: Bool) -> DeviceType {
        if let t = match(name) { return t }
        if let t = match(hint) { return t }
        if isAgent {
            let s = (name + " " + hint).lowercased()
            if ["pc", "laptop", "desktop", "macbook", "windows 10", "windows 11", "macos", "ke-toan", "client"].contains(where: { s.contains($0) }) { return .pc }
            return .server
        }
        return .other
    }

    private static func match(_ text: String) -> DeviceType? {
        let s = text.lowercased()
        guard !s.isEmpty else { return nil }
        func has(_ words: [String]) -> Bool { words.contains { s.contains($0) } }
        if has(["switch", "sw-", "-sw", "sw0", "core-sw", "cisco_ios", "%link", "procurve", "catalyst"]) { return .switchDevice }
        if has(["nas", "synology", "qnap", "truenas", "freenas", "unraid", "storage", "backup"]) { return .nas }
        if has(["cam", "hikvision", "dahua", "nvr", "dvr", "ezviz", "imou"]) { return .camera }
        if has(["unifi", "ap-", "wifi", "wlan", "hostapd", "aruba", "ruckus", "eap", "omada"]) { return .wifi }
        if has(["forti", "pfsense", "opnsense", "sophos", "firewall", "fw-", "fw_", "-fw", "asa", "sonicwall", "paloalto", "checkpoint", "watchguard", "untangle"]) { return .firewall }
        if has(["router", "mikrotik", "routeros", "edgerouter", "draytek", "gateway", "gw-"]) { return .router }
        return nil
    }
}

struct DeviceStat: Identifiable, Hashable {
    enum Kind: String { case syslog, agent }
    let kind: Kind
    let key: String          // IP (syslog) hoặc ID agent
    let autoName: String
    let address: String
    var alerts: Int
    var maxLevel: Int
    let hint: String

    var id: String { kind.rawValue + ":" + key }
}

struct DeviceLabel: Codable, Hashable {
    var name: String
    var type: DeviceType
}

/// Tên & loại thiết bị do người dùng đặt (lưu trên máy, theo từng máy chủ Wazuh).
enum DeviceLabels {
    private static let key = "deviceLabels.v1"

    private static func all() -> [String: DeviceLabel] {
        guard let d = UserDefaults.standard.data(forKey: key),
              let v = try? JSONDecoder().decode([String: DeviceLabel].self, from: d) else { return [:] }
        return v
    }

    static func get(server: UUID?, device: String) -> DeviceLabel? {
        all()["\(server?.uuidString ?? "-")|\(device)"]
    }

    static func set(_ label: DeviceLabel?, server: UUID?, device: String) {
        var a = all()
        a["\(server?.uuidString ?? "-")|\(device)"] = label
        if let d = try? JSONEncoder().encode(a) { UserDefaults.standard.set(d, forKey: key) }
    }
}
