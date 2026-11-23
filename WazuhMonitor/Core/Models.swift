import SwiftUI

// MARK: - Khoảng thời gian

enum TimeRange: String, CaseIterable, Identifiable {
    case m15 = "15m", h1 = "1h", h24 = "24h", d7 = "7d", d30 = "30d", custom = "custom"
    var id: String { rawValue }

    /// Các khoảng cố định hiển thị dạng chip.
    static var presets: [TimeRange] { [.m15, .h1, .h24, .d7, .d30] }

    var title: String {
        switch self {
        case .m15: return L("15 phút")
        case .h1: return L("1 giờ")
        case .h24: return L("24 giờ")
        case .d7: return L("7 ngày")
        case .d30: return L("30 ngày")
        case .custom: return CustomRange.label
        }
    }

    var short: String {
        switch self {
        case .m15: return "15M"
        case .h1: return "1H"
        case .h24: return "24H"
        case .d7: return L("7N")
        case .d30: return L("30N")
        case .custom: return L("Tuỳ chọn")
        }
    }

    /// Độ dài khoảng thời gian (giây).
    var span: TimeInterval {
        switch self {
        case .m15: return 900
        case .h1: return 3600
        case .h24: return 86400
        case .d7: return 7 * 86400
        case .d30: return 30 * 86400
        case .custom: return max(60, CustomRange.to.timeIntervalSince(CustomRange.from))
        }
    }

    /// Mốc bắt đầu / kết thúc theo cú pháp OpenSearch.
    var gte: String { self == .custom ? CustomRange.iso(CustomRange.from) : "now-\(rawValue)" }
    var lte: String { self == .custom ? CustomRange.iso(CustomRange.to) : "now" }

    var rangeClause: JSONValue { ["range": ["timestamp": ["gte": .string(gte), "lte": .string(lte)]]] }

    /// Khoá dùng cho `.task(id:)` — đổi khi khoảng tuỳ chọn thay đổi.
    var key: String { self == .custom ? "custom-\(Int(CustomRange.from.timeIntervalSince1970))-\(Int(CustomRange.to.timeIntervalSince1970))" : rawValue }

    /// Bước của date_histogram tự chọn theo độ dài khoảng.
    var interval: String {
        let s = span
        switch s {
        case ..<1801: return "30s"
        case ..<3601: return "2m"
        case ..<(6 * 3600 + 1): return "10m"
        case ..<(86400 + 1): return "1h"
        case ..<(3 * 86400 + 1): return "3h"
        case ..<(8 * 86400): return "6h"
        case ..<(32 * 86400): return "1d"
        default: return "7d"
        }
    }

    /// Khoảng ngắn (≤ 1 ngày) hiển thị giờ:phút trên trục.
    var showsTime: Bool { span <= 86400 * 1.01 }
}

/// Khoảng thời gian tuỳ chọn (lưu trên máy).
enum CustomRange {
    static let fromKey = "range.custom.from"
    static let toKey = "range.custom.to"

    static var from: Date {
        get { let v = UserDefaults.standard.double(forKey: fromKey); return v > 0 ? Date(timeIntervalSince1970: v) : Date().addingTimeInterval(-86400) }
        set { UserDefaults.standard.set(newValue.timeIntervalSince1970, forKey: fromKey) }
    }
    static var to: Date {
        get { let v = UserDefaults.standard.double(forKey: toKey); return v > 0 ? Date(timeIntervalSince1970: v) : Date() }
        set { UserDefaults.standard.set(newValue.timeIntervalSince1970, forKey: toKey) }
    }

    private static let isoFmt: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]; return f
    }()
    static func iso(_ d: Date) -> String { isoFmt.string(from: d) }

    static var label: String {
        let f = DateFormatter()
        f.dateFormat = "dd/MM HH:mm"
        return f.string(from: from) + " → " + f.string(from: to)
    }
}

// MARK: - Mức độ nghiêm trọng của cảnh báo (theo Wazuh dashboard)

enum Severity: String, CaseIterable, Identifiable {
    case critical, high, medium, low
    var id: String { rawValue }

    init(level: Int) {
        switch level {
        case 15...: self = .critical
        case 12...14: self = .high
        case 7...11: self = .medium
        default: self = .low
        }
    }

    var title: String {
        switch self {
        case .critical: return L("Nghiêm trọng")
        case .high: return L("Cao")
        case .medium: return L("Trung bình")
        case .low: return L("Thấp")
        }
    }

    var range: String {
        switch self {
        case .critical: return L("≥ 15")
        case .high: return L("12–14")
        case .medium: return L("7–11")
        case .low: return L("0–6")
        }
    }

    var minLevel: Int {
        switch self {
        case .critical: return 15
        case .high: return 12
        case .medium: return 7
        case .low: return 0
        }
    }

    var color: Color {
        switch self {
        case .critical: return .sevCritical
        case .high: return .sevHigh
        case .medium: return .sevMedium
        case .low: return .sevLow
        }
    }

    var icon: String {
        switch self {
        case .critical: return "flame.fill"
        case .high: return "exclamationmark.triangle.fill"
        case .medium: return "exclamationmark.circle.fill"
        case .low: return "info.circle.fill"
        }
    }
}

/// Mức độ lỗ hổng (CVE) từ Wazuh vulnerability detector.
enum VulnSeverity: String, CaseIterable, Identifiable {
    case critical = "Critical", high = "High", medium = "Medium", low = "Low"
    var id: String { rawValue }

    var title: String {
        switch self {
        case .critical: return L("Nghiêm trọng")
        case .high: return L("Cao")
        case .medium: return L("Trung bình")
        case .low: return L("Thấp")
        }
    }

    var color: Color {
        switch self {
        case .critical: return .sevCritical
        case .high: return .sevHigh
        case .medium: return .sevMedium
        case .low: return .sevLow
        }
    }

    static func color(for s: String) -> Color { VulnSeverity(rawValue: s)?.color ?? .gray }
}

// MARK: - Agent

enum AgentStatus: String, CaseIterable, Identifiable {
    case active, disconnected, never_connected, pending
    var id: String { rawValue }

    var title: String {
        switch self {
        case .active: return L("Hoạt động")
        case .disconnected: return L("Mất kết nối")
        case .never_connected: return L("Chưa kết nối")
        case .pending: return L("Đang chờ")
        }
    }

    var color: Color {
        switch self {
        case .active: return .neonGreen
        case .disconnected: return .neonRed
        case .never_connected: return .gray
        case .pending: return .neonYellow
        }
    }
}

struct Agent: Identifiable, Hashable {
    let id: String
    let name: String
    let ip: String
    let statusRaw: String
    let osName: String
    let osVersion: String
    let osPlatform: String
    let version: String
    let lastKeepAlive: String
    let dateAdd: String
    let groups: [String]
    let node: String

    init(_ j: JSONValue) {
        id = j.str("id")
        name = j.str("name")
        ip = j.str("ip")
        statusRaw = j.str("status")
        osName = j.str("os.name")
        osVersion = j.str("os.version")
        osPlatform = j.str("os.platform")
        version = j.str("version").replacingOccurrences(of: "Wazuh ", with: "")
        lastKeepAlive = j.str("lastKeepAlive")
        dateAdd = j.str("dateAdd")
        groups = j["group"]?.stringArray ?? []
        node = j.str("node_name")
    }

    var status: AgentStatus? { AgentStatus(rawValue: statusRaw) }
    var statusColor: Color { status?.color ?? .gray }
    var statusTitle: String { status?.title ?? statusRaw }

    var osText: String {
        let s = [osName, osVersion].filter { !$0.isEmpty }.joined(separator: " ")
        return s.isEmpty ? L("Không rõ hệ điều hành") : s
    }

    var osIcon: String {
        let p = (osPlatform + " " + osName).lowercased()
        if p.contains("darwin") || p.contains("mac") || p.contains("ios") { return "applelogo" }
        if p.contains("windows") { return "pc" }
        if p.isEmpty { return "questionmark.square.dashed" }
        return "terminal.fill"
    }
}

struct AgentSummary {
    var active = 0, disconnected = 0, neverConnected = 0, pending = 0, total = 0

    init() {}

    init(_ data: JSONValue) {
        // Wazuh ≥ 4.4: data.connection.{...}; bản cũ: data.{...}
        let c = data["connection"] ?? data
        active = c["active"]?.intValue ?? 0
        disconnected = c["disconnected"]?.intValue ?? 0
        neverConnected = c["never_connected"]?.intValue ?? 0
        pending = c["pending"]?.intValue ?? 0
        total = c["total"]?.intValue ?? (active + disconnected + neverConnected + pending)
    }

    func count(_ s: AgentStatus) -> Int {
        switch s {
        case .active: return active
        case .disconnected: return disconnected
        case .never_connected: return neverConnected
        case .pending: return pending
        }
    }
}

// MARK: - Cảnh báo

struct WazuhAlert: Identifiable, Hashable {
    let id: String
    let timestamp: String
    let level: Int
    let ruleID: String
    let description: String
    let groups: [String]
    let agentID: String
    let agentName: String
    let agentIP: String
    let location: String
    let fullLog: String
    let decoder: String
    let tactics: [String]
    let techniques: [String]
    let mitreIDs: [String]
    let source: JSONValue
    /// Giá trị `sort` của hit — dùng cho search_after.
    let sortValues: [JSONValue]

    init(_ hit: JSONValue) {
        let s = hit["_source"] ?? .object([:])
        source = s
        sortValues = hit["sort"]?.arrayValue ?? []
        id = hit.str("_id").isEmpty ? UUID().uuidString : hit.str("_id")
        timestamp = s.str("timestamp")
        level = s.path("rule.level")?.intValue ?? 0
        ruleID = s.str("rule.id")
        description = s.str("rule.description")
        groups = s.path("rule.groups")?.stringArray ?? []
        agentID = s.str("agent.id")
        agentName = s.str("agent.name")
        agentIP = s.str("agent.ip")
        location = s.str("location")
        fullLog = s.str("full_log")
        decoder = s.str("decoder.name")
        tactics = s.path("rule.mitre.tactic")?.stringArray ?? []
        techniques = s.path("rule.mitre.technique")?.stringArray ?? []
        mitreIDs = s.path("rule.mitre.id")?.stringArray ?? []
    }

    var severity: Severity { Severity(level: level) }
}

struct Bucket: Identifiable, Hashable {
    let key: String
    let count: Int
    var id: String { key }
}

struct TimelinePoint: Identifiable {
    let date: Date
    let total: Int
    let high: Int
    var id: Date { date }
}

struct AlertStats {
    var total = 0
    var levels: [Severity: Int] = [:]
    var timeline: [TimelinePoint] = []
    var rules: [Bucket] = []
    var agents: [Bucket] = []
    var tactics: [Bucket] = []
    var authFailures = 0

    init() {}

    init(_ r: JSONValue) {
        total = r.path("hits.total.value")?.intValue ?? 0
        let aggs = r["aggregations"] ?? .object([:])
        for b in aggs.path("levels.buckets")?.arrayValue ?? [] {
            if let s = Severity(rawValue: b.str("key")) { levels[s] = b["doc_count"]?.intValue ?? 0 }
        }
        timeline = (aggs.path("timeline.buckets")?.arrayValue ?? []).compactMap { b in
            guard let ms = b["key"]?.doubleValue else { return nil }
            return TimelinePoint(date: Date(timeIntervalSince1970: ms / 1000),
                                 total: b["doc_count"]?.intValue ?? 0,
                                 high: b.path("high.doc_count")?.intValue ?? 0)
        }
        func buckets(_ name: String) -> [Bucket] {
            (aggs.path("\(name).buckets")?.arrayValue ?? []).map { Bucket(key: $0.str("key"), count: $0["doc_count"]?.intValue ?? 0) }
        }
        rules = buckets("rules")
        agents = buckets("agents")
        tactics = buckets("tactics")
        authFailures = aggs.path("auth_fail.doc_count")?.intValue ?? 0
    }
}

// MARK: - Lỗ hổng

struct Vulnerability: Identifiable, Hashable {
    let id: String
    let cve: String
    let severity: String
    let score: Double?
    let packageName: String
    let packageVersion: String
    let description: String
    let reference: String
    let detected: String
    let agentName: String
    let published: String
    let os: String

    init(_ hit: JSONValue) {
        let s = hit["_source"] ?? .object([:])
        id = hit.str("_id").isEmpty ? UUID().uuidString : hit.str("_id")
        cve = s.str("vulnerability.id")
        severity = s.str("vulnerability.severity")
        score = s.path("vulnerability.score.base")?.doubleValue
        packageName = s.str("package.name")
        packageVersion = s.str("package.version")
        description = s.str("vulnerability.description")
        reference = s.str("vulnerability.reference")
        detected = s.str("vulnerability.detected_at")
        agentName = s.str("agent.name")
        published = s.str("vulnerability.published_at")
        os = s.str("host.os.full")
    }
}

// MARK: - SCA

struct SCAPolicy: Identifiable, Hashable {
    let id: String
    let name: String
    let pass: Int
    let fail: Int
    let invalid: Int
    let score: Int
    let endScan: String

    init(_ j: JSONValue) {
        id = j.str("policy_id")
        name = j.str("name")
        pass = j["pass"]?.intValue ?? 0
        fail = j["fail"]?.intValue ?? 0
        invalid = j["invalid"]?.intValue ?? 0
        score = j["score"]?.intValue ?? 0
        endScan = j.str("end_scan")
    }

    var scoreColor: Color { score >= 75 ? .neonGreen : score >= 50 ? .neonYellow : .neonRed }
}

struct SCACheck: Identifiable, Hashable {
    let id: String
    let title: String
    let result: String
    let rationale: String
    let remediation: String
    let description: String

    init(_ j: JSONValue) {
        id = j.str("id")
        title = j.str("title")
        result = j.str("result")
        rationale = j.str("rationale")
        remediation = j.str("remediation")
        description = j.str("description")
    }

    var resultColor: Color {
        switch result {
        case "passed": return .neonGreen
        case "failed": return .neonRed
        default: return .gray
        }
    }

    var resultTitle: String {
        switch result {
        case "passed": return L("Đạt")
        case "failed": return L("Không đạt")
        case "not applicable": return L("Không áp dụng")
        default: return result.isEmpty ? L("—") : result
        }
    }
}

struct Daemon: Hashable, Identifiable {
    let name: String
    let state: String
    var id: String { name }
}

// MARK: - Nhật ký manager

struct LogEntry: Identifiable, Hashable {
    let id = UUID()
    let timestamp: String
    let tag: String
    let level: String
    let text: String

    init(_ j: JSONValue) {
        timestamp = j.str("timestamp")
        tag = j.str("tag")
        level = j.str("level")
        text = j.str("description")
    }

    var color: Color {
        switch level {
        case "critical", "error": return .neonRed
        case "warning": return .neonOrange
        case "debug", "debug2": return .gray
        default: return .neonCyan
        }
    }
}
