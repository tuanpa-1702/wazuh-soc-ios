import SwiftUI
import Charts

/// Tab CVE: tổng hợp lỗ hổng (wazuh-states-vulnerabilities-*) + lịch sử phát hiện từ cảnh báo.
struct CVEView: View {
    let client: WazuhClient
    @State var agentName: String?
    @State var severity: VulnSeverity?

    init(client: WazuhClient, agentName: String? = nil, severity: VulnSeverity? = nil) {
        self.client = client
        _agentName = State(initialValue: agentName)
        _severity = State(initialValue: severity)
    }

    struct Overview {
        var total = 0
        var packagesAffected = 0
        var severity: [String: Int] = [:]
        var agents: [BarItem] = []
        var packages: [BarItem] = []
        var os: [BarItem] = []
        var years: [BarItem] = []
        var cvss: [BarItem] = []
    }

    @AppStorage("cve.historyRange") private var historyRaw = TimeRange.d30.rawValue
    @State private var overview: Overview?
    @State private var list: [Vulnerability] = []
    @State private var listTotal = 0
    @State private var allAgents: [String] = []
    @State private var history: [SeriesPoint] = []
    @State private var historyAgents: [(agent: String, active: Int, solved: Int)] = []
    @State private var error: String?
    @State private var historyError: String?
    @State private var loading = false
    @State private var selected: Vulnerability?

    private var historyRange: TimeRange { TimeRange(rawValue: historyRaw) ?? .d30 }

    var body: some View {
        TechScroll {
            if !client.hasIndexer {
                EmptyStateCard(icon: "externaldrive.badge.questionmark", title: L("Chưa kết nối Indexer"),
                               message: L("Lỗ hổng được lưu trong Wazuh Indexer. Thêm địa chỉ Indexer trong phần máy chủ."), color: .neonOrange)
            } else {
                filterBar
                if let error { ErrorCard(message: error) { Task { await load() } } }
                if let o = overview {
                    summaryCard(o)
                    if o.total == 0 {
                        EmptyStateCard(icon: "checkmark.seal.fill", title: L("Không có lỗ hổng"),
                                       message: L("Không có CVE nào khớp bộ lọc (cần Wazuh 4.8+ bật vulnerability-detection)."), color: .sevOK)
                    } else {
                        if agentName == nil { barsCard(L("Theo agent"), "desktopcomputer", o.agents, .neonCyan) { agentName = $0.key } }
                        barsCard(L("Gói phần mềm nhiều lỗ hổng"), "shippingbox.fill", o.packages, .neonOrange, onTap: nil)
                        chartCard(L("Phân bố điểm CVSS"), "chart.bar.fill", o.cvss)
                        chartCard(L("Theo năm công bố"), "calendar", o.years)
                        barsCard(L("Theo hệ điều hành"), "laptopcomputer", o.os, .neonPurple, onTap: nil)
                    }
                } else if loading {
                    SkeletonBlock().card()
                }
                listCard
                historyCard
            }
        }
        .navigationTitle(agentName.map { "CVE • \($0)" } ?? L("Lỗ hổng (CVE)"))
        .inlineTitleIf(agentName != nil)
        .toolbar { ToolbarItem(placement: .primaryAction) { if loading { ProgressView() } } }
        .refreshable { await load() }
        .task(id: "\(agentName ?? "")|\(severity?.rawValue ?? "")|\(historyRaw)") { await load() }
        .sheet(item: $selected) { v in NavigationStack { VulnDetailView(v: v) } }
    }

    // MARK: Bộ lọc

    private var filterBar: some View {
        VStack(alignment: .leading, spacing: 8) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    Menu {
                        Button(L("Tất cả agent")) { agentName = nil }
                        ForEach(allAgents, id: \.self) { a in Button(a) { agentName = a } }
                    } label: {
                        HStack(spacing: 5) {
                            Image(systemName: "desktopcomputer")
                            Text(agentName ?? L("Tất cả agent")).lineLimit(1)
                            Image(systemName: "chevron.down").font(.caption2)
                        }
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(agentName == nil ? Color.neonCyan : Color.onAccent)
                        .padding(.horizontal, 14)
                        .frame(minHeight: 36)
                        .background(agentName == nil ? Color.chipFill : Color.neonCyan, in: Capsule())
                    }
                    FilterChip(title: L("Mọi mức"), color: .neonCyan, selected: severity == nil) { severity = nil }
                    ForEach(VulnSeverity.allCases) { s in
                        FilterChip(title: s.title, color: s.color, selected: severity == s) { severity = s }
                    }
                }
            }
        }
    }

    // MARK: Thẻ

    private func summaryCard(_ o: Overview) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L("TỔNG LỖ HỔNG")).techLabel()
                    Text(o.total.formatted()).font(.system(size: 30, weight: .heavy, design: .rounded)).foregroundStyle(Color.sevCritical)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 2) {
                    Text(L("GÓI BỊ ẢNH HƯỞNG")).techLabel()
                    Text(o.packagesAffected.formatted()).font(.system(size: 20, weight: .bold, design: .rounded)).foregroundStyle(Color.sevHigh)
                }
            }
            HStack(spacing: 8) {
                ForEach(VulnSeverity.allCases) { s in
                    Button { severity = severity == s ? nil : s } label: {
                        VStack(spacing: 3) {
                            Text(Fmt.compact(o.severity[s.rawValue] ?? 0))
                                .font(.system(size: 18, weight: .bold, design: .rounded)).foregroundStyle(s.color)
                            Text(s.title).font(.caption2).foregroundStyle(.secondary).lineLimit(1).minimumScaleFactor(0.7)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                        .background(s.color.opacity(severity == s ? 0.25 : 0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .card(glow: .sevCritical)
    }

    private func barsCard(_ title: String, _ icon: String, _ items: [BarItem], _ color: Color, onTap: ((BarItem) -> Void)?) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: title, icon: icon, color: color)
            if items.isEmpty { Text(L("Chưa có dữ liệu")).font(.footnote).foregroundStyle(.secondary) }
            let maxV = max(items.map(\.value).max() ?? 1, 1)
            ForEach(items) { it in
                Button { onTap?(it) } label: {
                    VStack(alignment: .leading, spacing: 5) {
                        HStack {
                            Text(it.key).font(.footnote).lineLimit(1)
                            Spacer()
                            Text(Fmt.compact(Int(it.value))).font(.footnote.monospaced().weight(.semibold)).foregroundStyle(color)
                            if onTap != nil { Image(systemName: "line.3.horizontal.decrease.circle").font(.caption2).foregroundStyle(.tertiary) }
                        }
                        MeterBar(value: it.value / maxV, color: color, height: 5)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .card()
    }

    private func chartCard(_ title: String, _ icon: String, _ items: [BarItem]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: title, icon: icon, color: .sevHigh)
            Chart(items) { it in
                BarMark(x: .value("x", it.key), y: .value("n", it.value))
                    .foregroundStyle(cvssColor(it.key))
                    .cornerRadius(3)
            }
            .chartYAxis {
                AxisMarks(position: .leading) { v in
                    AxisGridLine().foregroundStyle(Color.track)
                    AxisValueLabel { if let n = v.as(Double.self) { Text(Fmt.compact(Int(n))).font(.caption2.monospaced()) } }
                }
            }
            .frame(height: 160)
        }
        .card()
    }

    private func cvssColor(_ key: String) -> Color {
        guard let s = Double(key) else { return .sevHigh }
        if s >= 9 { return .sevCritical }
        if s >= 7 { return .sevHigh }
        if s >= 4 { return .sevMedium }
        return .sevLow
    }

    private var listCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            CardHeader(title: severity == nil ? L("CVE Nghiêm trọng & Cao") : Lf("CVE mức {0}", severity!.title),
                       icon: "exclamationmark.shield.fill", color: .sevCritical)
            if listTotal > list.count {
                Text(Lf("Hiển thị {0}/{1} theo điểm CVSS", "\(list.count)", "\(listTotal.formatted())")).font(.caption2).foregroundStyle(.secondary)
            }
            if list.isEmpty && !loading { Text(L("Không có CVE")).font(.footnote).foregroundStyle(.secondary) }
            ForEach(list) { v in
                Button { selected = v } label: {
                    HStack(alignment: .top, spacing: 10) {
                        Text(v.score.map { String(format: "%.1f", $0) } ?? "–")
                            .font(.system(.subheadline, design: .monospaced).weight(.bold))
                            .foregroundStyle(VulnSeverity.color(for: v.severity))
                            .frame(width: 44, height: 32)
                            .background(VulnSeverity.color(for: v.severity).opacity(0.13), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                        VStack(alignment: .leading, spacing: 2) {
                            Text(v.cve).font(.footnote.monospaced().weight(.semibold))
                            Text("\(v.packageName) \(v.packageVersion)").font(.caption).lineLimit(1)
                            Text(v.agentName).font(.caption2).foregroundStyle(.secondary)
                        }
                        Spacer(minLength: 0)
                        Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .card()
    }

    private var historyCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: L("Lịch sử phát hiện (Active / Solved)"), icon: "clock.arrow.circlepath", color: .neonCyan)
            RangeBar(rangeRaw: $historyRaw)
            if let historyError {
                Text(historyError).font(.caption).foregroundStyle(Color.neonOrange)
            } else if history.allSatisfy({ $0.value == 0 }) {
                Text(L("Không có cảnh báo vulnerability-detector trong khoảng này")).font(.footnote).foregroundStyle(.secondary)
            } else {
                Chart(history) { p in
                    BarMark(x: .value(L("Thời gian"), p.date, unit: historyRange.barUnit), y: .value(L("Số lượng"), p.value))
                        .foregroundStyle(by: .value(L("Trạng thái"), p.series))
                }
                .chartForegroundStyleScale(domain: ["Active", "Solved"], range: [Color.sevHigh, Color.sevOK])
                .socAxes(range: historyRange, unit: .count)
                .frame(height: 170)
                ForEach(historyAgents, id: \.agent) { a in
                    HStack {
                        Text(a.agent).font(.footnote)
                        Spacer()
                        Label("\(a.active)", systemImage: "exclamationmark.circle.fill").foregroundStyle(Color.sevHigh)
                        Label("\(a.solved)", systemImage: "checkmark.circle.fill").foregroundStyle(Color.sevOK)
                    }
                    .font(.caption.monospacedDigit())
                }
            }
        }
        .card()
    }

    // MARK: Tải dữ liệu

    private var vulnFilters: [JSONValue] {
        var f: [JSONValue] = []
        if let agentName { f.append(["term": ["agent.name": .string(agentName)]]) }
        if let severity { f.append(["term": ["vulnerability.severity": .string(severity.rawValue)]]) }
        return f
    }

    private func load() async {
        loading = true
        defer { loading = false }
        async let ov: Void = loadOverview()
        async let ls: Void = loadList()
        async let hs: Void = loadHistory()
        _ = await (ov, ls, hs)
    }

    private func buckets(_ r: JSONValue, _ name: String) -> [BarItem] {
        (r.path("aggregations.\(name).buckets")?.arrayValue ?? []).map { BarItem(key: $0.str("key_as_string").isEmpty ? $0.str("key") : $0.str("key_as_string"), value: $0["doc_count"]?.doubleValue ?? 0) }
    }

    private func loadOverview() async {
        do {
            let r = try await client.search("wazuh-states-vulnerabilities-*", [
                "size": 0, "track_total_hits": true,
                "query": Q.bool(vulnFilters),
                "aggs": [
                    "sev": ["terms": ["field": "vulnerability.severity", "size": 8]],
                    "agent": ["terms": ["field": "agent.name", "size": 15]],
                    "pkg": ["terms": ["field": "package.name", "size": 12]],
                    "pkgs": ["cardinality": ["field": "package.name"]],
                    "os": ["terms": ["field": "host.os.full", "size": 8]],
                    "allAgents": ["terms": ["field": "agent.name", "size": 200, "order": ["_key": "asc"]]],
                    "cvss": ["histogram": ["field": "vulnerability.score.base", "interval": 1, "min_doc_count": 0,
                                           "extended_bounds": ["min": 0, "max": 10]]],
                    "year": ["date_histogram": ["field": "vulnerability.published_at", "calendar_interval": "year", "format": "yyyy", "min_doc_count": 1]],
                ],
            ])
            var o = Overview()
            o.total = r.path("hits.total.value")?.intValue ?? 0
            o.packagesAffected = r.path("aggregations.pkgs.value")?.intValue ?? 0
            for b in buckets(r, "sev") { o.severity[b.key] = Int(b.value) }
            o.agents = buckets(r, "agent")
            o.packages = buckets(r, "pkg")
            o.os = buckets(r, "os")
            o.years = Array(buckets(r, "year").suffix(12))
            o.cvss = buckets(r, "cvss").map { BarItem(key: String(Int(Double($0.key) ?? 0)), value: $0.value) }
            overview = o
            if agentName == nil { allAgents = buckets(r, "allAgents").map(\.key) }
            error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg }
        }
    }

    private func loadList() async {
        var f = vulnFilters
        if severity == nil { f.append(["terms": ["vulnerability.severity": ["Critical", "High"]]]) }
        do {
            let r = try await client.search("wazuh-states-vulnerabilities-*", [
                "size": 100, "track_total_hits": true, "query": Q.bool(f),
                "sort": [["vulnerability.score.base": ["order": "desc", "unmapped_type": "float"]]],
            ])
            let hits = r.path("hits.hits")?.arrayValue ?? []
            list = hits.map(Vulnerability.init)
            listTotal = r.path("hits.total.value")?.intValue ?? hits.count
        } catch {
            if let msg = errorText(error), self.error == nil { self.error = msg }
        }
    }

    private func loadHistory() async {
        var f: [JSONValue] = [historyRange.rangeClause, Q.qs("rule.groups:vulnerability-detector")]
        if let agentName { f.append(["term": ["agent.name": .string(agentName)]]) }
        if let severity { f.append(Q.qs("data.vulnerability.severity:\(severity.rawValue)")) }
        let status: JSONValue = ["filters": ["filters": ["Active": Q.qs("data.vulnerability.status:Active"),
                                                         "Solved": Q.qs("data.vulnerability.status:Solved")]]]
        do {
            let r = try await client.search("wazuh-alerts-*", [
                "size": 0, "query": Q.bool(f),
                "aggs": [
                    "t": Q.dateHistogram(historyRange, aggs: ["s": status]),
                    "a": ["terms": ["field": "agent.name", "size": 10], "aggs": ["s": status]],
                ],
            ])
            var pts: [SeriesPoint] = []
            for b in r.path("aggregations.t.buckets")?.arrayValue ?? [] {
                guard let ms = b["key"]?.doubleValue else { continue }
                let d = Date(timeIntervalSince1970: ms / 1000)
                for k in ["Active", "Solved"] {
                    pts.append(SeriesPoint(date: d, series: k, value: b.path("s.buckets.\(k).doc_count")?.doubleValue ?? 0))
                }
            }
            history = pts
            historyAgents = (r.path("aggregations.a.buckets")?.arrayValue ?? []).map { b in
                (b.str("key"), b.path("s.buckets.Active.doc_count")?.intValue ?? 0, b.path("s.buckets.Solved.doc_count")?.intValue ?? 0)
            }
            historyError = nil
        } catch {
            if let msg = errorText(error) { historyError = msg }
        }
    }
}
