import SwiftUI
import Charts

// MARK: - Danh sách dashboard theo module

struct ModulesView: View {
    let client: WazuhClient
    var agentID: String?
    var agentName: String?

    @AppStorage("dashboard.range") private var rangeRaw = TimeRange.h24.rawValue
    @State private var counts: [String: Int] = [:]
    @State private var vulnTotal: Int?
    @State private var socSummaries: [String: WazuhClient.DeviceSummary] = [:]
    @AppStorage(CustomRange.fromKey) private var fromTS = 0.0
    @AppStorage(CustomRange.toKey) private var toTS = 0.0
    @State private var error: String?
    @State private var loading = false

    private var range: TimeRange { TimeRange(rawValue: rangeRaw) ?? .h24 }

    var body: some View {
        TechScroll {
            if !client.hasIndexer {
                EmptyStateCard(icon: "externaldrive.badge.questionmark", title: L("Chưa kết nối Indexer"),
                               message: L("Các dashboard đọc dữ liệu từ Wazuh Indexer (cổng 9200). Thêm địa chỉ Indexer trong phần máy chủ."),
                               color: .neonOrange)
            } else {
                RangeBar(rangeRaw: $rangeRaw)
                if let error { ErrorCard(message: error) { Task { await load() } } }

                if agentID == nil {
                    HStack(spacing: 6) {
                        Image(systemName: "shield.checkered").font(.caption).foregroundStyle(Color.neonCyan)
                        Text(L("Thiết bị SOC")).font(.headline)
                        Spacer()
                    }
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 160), spacing: 12)], spacing: 12) {
                        ForEach(DeviceConfig.catalog) { d in
                            NavigationLink { DeviceScreen(client: client, device: d) } label: {
                                DeviceSummaryTile(device: d, summary: socSummaries[d.id])
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    HStack(spacing: 6) {
                        Image(systemName: "square.grid.3x3.fill").font(.caption).foregroundStyle(Color.neonCyan)
                        Text(L("Thiết bị phát hiện tự động")).font(.headline)
                        Spacer()
                    }
                    .padding(.top, 4)
                    DevicesSection(client: client, range: range)
                    HStack(spacing: 6) {
                        Image(systemName: "square.stack.3d.up.fill").font(.caption).foregroundStyle(Color.neonCyan)
                        Text(L("Module")).font(.headline)
                        Spacer()
                    }
                    .padding(.top, 8)
                }

                ForEach(ModuleSection.allCases) { section in
                    let mods = WazuhModule.all.filter { $0.section == section }
                    VStack(alignment: .leading, spacing: 10) {
                        Text(L(section.rawValue)).techLabel().padding(.leading, 4)
                        LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
                            ForEach(mods) { m in
                                NavigationLink {
                                    ModuleDashboardView(client: client, module: m, agentID: agentID, agentName: agentName)
                                } label: {
                                    ModuleTile(module: m, count: counts[m.filter == nil ? "all" : m.id])
                                }
                                .buttonStyle(.plain)
                            }
                            if section == .security && agentID == nil {
                                NavigationLink {
                                    VulnOverviewView(client: client)
                                } label: {
                                    ModuleTile(module: WazuhModule(id: "vuln", title: L("Lỗ hổng (CVE)"), subtitle: L("Phần mềm có lỗ hổng"),
                                                                   icon: "exclamationmark.shield.fill", color: .neonRed, filter: nil, fields: []),
                                               count: vulnTotal, countLabel: "CVE")
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle(agentName.map { Lf("Dashboard • {0}", "\($0)") } ?? L("Thiết bị"))
        .inlineTitleIf(agentName != nil)
        .toolbar { ToolbarItem(placement: .primaryAction) { if loading { ProgressView() } } }
        .refreshable { await load() }
        .task(id: range.key) { await load() }
    }

    private func load() async {
        guard client.hasIndexer else { return }
        if agentID == nil, let s = try? await client.deviceSummaries(DeviceConfig.catalog, range: range) { socSummaries = s }
        loading = true
        defer { loading = false }
        do {
            counts = try await client.moduleCounts(WazuhModule.all, range: range, agentID: agentID)
            error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg }
        }
        if agentID == nil, let v = try? await client.vulnerabilityOverview() { vulnTotal = v.total }
    }
}

struct ModuleTile: View {
    let module: WazuhModule
    let count: Int?
    var countLabel = L("cảnh báo")

    var body: some View {
        let active = (count ?? 0) > 0
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: module.icon)
                    .font(.title3)
                    .foregroundStyle(module.color)
                    .neonGlow(module.color, radius: active ? 6 : 0)
                Spacer()
                Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
            }
            Text(module.title)
                .font(.subheadline.weight(.semibold))
                .lineLimit(2)
                .minimumScaleFactor(0.85)
                .fixedSize(horizontal: false, vertical: true)
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text(count.map { Fmt.compact($0) } ?? L("—"))
                    .font(.system(size: 20, weight: .bold, design: .rounded))
                    .foregroundStyle(active ? module.color : .secondary)
                Text(countLabel).font(.caption2).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 100, alignment: .topLeading)
        .card(glow: active ? module.color : nil)
    }
}

// MARK: - Dashboard một module

struct ModuleDashboardView: View {
    let client: WazuhClient
    let module: WazuhModule
    var agentID: String?
    var agentName: String?

    @AppStorage("dashboard.range") private var rangeRaw = TimeRange.h24.rawValue
    @State private var stats: AlertStats?
    @State private var tops: [String: [Bucket]] = [:]
    @State private var recent: [WazuhAlert] = []
    @State private var error: String?
    @State private var loading = false

    private var range: TimeRange { TimeRange(rawValue: rangeRaw) ?? .h24 }

    var body: some View {
        TechScroll {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 12) {
                    Image(systemName: module.icon)
                        .font(.title2)
                        .foregroundStyle(module.color)
                        .neonGlow(module.color, radius: 8)
                        .frame(width: 48, height: 48)
                        .background(module.color.opacity(0.12), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(module.subtitle).font(.footnote).foregroundStyle(.secondary)
                        if let agentName { Pill(text: agentName, color: .neonCyan, icon: "desktopcomputer") }
                    }
                    Spacer()
                }
            }
            .card(glow: module.color)

            RangeBar(rangeRaw: $rangeRaw, color: module.color)

            if let error { ErrorCard(message: error) { Task { await load() } } }

            summaryCard
            VStack(alignment: .leading, spacing: 12) {
                CardHeader(title: L("Diễn biến"), icon: "waveform.path.ecg", color: module.color)
                AlertTimelineChart(points: stats?.timeline ?? [], range: range, color: module.color, loading: loading)
            }
            .card()

            if module.id == "syslog" && !loading && (stats?.total ?? 0) == 0 && error == nil {
                EmptyStateCard(icon: "antenna.radiowaves.left.and.right.slash", title: L("Chưa nhận log syslog"),
                               message: L("Bật nhận syslog trong ossec.conf của manager: <remote><connection>syslog</connection><port>514</port><protocol>udp</protocol><allowed-ips>192.168.0.0/16</allowed-ips></remote>, rồi trỏ thiết bị mạng gửi log tới IP manager cổng 514."),
                               color: .neonOrange)
            }

            ForEach(module.fields, id: \.self) { f in
                if let items = tops[f.field], !items.isEmpty {
                    DrillDownTopCard(client: client, title: f.title, field: f.field, items: items, color: module.color,
                                     range: range, agentID: agentID, extra: module.extraFilters)
                }
            }

            if !recent.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    CardHeader(title: L("Cảnh báo mới nhất"), icon: "clock.arrow.circlepath", color: module.color)
                    ForEach(recent) { a in
                        NavigationLink { AlertDetailView(client: client, alert: a) } label: {
                            HStack(alignment: .top, spacing: 10) {
                                LevelBadge(level: a.level, size: 30)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(a.description).font(.footnote.weight(.medium)).lineLimit(2).multilineTextAlignment(.leading)
                                    Text(Lf("{0} • {1}", "\(module.id == "syslog" ? a.location : a.agentName)", "\(Fmt.ago(a.timestamp))"))
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                                Spacer(minLength: 0)
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                    NavigationLink {
                        AlertsView(client: client, initialRange: range, agentID: agentID, agentName: agentName,
                                   extra: module.extraFilters, title: module.title)
                    } label: {
                        Label(L("Xem tất cả cảnh báo"), systemImage: "list.bullet")
                    }
                    .buttonStyle(GlassButtonStyle(tint: module.color))
                }
                .card()
            }
        }
        .navigationTitle(module.title)
        .inlineTitle()
        .toolbar { ToolbarItem(placement: .primaryAction) { if loading { ProgressView() } } }
        .refreshable { await load() }
        .task(id: range.key) { await load() }
    }

    private var summaryCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text(L("TỔNG CẢNH BÁO")).techLabel()
                Spacer()
                Text((stats?.total ?? 0).formatted())
                    .font(.system(size: 28, weight: .heavy, design: .rounded))
                    .foregroundStyle(module.color)
            }
            HStack(spacing: 8) {
                ForEach(Severity.allCases) { s in
                    VStack(spacing: 3) {
                        Text(Fmt.compact(stats?.levels[s] ?? 0))
                            .font(.system(size: 17, weight: .bold, design: .rounded))
                            .foregroundStyle((stats?.levels[s] ?? 0) > 0 ? s.color : .secondary)
                        Text(s.title).font(.caption2).foregroundStyle(.secondary).lineLimit(1).minimumScaleFactor(0.7)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .background(s.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                }
            }
        }
        .card()
    }

    private func load() async {
        loading = true
        defer { loading = false }
        let extra = module.extraFilters
        do {
            async let s = client.alertStats(range: range, agentID: agentID, extra: extra)
            async let r = client.alerts(range: range, minLevel: 0, search: "", agentID: agentID, from: 0, size: 8, extra: extra)
            let (sv, rv) = try await (s, r)
            stats = sv
            recent = rv.alerts
            error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg }
            return
        }
        // Mỗi trường một truy vấn: trường không tồn tại / không thống kê được thì bỏ qua.
        var result: [String: [Bucket]] = [:]
        await withTaskGroup(of: (String, [Bucket]?).self) { group in
            for f in module.fields {
                group.addTask { [client, range, agentID] in
                    (f.field, try? await client.topValues(f.field, range: range, agentID: agentID, extra: extra))
                }
            }
            for await (k, v) in group { if let v { result[k] = v } }
        }
        tops = result
    }
}

/// Top giá trị — chạm một dòng để xem các cảnh báo tương ứng.
struct DrillDownTopCard: View {
    let client: WazuhClient
    let title: String
    let field: String
    let items: [Bucket]
    let color: Color
    let range: TimeRange
    let agentID: String?
    let extra: [JSONValue]

    var body: some View {
        let maxCount = max(items.map(\.count).max() ?? 1, 1)
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: title, icon: "chart.bar.fill", color: color)
            ForEach(items) { item in
                NavigationLink {
                    AlertsView(client: client, initialRange: range, agentID: agentID,
                               extra: extra + [["term": [field: .string(item.key)]]],
                               title: item.key)
                } label: {
                    VStack(alignment: .leading, spacing: 5) {
                        HStack(alignment: .firstTextBaseline) {
                            Text(item.key.isEmpty ? L("(trống)") : item.key)
                                .font(.footnote)
                                .lineLimit(2)
                                .multilineTextAlignment(.leading)
                            Spacer(minLength: 8)
                            Text(item.count.formatted())
                                .font(.system(.footnote, design: .monospaced).weight(.semibold))
                                .foregroundStyle(color.opacity(0.9))
                                .layoutPriority(1)
                            Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                        }
                        MeterBar(value: Double(item.count) / Double(maxCount), color: color, height: 5)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .card()
    }
}

/// Biểu đồ cột số cảnh báo theo thời gian (dùng chung).
struct AlertTimelineChart: View {
    let points: [TimelinePoint]
    let range: TimeRange
    var color: Color = .neonCyan
    var loading = false

    var body: some View {
        if points.isEmpty {
            Text(loading ? L("Đang tải…") : L("Chưa có dữ liệu")).font(.footnote).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, minHeight: 80)
        } else {
            Chart {
                ForEach(points) { p in
                    BarMark(x: .value("Thời gian", p.date), y: .value("Số lượng", p.total))
                        .foregroundStyle(by: .value("Loại", L("Tất cả")))
                    BarMark(x: .value("Thời gian", p.date), y: .value("Số lượng", p.high))
                        .foregroundStyle(by: .value("Loại", L("Cao ≥ 12")))
                }
            }
            .chartForegroundStyleScale([L("Tất cả"): color.opacity(0.75), L("Cao ≥ 12"): Color.neonPink])
            .chartYAxis {
                AxisMarks(position: .leading) { v in
                    AxisGridLine().foregroundStyle(Color.track)
                    AxisValueLabel {
                        if let n = v.as(Int.self) { Text(Fmt.compact(n)).font(.caption2.monospaced()) }
                    }
                }
            }
            .chartXAxis {
                AxisMarks(values: .automatic(desiredCount: 4)) { v in
                    AxisGridLine().foregroundStyle(Color.track)
                    AxisValueLabel {
                        if let d = v.as(Date.self) {
                            Text(Self.axisLabel(d, range)).font(.caption2.monospacedDigit()).fixedSize()
                        }
                    }
                }
            }
            .chartLegend(position: .bottom, alignment: .leading)
            .frame(height: 170)
        }
    }

    static func axisLabel(_ d: Date, _ range: TimeRange) -> String { socAxisLabel(d, range) }
}

// MARK: - Tổng hợp lỗ hổng

struct VulnOverviewView: View {
    let client: WazuhClient
    @State private var data: (severity: [String: Int], cves: [Bucket], packages: [Bucket], agents: [Bucket], total: Int)?
    @State private var error: String?
    @State private var loading = false

    var body: some View {
        TechScroll {
            if let error { ErrorCard(message: error) { Task { await load() } } }
            if let data {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(alignment: .firstTextBaseline) {
                        Text(L("TỔNG LỖ HỔNG")).techLabel()
                        Spacer()
                        Text(data.total.formatted())
                            .font(.system(size: 28, weight: .heavy, design: .rounded))
                            .foregroundStyle(Color.neonRed)
                    }
                    HStack(spacing: 8) {
                        ForEach(VulnSeverity.allCases) { s in
                            VStack(spacing: 3) {
                                Text(Fmt.compact(data.severity[s.rawValue] ?? 0))
                                    .font(.system(size: 18, weight: .bold, design: .rounded))
                                    .foregroundStyle(s.color)
                                Text(s.title).font(.caption2).foregroundStyle(.secondary).lineLimit(1).minimumScaleFactor(0.7)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 8)
                            .background(s.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                        }
                    }
                }
                .card(glow: .neonRed)
                if data.total == 0 {
                    EmptyStateCard(icon: "checkmark.seal.fill", title: L("Không có dữ liệu lỗ hổng"),
                                   message: L("Cần Wazuh 4.8+ và bật vulnerability-detection trong ossec.conf."), color: .neonGreen)
                }
                TopBarsCard(title: L("CVE phổ biến"), icon: "number", items: data.cves, color: .neonRed)
                TopBarsCard(title: L("Gói phần mềm nhiều lỗ hổng"), icon: "shippingbox.fill", items: data.packages, color: .neonOrange)
                TopBarsCard(title: L("Agent nhiều lỗ hổng"), icon: "desktopcomputer", items: data.agents, color: .neonYellow)
            } else if loading {
                LoadingRow().padding(.top, 40)
            }
        }
        .navigationTitle(L("Lỗ hổng (CVE)"))
        .inlineTitle()
        .refreshable { await load() }
        .task { await load() }
    }

    private func load() async {
        loading = true
        defer { loading = false }
        do {
            data = try await client.vulnerabilityOverview()
            error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg }
        }
    }
}
