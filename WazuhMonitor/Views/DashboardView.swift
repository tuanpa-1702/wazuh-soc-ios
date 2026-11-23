import SwiftUI
import Charts

struct DashboardView: View {
    let client: WazuhClient
    @EnvironmentObject private var store: ServerStore
    @AppStorage("dashboard.refreshSeconds") private var refreshSeconds = 60
    @AppStorage("dashboard.range") private var rangeRaw = TimeRange.h24.rawValue

    @State private var info: JSONValue?
    @State private var daemons: [Daemon] = []
    @State private var summary: AgentSummary?
    @State private var stats: AlertStats?
    @State private var vulns: [String: Int]?
    @State private var vulnPackages: Int?
    @State private var devices: [String: WazuhClient.DeviceSummary] = [:]
    @State private var devicesError: String?
    @State private var sevTimeline: [SeriesPoint] = []
    @AppStorage(CustomRange.fromKey) private var fromTS = 0.0
    @AppStorage(CustomRange.toKey) private var toTS = 0.0
    @State private var apiError: String?
    @State private var indexerError: String?
    @State private var loading = false
    @State private var showServers = false

    private var range: TimeRange { TimeRange(rawValue: rangeRaw) ?? .h24 }

    var body: some View {
        TechScroll {
            if let apiError, info == nil {
                ErrorCard(message: apiError) { Task { await load() } }
            }
            managerCard
            agentsCard
            rangePicker
            if client.hasIndexer {
                if let indexerError {
                    ErrorCard(message: indexerError) { Task { await load() } }
                }
                severityGrid
                devicesCard
                vulnCard
                timelineCard
                if let stats {
                    TopBarsCard(title: L("Rule kích hoạt nhiều"), icon: "list.number", items: stats.rules, color: .neonPurple)
                    TopBarsCard(title: L("Agent nhiều cảnh báo"), icon: "desktopcomputer", items: stats.agents, color: .neonCyan)
                    if !stats.tactics.isEmpty {
                        TopBarsCard(title: "MITRE ATT&CK", icon: "target", items: stats.tactics, color: .neonPink)
                    }
                }
            } else {
                EmptyStateCard(icon: "externaldrive.badge.questionmark",
                               title: L("Chưa kết nối Indexer"),
                               message: L("Thêm địa chỉ Wazuh Indexer (cổng 9200) trong phần máy chủ để xem cảnh báo, biểu đồ và lỗ hổng."),
                               color: .neonOrange)
            }
        }
        .navigationTitle("Wazuh")
        .toolbar {
            ToolbarItem(placement: .navigationBarLeading) {
                Button { showServers = true } label: {
                    Label(store.activeServer?.displayName ?? L("Máy chủ"), systemImage: "server.rack")
                        .labelStyle(.titleAndIcon)
                        .font(.footnote.weight(.semibold))
                        .lineLimit(1)
                }
            }
            ToolbarItem(placement: .primaryAction) {
                if loading { ProgressView() } else {
                    Button { Task { await load() } } label: { Image(systemName: "arrow.clockwise") }
                }
            }
        }
        .sheet(isPresented: $showServers) {
            NavigationStack { ServerListView() }
        }
        .refreshable { await load() }
        .task(id: range.key) {
            await load()
            while refreshSeconds > 0 && !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(refreshSeconds) * 1_000_000_000)
                if Task.isCancelled { break }
                await load()
            }
        }
    }

    // MARK: - Tải dữ liệu

    private func load() async {
        loading = true
        defer { loading = false }
        async let infoTask = client.managerInfo()
        async let statusTask = client.managerStatus()
        async let summaryTask = client.agentsSummary()
        do {
            let (i, d, s) = try await (infoTask, statusTask, summaryTask)
            info = i; daemons = d; summary = s; apiError = nil
        } catch {
            if let msg = errorText(error) { apiError = msg }
        }
        guard client.hasIndexer else { return }
        do {
            stats = try await client.alertStats(range: range)
            indexerError = nil
        } catch {
            if let msg = errorText(error) { indexerError = msg }
        }
        async let dev = client.deviceSummaries(DeviceConfig.catalog, range: range)
        async let tl = client.severityTimeline(range: range)
        do { devices = try await dev; devicesError = nil } catch { devicesError = errorText(error) }
        sevTimeline = (try? await tl) ?? sevTimeline
        if let r = try? await client.search("wazuh-states-vulnerabilities-*", [
            "size": 0, "aggs": ["sev": ["terms": ["field": "vulnerability.severity", "size": 8]],
                                "pkgs": ["cardinality": ["field": "package.name"]]],
        ]) {
            var out: [String: Int] = [:]
            for b in r.path("aggregations.sev.buckets")?.arrayValue ?? [] { out[b.str("key")] = b["doc_count"]?.intValue ?? 0 }
            vulns = out
            vulnPackages = r.path("aggregations.pkgs.value")?.intValue
        }
    }

    // MARK: - Thiết bị (SOC Home)

    private var devicesCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "square.grid.3x3.fill").font(.caption).foregroundStyle(Color.neonCyan)
                Text(L("THIẾT BỊ")).techLabel()
                Spacer()
            }
            .padding(.leading, 4)
            if let devicesError { Text(devicesError).font(.caption).foregroundStyle(Color.neonOrange) }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 160), spacing: 12)], spacing: 12) {
                ForEach(DeviceConfig.catalog) { d in
                    NavigationLink { DeviceScreen(client: client, device: d) } label: {
                        DeviceSummaryTile(device: d, summary: devices[d.id])
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    // MARK: - Thẻ manager

    private var stoppedDaemons: [String] {
        daemons.filter { Self.coreDaemons.contains($0.name) && $0.state != "running" }.map(\.name)
    }

    private static let coreDaemons: Set<String> = ["wazuh-analysisd", "wazuh-remoted", "wazuh-db", "wazuh-modulesd", "wazuh-apid", "wazuh-execd"]

    private var managerCard: some View {
        let healthy = !daemons.isEmpty && stoppedDaemons.isEmpty
        let accent: Color = info == nil ? .gray : (healthy ? .neonGreen : .neonOrange)
        return HStack(spacing: 16) {
            ZStack {
                Circle().fill(accent.opacity(0.12)).frame(width: 68, height: 68)
                Circle().strokeBorder(accent.opacity(0.6), lineWidth: 1.5).frame(width: 68, height: 68)
                Image(systemName: healthy ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                    .font(.system(size: 30))
                    .foregroundStyle(accent)
                    .neonGlow(accent, radius: 10)
            }
            VStack(alignment: .leading, spacing: 5) {
                Text("WAZUH MANAGER").techLabel()
                Text(info == nil ? L("Đang kết nối…") : (healthy ? L("HOẠT ĐỘNG") : L("CẦN KIỂM TRA")))
                    .font(.system(size: 22, weight: .heavy, design: .rounded))
                    .foregroundStyle(accent)
                    .neonGlow(accent, radius: 6)
                HStack(spacing: 6) {
                    if let v = info?.str("version"), !v.isEmpty { Pill(text: v, color: .neonCyan) }
                    if !daemons.isEmpty {
                        let running = daemons.filter { $0.state == "running" }.count
                        Pill(text: Lf("{0}/{1} dịch vụ", "\(running)", "\(daemons.count)"), color: healthy ? .neonGreen : .neonOrange, icon: "gearshape.2.fill")
                    }
                }
                if !stoppedDaemons.isEmpty {
                    Text(L("Dừng: ") + stoppedDaemons.joined(separator: ", "))
                        .font(.caption).foregroundStyle(Color.neonOrange)
                }
            }
            Spacer(minLength: 0)
        }
        .card(glow: accent)
    }

    // MARK: - Thẻ agent

    private var agentsCard: some View {
        let s = summary ?? AgentSummary()
        let total = s.total
        // API đếm cả manager (agent 000, luôn active).
        let active = s.active
        let ratio = total > 0 ? Double(active) / Double(total) : 0
        return VStack(alignment: .leading, spacing: 14) {
            CardHeader(title: "Agent", icon: "desktopcomputer", color: .neonGreen)
            HStack(spacing: 18) {
                ZStack {
                    RingGauge(value: ratio, color: .neonGreen, lineWidth: 11)
                    VStack(spacing: 0) {
                        Text("\(active)")
                            .font(.system(size: 26, weight: .bold, design: .rounded))
                        Text("/ \(total)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    }
                }
                .frame(width: 100, height: 100)
                VStack(spacing: 8) {
                    agentStatRow(.active, active)
                    agentStatRow(.disconnected, s.disconnected)
                    agentStatRow(.never_connected, s.neverConnected)
                    agentStatRow(.pending, s.pending)
                }
            }
        }
        .card()
    }

    private func agentStatRow(_ status: AgentStatus, _ n: Int) -> some View {
        HStack(spacing: 8) {
            StatusDot(color: status.color, size: 8)
            Text(status.title).font(.subheadline)
            Spacer()
            Text("\(n)").font(.system(.subheadline, design: .monospaced).weight(.semibold))
                .foregroundStyle(n > 0 && status == .disconnected ? Color.neonRed : .primary)
        }
    }

    // MARK: - Cảnh báo

    private var rangePicker: some View {
        RangeBar(rangeRaw: $rangeRaw)
    }

    private var severityGrid: some View {
        let columns = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]
        return VStack(spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(Lf("CẢNH BÁO {0}", "\(range.title.uppercased())")).techLabel()
                    Text((stats?.total ?? 0).formatted())
                        .font(.system(size: 34, weight: .heavy, design: .rounded))
                        .foregroundStyle(.primary)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 2) {
                    Text(L("ĐĂNG NHẬP LỖI")).techLabel()
                    Text((stats?.authFailures ?? 0).formatted())
                        .font(.system(size: 20, weight: .bold, design: .rounded))
                        .foregroundStyle(Color.neonPink)
                }
            }
            .card()
            LazyVGrid(columns: columns, spacing: 12) {
                ForEach(Severity.allCases) { s in
                    NavigationLink { AlertsView(client: client, initialMinLevel: s.minLevel, initialRange: range) } label: { severityTile(s) }
                        .buttonStyle(.plain)
                }
            }
        }
    }

    private func severityTile(_ s: Severity) -> some View {
        let n = stats?.levels[s] ?? 0
        let lit = n > 0 && (s == .critical || s == .high)
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: s.icon).foregroundStyle(s.color).neonGlow(s.color, radius: 6)
                Spacer()
                Text("Lv " + s.range).font(.caption2.monospaced()).foregroundStyle(.secondary)
            }
            Text(Fmt.compact(n))
                .font(.system(size: 28, weight: .bold, design: .rounded))
                .foregroundStyle(n > 0 ? s.color : Color.sevOK)
            HStack {
                Text(s.title).techLabel()
                Spacer()
                Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
            }
        }
        .card(glow: lit ? s.color : nil)
    }

    private var timelineCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: L("Cảnh báo theo mức độ"), icon: "chart.bar.xaxis", color: .neonCyan)
            if !sevTimeline.isEmpty {
                SeverityStackChart(points: sevTimeline, range: range)
            } else {
                Text(loading ? L("Đang tải…") : L("Chưa có dữ liệu")).font(.footnote).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 80)
            }
        }
        .card()
    }

    @ViewBuilder private var vulnCard: some View {
        if let vulns, !vulns.isEmpty {
            VStack(alignment: .leading, spacing: 12) {
                CardHeader(title: L("Lỗ hổng (CVE)"), icon: "ladybug.fill", color: .neonRed)
                HStack(spacing: 8) {
                    ForEach(VulnSeverity.allCases) { s in
                        VStack(spacing: 4) {
                            Text(Fmt.compact(vulns[s.rawValue] ?? 0))
                                .font(.system(size: 20, weight: .bold, design: .rounded))
                                .foregroundStyle(s.color)
                            Text(s.title)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .minimumScaleFactor(0.8)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(s.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    }
                }
                HStack {
                    Text(Lf("Tổng {0} • {1} gói bị ảnh hưởng", (vulns.values.reduce(0, +)).formatted(), (vulnPackages ?? 0).formatted()))
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    NavigationLink { CVEView(client: client) } label: {
                        HStack(spacing: 3) { Text(L("Chi tiết")); Image(systemName: "chevron.right") }.font(.caption.weight(.semibold))
                    }
                }
            }
            .card()
        }
    }
}

struct DeviceSummaryTile: View {
    let device: DeviceConfig
    let summary: WazuhClient.DeviceSummary?

    var body: some View {
        let s = summary ?? .init()
        let hot = s.high > 0
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top) {
                Image(systemName: device.icon)
                    .font(.title3)
                    .foregroundStyle(device.color)
                    .frame(width: 34, height: 34)
                    .background(device.color.opacity(0.12), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                VStack(alignment: .leading, spacing: 1) {
                    Text(device.title).font(.subheadline.weight(.semibold)).lineLimit(1)
                    Text(device.address).font(.caption2.monospaced()).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            Sparkline(values: s.spark, color: hot ? .sevHigh : device.color)
                .frame(height: 30)
            HStack(spacing: 0) {
                stat(L("Sự kiện"), s.events, device.color, plain: true)
                stat("≥7", s.medium, .sevMedium)
                stat("≥12", s.high, .sevHigh)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card(glow: hot ? .sevHigh : nil)
        .redacted(reason: summary == nil ? .placeholder : [])
    }

    private func stat(_ title: String, _ n: Int, _ color: Color, plain: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(Fmt.compact(n)).font(.system(size: 15, weight: .bold, design: .rounded))
                .foregroundStyle(plain ? .primary : (n > 0 ? color : Color.sevOK))
            Text(title).font(.caption2).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
