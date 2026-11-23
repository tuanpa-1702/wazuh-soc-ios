import SwiftUI

/// Màn hình một thiết bị (dựng từ DeviceConfig). Mỗi panel tự tải, lỗi panel nào hiện ở panel đó.
struct DeviceScreen: View {
    let client: WazuhClient
    let device: DeviceConfig

    @AppStorage("dashboard.range") private var rangeRaw = TimeRange.h24.rawValue
    @AppStorage(CustomRange.fromKey) private var fromTS = 0.0
    @AppStorage(CustomRange.toKey) private var toTS = 0.0
    @State private var collapsed: Set<String> = []
    @State private var agent: Agent?
    @State private var agentError: String?
    @State private var reloadToken = 0

    private var range: TimeRange { TimeRange(rawValue: rangeRaw) ?? .h24 }
    private var groups: [PanelGroup] { [DeviceConfig.commonGroup] + device.groups }

    var body: some View {
        TechScroll {
            header
            RangeBar(rangeRaw: $rangeRaw, color: device.color)
            ForEach(groups) { g in
                VStack(alignment: .leading, spacing: 12) {
                    Button {
                        withAnimation(.easeInOut(duration: 0.2)) {
                            if collapsed.contains(g.id) { collapsed.remove(g.id) } else { collapsed.insert(g.id) }
                        }
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: g.icon).font(.caption).foregroundStyle(device.color)
                            Text(g.title.uppercased()).techLabel()
                            Spacer()
                            Image(systemName: collapsed.contains(g.id) ? "chevron.down" : "chevron.up")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 4)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    if !collapsed.contains(g.id) {
                        ForEach(g.panels) { p in
                            PanelCard(client: client, device: device, panel: p, range: range, agent: agent, agentError: agentError)
                                .id("\(p.id)|\(range.key)|\(reloadToken)")
                        }
                    }
                }
                .padding(.top, 4)
            }
        }
        .navigationTitle(device.title)
        .inlineTitle()
        .refreshable { reloadToken += 1 }
        .onAppear {
            #if DEBUG
            if let g = UserDefaults.standard.string(forKey: "ui.expand"), let n = Int(g) {
                collapsed = Set(groups.enumerated().filter { $0.offset != n }.map(\.element.id))
            }
            #endif
        }
        .task(id: device.id) {
            guard let name = device.agentName else { return }
            do {
                agent = try await client.agent(named: name)
                agentError = agent == nil ? Lf("Không tìm thấy agent tên {0}.", name) : nil
            } catch {
                agentError = errorText(error)
            }
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: device.icon)
                .font(.title2)
                .foregroundStyle(device.color)
                .frame(width: 48, height: 48)
                .background(device.color.opacity(0.12), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            VStack(alignment: .leading, spacing: 4) {
                Text(device.address).font(.subheadline.monospaced())
                Text(device.filter).font(.caption.monospaced()).foregroundStyle(.secondary)
                if let agent {
                    HStack(spacing: 6) {
                        Pill(text: agent.statusTitle, color: agent.statusColor)
                        Text("ID \(agent.id) • \(agent.osText)").font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }
            Spacer()
        }
        .card(glow: device.color)
    }
}

// MARK: - Một panel

struct PanelCard: View {
    let client: WazuhClient
    let device: DeviceConfig
    let panel: Panel
    let range: TimeRange
    let agent: Agent?
    let agentError: String?

    @State private var data: PanelData?
    @State private var error: String?
    @State private var loading = false

    var body: some View {
        switch panel.kind {
        case .cve:
            AgentCVEPanel(client: client, agentName: device.agentName ?? "", agent: agent, color: device.color)
        case .sca:
            AgentSCAPanel(client: client, agent: agent, agentError: agentError)
        case .inventory:
            InventoryPanel(client: client, agent: agent, agentError: agentError)
        default:
            standard
        }
    }

    private var drillExtra: [JSONValue] {
        [Q.qs(device.filter)] + (panel.filter.map { [Q.qs($0)] } ?? [])
    }

    private var standard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                CardHeader(title: panel.title, icon: panel.icon, color: device.color)
                if loading { ProgressView().controlSize(.small) }
            }
            if let error {
                VStack(alignment: .leading, spacing: 8) {
                    Text(error).font(.caption).foregroundStyle(Color.neonOrange)
                    Button(L("Thử lại")) { Task { await load() } }.buttonStyle(GlassButtonStyle(tint: .neonOrange))
                }
            } else if let data {
                if data.isEmpty {
                    Text(L("Không có dữ liệu trong khoảng thời gian này")).font(.footnote).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, minHeight: 44)
                } else {
                    content(data)
                }
            } else {
                SkeletonBlock()
            }
        }
        .card()
        .task { await load() }
    }

    @ViewBuilder private func content(_ data: PanelData) -> some View {
        switch data {
        case .kpis(let values):
            if case .kpis(let kpis) = panel.kind {
                KPIGrid {
                    ForEach(Array(kpis.enumerated()), id: \.offset) { i, k in
                        let v = i < values.count ? values[i] : 0
                        let tile = KPITile(title: k.title, icon: k.icon, value: k.unit.format(v),
                                           color: k.alert ? (v > 0 ? .sevHigh : .sevOK) : device.color, lit: k.alert && v > 0)
                        if let d = k.drill {
                            NavigationLink { alertsList(d, title: k.title) } label: { tile }.buttonStyle(.plain)
                        } else { tile }
                    }
                }
            }
        case .series(let pts):
            if case .levelTimeline = panel.kind {
                SeverityStackChart(points: pts, range: range)
            } else {
                let unit: ValueUnit = { if case .series(_, let u, _) = panel.kind { return u }; return .count }()
                SeriesChart(points: pts, range: range, unit: unit, color: device.color)
                if unit == .bytes {
                    Text(Lf("Tổng: {0}", unit.format(pts.reduce(0) { $0 + $1.value })))
                        .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                }
            }
        case .bars(let items, let unit, _):
            BarList(items: items, unit: unit, color: device.color) { it in
                it.drill.map { d in AnyView(alertsList(d, title: it.key)) }
            }
        case .donut(let items, _):
            DonutChart(items: items, colorFor: { it, i in
                if case .levelDonut = panel.kind, let l = it.level { return Severity(level: l).color }
                return DonutChart.palette[i % DonutChart.palette.count]
            })
        case .heat(let rows, let cols, let cells):
            HeatmapChart(rows: rows, cols: cols, cells: cells, color: device.color)
        case .feed(let alerts):
            VStack(spacing: 8) {
                ForEach(alerts) { a in
                    NavigationLink { AlertDetailView(client: client, alert: a) } label: { FeedRow(alert: a, slowField: slowField) }
                        .buttonStyle(.plain)
                    if a.id != alerts.last?.id { Divider().opacity(0.3) }
                }
                NavigationLink { alertsList(nil, title: panel.title) } label: {
                    Label(L("Xem tất cả"), systemImage: "list.bullet")
                }
                .buttonStyle(GlassButtonStyle(tint: device.color))
            }
        case .compare(let current, let items):
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline) {
                    Text(L("1 giờ vừa qua")).font(.subheadline)
                    Spacer()
                    Text(Fmt.compact(Int(current))).font(.system(size: 24, weight: .bold, design: .rounded)).foregroundStyle(device.color)
                }
                ForEach(items) { c in
                    HStack {
                        Text(c.title).font(.footnote).foregroundStyle(.secondary)
                        Spacer()
                        Text(Fmt.compact(Int(c.value))).font(.footnote.monospacedDigit())
                        if let ch = c.change {
                            Text(String(format: "%+.0f%%", ch * 100))
                                .font(.caption.monospacedDigit().weight(.semibold))
                                .foregroundStyle(ch > 0.2 ? Color.sevHigh : (ch < -0.2 ? Color.sevOK : .secondary))
                                .frame(width: 60, alignment: .trailing)
                        } else {
                            Text("—").font(.caption).foregroundStyle(.tertiary).frame(width: 60, alignment: .trailing)
                        }
                    }
                }
            }
        case .geo(let pts):
            GeoMapView(points: pts, color: device.color)
            Text(Lf("{0} vị trí", "\(pts.count)")).font(.caption2).foregroundStyle(.secondary)
        case .none:
            EmptyView()
        }
    }

    private var slowField: String? {
        if case .slowest(let f, _) = panel.kind { return f }
        return nil
    }

    private func alertsList(_ q: String?, title: String) -> some View {
        AlertsView(client: client, initialRange: range, extra: drillExtra + (q.map { [Q.qs($0)] } ?? []),
                   title: device.title + " • " + title)
    }

    private func load() async {
        loading = true
        defer { loading = false }
        do {
            data = try await client.runPanel(panel, deviceFilter: device.filter, range: range)
            error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg }
        }
    }
}

/// Danh sách thanh ngang có chạm xem chi tiết.
struct BarList: View {
    let items: [BarItem]
    let unit: ValueUnit
    var color: Color = .neonCyan
    var destination: (BarItem) -> AnyView?

    var body: some View {
        let maxV = max(items.map(\.value).max() ?? 1, 1)
        VStack(alignment: .leading, spacing: 10) {
            ForEach(items) { it in
                let row = VStack(alignment: .leading, spacing: 5) {
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        if let l = it.level { LevelBadge(level: l, size: 22) }
                        VStack(alignment: .leading, spacing: 1) {
                            Text(it.key.isEmpty ? L("(trống)") : it.key).font(.footnote).lineLimit(2).multilineTextAlignment(.leading)
                            if let d = it.detail { Text(d).font(.caption2.monospaced()).foregroundStyle(.tertiary) }
                        }
                        Spacer(minLength: 8)
                        Text(unit.format(it.value))
                            .font(.system(.footnote, design: .monospaced).weight(.semibold))
                            .foregroundStyle(color.opacity(0.9))
                            .layoutPriority(1)
                    }
                    MeterBar(value: it.value / maxV, color: it.level.map { Severity(level: $0).color } ?? color, height: 5)
                }
                .contentShape(Rectangle())
                if let dest = destination(it) {
                    NavigationLink { dest } label: { row }.buttonStyle(.plain)
                } else {
                    row
                }
            }
        }
    }
}

struct FeedRow: View {
    let alert: WazuhAlert
    var slowField: String? = nil

    private static let keyFields = ["data.srcip", "data.dstip", "data.action", "data.srcuser", "data.dstuser", "data.user",
                                    "syscheck.path", "data.req_path", "data.http_status", "data.app", "data.win.system.eventID"]

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            LevelBadge(level: alert.level, size: 30)
            VStack(alignment: .leading, spacing: 3) {
                Text(alert.description).font(.footnote.weight(.medium)).lineLimit(2).multilineTextAlignment(.leading)
                Text(Fmt.time(alert.timestamp) + " • " + (alert.agentID == "000" ? alert.location : alert.agentName))
                    .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                let kv = keyValues
                if !kv.isEmpty {
                    Text(kv).font(.caption2.monospaced()).foregroundStyle(Color.neonCyan.opacity(0.85)).lineLimit(2)
                }
            }
            Spacer(minLength: 0)
            if let slowField {
                Text(alert.source.str(slowField) + " ms").font(.caption.monospacedDigit().weight(.bold)).foregroundStyle(Color.sevHigh)
            }
        }
        .contentShape(Rectangle())
    }

    private var keyValues: String {
        Self.keyFields.compactMap { f in
            let v = alert.source.str(f)
            return v.isEmpty ? nil : "\(f.split(separator: ".").last ?? ""): \(v)"
        }
        .prefix(3)
        .joined(separator: "  ")
    }
}

struct SkeletonBlock: View {
    @State private var pulse = false
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(0..<3, id: \.self) { i in
                RoundedRectangle(cornerRadius: 6).fill(Color.track)
                    .frame(maxWidth: i == 2 ? 180 : .infinity).frame(height: 14)
            }
        }
        .opacity(pulse ? 0.4 : 0.9)
        .onAppear { withAnimation(.easeInOut(duration: 0.8).repeatForever()) { pulse = true } }
    }
}

// MARK: - Panel CVE của agent

struct AgentCVEPanel: View {
    let client: WazuhClient
    let agentName: String
    let agent: Agent?
    var color: Color = .neonRed

    @State private var counts: [String: Int]?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: L("Lỗ hổng (CVE)"), icon: "ladybug.fill", color: .sevCritical)
            if let error {
                Text(error).font(.caption).foregroundStyle(Color.neonOrange)
                Button(L("Thử lại")) { Task { await load() } }.buttonStyle(GlassButtonStyle(tint: .neonOrange))
            } else if let counts {
                HStack(spacing: 8) {
                    ForEach(VulnSeverity.allCases) { s in
                        NavigationLink { CVEView(client: client, agentName: agentName, severity: s) } label: {
                            VStack(spacing: 3) {
                                Text(Fmt.compact(counts[s.rawValue] ?? 0))
                                    .font(.system(size: 18, weight: .bold, design: .rounded))
                                    .foregroundStyle((counts[s.rawValue] ?? 0) > 0 ? s.color : .secondary)
                                Text(s.title).font(.caption2).foregroundStyle(.secondary).lineLimit(1).minimumScaleFactor(0.7)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 8)
                            .background(s.color.opacity(0.1), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                        }
                        .buttonStyle(.plain)
                    }
                }
                NavigationLink { CVEView(client: client, agentName: agentName) } label: {
                    Label(Lf("Mở CVE của {0}", agentName), systemImage: "arrow.right.circle")
                }
                .buttonStyle(GlassButtonStyle(tint: .sevCritical))
            } else {
                SkeletonBlock()
            }
        }
        .card()
        .task { await load() }
    }

    private func load() async {
        do {
            let r = try await client.search("wazuh-states-vulnerabilities-*", [
                "size": 0, "query": ["term": ["agent.name": .string(agentName)]],
                "aggs": ["sev": ["terms": ["field": "vulnerability.severity", "size": 8]]],
            ])
            var out: [String: Int] = [:]
            for b in r.path("aggregations.sev.buckets")?.arrayValue ?? [] { out[b.str("key")] = b["doc_count"]?.intValue ?? 0 }
            counts = out
            error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg }
        }
    }
}

// MARK: - Panel SCA

struct AgentSCAPanel: View {
    let client: WazuhClient
    let agent: Agent?
    let agentError: String?

    @State private var policies: [SCAPolicy]?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: L("Đánh giá cấu hình (SCA / CIS)"), icon: "checklist", color: .neonGreen)
            if let msg = agentError ?? error {
                Text(msg).font(.caption).foregroundStyle(Color.neonOrange)
            } else if let policies {
                if policies.isEmpty {
                    Text(L("Chưa có kết quả SCA")).font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(policies) { p in
                    NavigationLink { SCAChecksView(client: client, agentID: agent?.id ?? "", policy: p) } label: {
                        HStack(spacing: 12) {
                            ZStack {
                                RingGauge(value: Double(p.score) / 100, color: p.scoreColor, lineWidth: 6)
                                Text("\(p.score)%").font(.caption.weight(.bold).monospacedDigit())
                            }
                            .frame(width: 52, height: 52)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(p.name).font(.footnote.weight(.medium)).lineLimit(2).multilineTextAlignment(.leading)
                                HStack(spacing: 8) {
                                    Label("\(p.pass)", systemImage: "checkmark.circle.fill").foregroundStyle(Color.sevOK)
                                    Label("\(p.fail)", systemImage: "xmark.circle.fill").foregroundStyle(Color.sevCritical)
                                    Label("\(p.invalid)", systemImage: "minus.circle.fill").foregroundStyle(.secondary)
                                }
                                .font(.caption.monospacedDigit())
                                Text(L("Chạm để xem mục không đạt")).font(.caption2).foregroundStyle(.tertiary)
                            }
                            Spacer(minLength: 0)
                            Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            } else {
                SkeletonBlock()
            }
        }
        .card()
        .task(id: agent?.id) { await load() }
    }

    private func load() async {
        guard let id = agent?.id else { return }
        do {
            policies = try await client.sca(id)
            error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg }
        }
    }
}

// MARK: - Panel inventory

struct InventoryPanel: View {
    let client: WazuhClient
    let agent: Agent?
    let agentError: String?

    @State private var os: JSONValue?
    @State private var hw: JSONValue?
    @State private var ports: Int?
    @State private var procs: Int?
    @State private var loaded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            CardHeader(title: L("Kiểm kê máy chủ"), icon: "cpu", color: .neonCyan)
            if let agentError {
                Text(agentError).font(.caption).foregroundStyle(Color.neonOrange)
            } else if loaded {
                InfoRow(label: L("Hệ điều hành"), value: os?.str("os.name").isEmpty == false ? "\(os!.str("os.name")) \(os!.str("os.version"))" : (agent?.osText ?? "—"))
                InfoRow(label: "CPU", value: hw?.str("cpu.name") ?? "—")
                InfoRow(label: L("Số nhân"), value: hw?.str("cpu.cores") ?? "—", mono: true)
                InfoRow(label: "RAM", value: hw.map { Fmt.bytes(($0.path("ram.total")?.doubleValue ?? 0) * 1024) } ?? "—", mono: true)
                InfoRow(label: L("Cổng đang lắng nghe"), value: ports.map(String.init) ?? "—", mono: true)
                InfoRow(label: L("Tiến trình"), value: procs.map(String.init) ?? "—", mono: true)
                if let agent {
                    NavigationLink { HostInventoryView(client: client, agent: agent) } label: {
                        Label(L("Xem đầy đủ inventory"), systemImage: "list.bullet.rectangle")
                    }
                    .buttonStyle(GlassButtonStyle(tint: .neonCyan))
                }
            } else {
                SkeletonBlock()
            }
        }
        .card()
        .task(id: agent?.id) { await load() }
    }

    private func load() async {
        guard let id = agent?.id else { return }
        async let o = try? client.syscollector(id, "os")
        async let h = try? client.syscollector(id, "hardware")
        async let p = try? client.syscollectorList(id, "ports", query: [URLQueryItem(name: "state", value: "listening")])
        async let pr = try? client.call("GET", "/syscollector/\(id)/processes", query: [URLQueryItem(name: "limit", value: "1")])
        os = await o
        hw = await h
        ports = await p?.count
        procs = await pr?["total_affected_items"]?.intValue
        loaded = true
    }
}

// MARK: - Inventory đầy đủ

struct HostInventoryView: View {
    let client: WazuhClient
    let agent: Agent

    @State private var os: JSONValue?
    @State private var hw: JSONValue?
    @State private var ifaces: [JSONValue] = []
    @State private var addrs: [JSONValue] = []
    @State private var ports: [JSONValue] = []
    @State private var procs: [JSONValue] = []
    @State private var services: [JSONValue]?
    @State private var users: [JSONValue]?
    @State private var loading = false

    var body: some View {
        TechScroll {
            VStack(alignment: .leading, spacing: 6) {
                CardHeader(title: L("Hệ thống"), icon: "cpu", color: .neonCyan)
                InfoRow(label: L("Hệ điều hành"), value: [os?.str("os.name"), os?.str("os.version")].compactMap { $0 }.joined(separator: " "))
                InfoRow(label: "Kernel", value: os?.str("release") ?? "", mono: true)
                InfoRow(label: L("Kiến trúc"), value: os?.str("architecture") ?? "", mono: true)
                InfoRow(label: "Hostname", value: os?.str("hostname") ?? "", mono: true)
                InfoRow(label: "CPU", value: hw?.str("cpu.name") ?? "")
                InfoRow(label: L("Số nhân"), value: hw?.str("cpu.cores") ?? "", mono: true)
                InfoRow(label: "RAM", value: hw.map { Fmt.bytes(($0.path("ram.total")?.doubleValue ?? 0) * 1024) } ?? "", mono: true)
                InfoRow(label: L("RAM trống"), value: hw.map { Fmt.bytes(($0.path("ram.free")?.doubleValue ?? 0) * 1024) } ?? "", mono: true)
            }
            .card()

            listCard(L("Interface & IP"), "network", ifaces.map { i in
                let name = i.str("name")
                let ips = addrs.filter { $0.str("iface") == name }.map { $0.str("address") }.filter { !$0.isEmpty }
                return (name + "  " + i.str("state"), ([i.str("mac")] + ips).filter { !$0.isEmpty }.joined(separator: " • "))
            })

            let listening = ports.filter { $0.str("state") == "listening" || $0.str("protocol").hasPrefix("udp") }
            let established = ports.filter { $0.str("state") == "established" }
            listCard(Lf("Bề mặt tấn công: cổng lắng nghe ({0})", "\(listening.count)"), "door.left.hand.open", listening.map { p in
                ("\(p.str("local.port"))/\(p.str("protocol"))", "\(p.str("local.ip")) • \(p.str("process").isEmpty ? "pid \(p.str("pid"))" : p.str("process"))")
            })
            listCard(Lf("Kết nối đang mở ({0})", "\(established.count)"), "arrow.left.arrow.right", established.prefix(30).map { p in
                ("\(p.str("remote.ip")):\(p.str("remote.port"))", "\(p.str("local.port"))/\(p.str("protocol")) • \(p.str("process"))")
            })

            if let services {
                let byState = Dictionary(grouping: services) { $0.str("state").isEmpty ? $0.str("status") : $0.str("state") }
                VStack(alignment: .leading, spacing: 8) {
                    CardHeader(title: Lf("Dịch vụ ({0})", "\(services.count)"), icon: "gearshape.2.fill", color: .neonGreen)
                    ForEach(byState.keys.sorted(), id: \.self) { k in
                        InfoRow(label: k.isEmpty ? L("(không rõ)") : k, value: "\(byState[k]?.count ?? 0)", mono: true)
                    }
                    ForEach(Array(services.prefix(25).enumerated()), id: \.offset) { _, s in
                        Text("\(s.str("name").isEmpty ? s.str("service.name") : s.str("name"))  •  \(s.str("state").isEmpty ? s.str("status") : s.str("state"))")
                            .font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                .card()
            }

            if let users {
                let interactive = users.filter { u in
                    let sh = u.str("shell").isEmpty ? u.str("user.shell") : u.str("shell")
                    return !sh.isEmpty && !sh.contains("nologin") && !sh.contains("false")
                }
                listCard(Lf("Người dùng tương tác ({0})", "\(interactive.count)"), "person.2.fill", interactive.map { u in
                    let n = u.str("name").isEmpty ? u.str("user.name") : u.str("name")
                    return (n, u.str("shell").isEmpty ? u.str("user.shell") : u.str("shell"))
                })
            }

            let top = procs.sorted { ($0["resident"]?.doubleValue ?? 0) > ($1["resident"]?.doubleValue ?? 0) }.prefix(20)
            listCard(Lf("Tiến trình dùng RAM nhiều ({0})", "\(procs.count)"), "memorychip", top.map { p in
                (p.str("name"), "pid \(p.str("pid")) • \(Fmt.bytes((p["resident"]?.doubleValue ?? 0) * 4096)) • \(p.str("euser"))")
            })

            NavigationLink { PackagesView(client: client, agentID: agent.id) } label: {
                Label(L("Gói phần mềm"), systemImage: "shippingbox.fill")
            }
            .buttonStyle(GlassButtonStyle(tint: .neonCyan))
        }
        .navigationTitle(agent.name)
        .inlineTitle()
        .toolbar { ToolbarItem(placement: .primaryAction) { if loading { ProgressView() } } }
        .refreshable { await load() }
        .task { await load() }
    }

    private func listCard(_ title: String, _ icon: String, _ rows: [(String, String)]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            CardHeader(title: title, icon: icon, color: .neonCyan)
            if rows.isEmpty { Text(L("Chưa có dữ liệu")).font(.footnote).foregroundStyle(.secondary) }
            ForEach(Array(rows.enumerated()), id: \.offset) { _, r in
                VStack(alignment: .leading, spacing: 2) {
                    Text(r.0).font(.footnote.monospaced().weight(.medium))
                    Text(r.1).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(2)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
    }

    private func load() async {
        loading = true
        defer { loading = false }
        let id = agent.id
        async let o = try? client.syscollector(id, "os")
        async let h = try? client.syscollector(id, "hardware")
        async let i = try? client.syscollectorList(id, "netiface")
        async let a = try? client.syscollectorList(id, "netaddr")
        async let p = try? client.syscollectorList(id, "ports")
        async let pr = try? client.syscollectorList(id, "processes")
        async let sv = try? client.syscollectorList(id, "services")
        async let us = try? client.syscollectorList(id, "users")
        os = await o
        hw = await h
        ifaces = await i ?? []
        addrs = await a ?? []
        ports = await p ?? []
        procs = await pr ?? []
        services = await sv
        users = await us
    }
}
