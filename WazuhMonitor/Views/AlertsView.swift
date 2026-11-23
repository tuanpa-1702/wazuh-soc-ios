import SwiftUI

struct AlertsView: View {
    let client: WazuhClient
    var agentID: String?
    var agentName: String?
    var extra: [JSONValue] = []
    var title: String?

    @State private var minLevel: Int
    @State private var maxLevel: Int?
    @State private var agentFilter: String?
    @State private var groupFilter: String?
    @State private var agentOptions: [String] = []
    @State private var groupOptions: [String] = []
    @State private var showCustom = false
    @AppStorage(CustomRange.fromKey) private var fromTS = 0.0
    @AppStorage(CustomRange.toKey) private var toTS = 0.0
    @State private var range: TimeRange
    @State private var alerts: [WazuhAlert] = []
    @State private var total = 0
    @State private var search = ""
    @State private var appliedSearch = ""
    @State private var loading = false
    @State private var loadingMore = false
    @State private var error: String?
    @State private var loaded = false

    init(client: WazuhClient, initialMinLevel: Int = 0, initialRange: TimeRange = .h24,
         agentID: String? = nil, agentName: String? = nil, extra: [JSONValue] = [], title: String? = nil) {
        self.client = client
        self.agentID = agentID
        self.agentName = agentName
        self.extra = extra
        self.title = title
        _minLevel = State(initialValue: initialMinLevel)
        _range = State(initialValue: initialRange)
    }

    private struct LevelFilter: Identifiable {
        let title: String
        let level: Int
        var max: Int? = nil
        let color: Color
        var id: String { "\(level)-\(max ?? -1)" }
    }

    private static var levelFilters: [LevelFilter] { [
        LevelFilter(title: L("Tất cả"), level: 0, color: .neonCyan),
        LevelFilter(title: L("≥ 7"), level: 7, color: .sevMedium),
        LevelFilter(title: L("≥ 12"), level: 12, color: .sevHigh),
        LevelFilter(title: L("≥ 15"), level: 15, color: .sevCritical),
        LevelFilter(title: L("Thấp 0–6"), level: 0, max: 6, color: .sevLow),
        LevelFilter(title: L("TB 7–11"), level: 7, max: 11, color: .sevMedium),
        LevelFilter(title: L("Cao 12–14"), level: 12, max: 14, color: .sevHigh),
    ] }

    private var effectiveExtra: [JSONValue] {
        var e = extra
        if let agentFilter { e.append(["term": ["agent.name": .string(agentFilter)]]) }
        if let groupFilter { e.append(["term": ["rule.groups": .string(groupFilter)]]) }
        return e
    }

    var body: some View {
        List {
            if !client.hasIndexer {
                EmptyStateCard(icon: "externaldrive.badge.questionmark", title: L("Chưa kết nối Indexer"),
                               message: L("Cảnh báo được lưu trong Wazuh Indexer. Thêm địa chỉ Indexer (cổng 9200) trong phần máy chủ."),
                               color: .neonOrange)
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            } else if let error, alerts.isEmpty {
                ErrorCard(message: error) { Task { await reload() } }
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            } else if loaded && alerts.isEmpty {
                EmptyStateCard(icon: "checkmark.seal.fill", title: L("Không có cảnh báo"),
                               message: Lf("Không có cảnh báo nào khớp bộ lọc trong {0} qua.", "\(range.title)"), color: .neonGreen)
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            }
            Section {
                ForEach(alerts) { alert in
                    NavigationLink { AlertDetailView(client: client, alert: alert) } label: { AlertRow(alert: alert) }
                        .listRowBackground(Color.glassRow)
                        .listRowSeparatorTint(Color.glassStroke)
                        .onAppear {
                            if alert.id == alerts.last?.id { Task { await loadMore() } }
                        }
                }
                if loadingMore {
                    LoadingRow().listRowBackground(Color.clear)
                }
            } header: {
                if !alerts.isEmpty {
                    Text(Lf("{0} cảnh báo • {1}", "\(total.formatted())", "\(range.title)")).font(.caption.monospaced())
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(TechBackground())
        .safeAreaInset(edge: .top, spacing: 0) { filterBar.background(Color.headerBar) }
        .navigationTitle(title ?? agentName.map { Lf("Cảnh báo • {0}", "\($0)") } ?? L("Cảnh báo"))
        .inlineTitleIf(agentName != nil || title != nil)
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: L("Tìm: sshd, rule.id:5710, 10.0.0.5…"))
        .onSubmit(of: .search) { appliedSearch = search }
        .onChange(of: search) { if $0.isEmpty && !appliedSearch.isEmpty { appliedSearch = "" } }
        .scrollDismissesKeyboard(.immediately)
        .refreshable { await reload() }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                if loading { ProgressView() }
            }
        }
        .task(id: "\(minLevel)|\(maxLevel ?? -1)|\(range.key)|\(appliedSearch)|\(agentFilter ?? "")|\(groupFilter ?? "")") { await reload() }
        .task(id: range.key) { await loadOptions() }
        .sheet(isPresented: $showCustom) {
            CustomRangeSheet { f, t in
                fromTS = f.timeIntervalSince1970
                toTS = t.timeIntervalSince1970
                range = .custom
            }
            .presentationDetents([.medium])
        }
    }

    private var filterBar: some View {
        ChipBar {
            Menu {
                Picker(L("Khoảng thời gian"), selection: $range) {
                    ForEach(TimeRange.presets) { Text($0.title).tag($0) }
                    if range == .custom { Text(TimeRange.custom.title).tag(TimeRange.custom) }
                }
                Button { showCustom = true } label: { Label(L("Tuỳ chọn…"), systemImage: "calendar") }
            } label: {
                HStack(spacing: 5) {
                    Image(systemName: "clock")
                    Text(range.short)
                    Image(systemName: "chevron.down").font(.caption2)
                }
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(Color.neonPurple)
                .padding(.horizontal, 14)
                .frame(minHeight: 36)
                .background(Color.chipFill, in: Capsule())
                .overlay(Capsule().strokeBorder(Color.neonPurple.opacity(0.5), lineWidth: 1))
            }
            if agentID == nil {
                menuChip(icon: "desktopcomputer", title: agentFilter ?? "Agent", active: agentFilter != nil) {
                    Button(L("Tất cả agent")) { agentFilter = nil }
                    ForEach(agentOptions, id: \.self) { a in Button(a) { agentFilter = a } }
                }
            }
            menuChip(icon: "tag", title: groupFilter ?? L("Nhóm rule"), active: groupFilter != nil) {
                Button(L("Tất cả nhóm")) { groupFilter = nil }
                ForEach(groupOptions, id: \.self) { g in Button(g) { groupFilter = g } }
            }
            ForEach(Self.levelFilters) { f in
                FilterChip(title: f.title, color: f.color, selected: minLevel == f.level && maxLevel == f.max) {
                    minLevel = f.level; maxLevel = f.max
                }
            }
        }
    }

    private func menuChip<C: View>(icon: String, title: String, active: Bool, @ViewBuilder content: () -> C) -> some View {
        Menu { content() } label: {
            HStack(spacing: 5) {
                Image(systemName: icon)
                Text(title).lineLimit(1)
                Image(systemName: "chevron.down").font(.caption2)
            }
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(active ? Color.onAccent : Color.neonCyan)
            .padding(.horizontal, 14)
            .frame(minHeight: 36)
            .background(active ? Color.neonCyan : Color.chipFill, in: Capsule())
            .overlay(Capsule().strokeBorder(Color.neonCyan.opacity(active ? 0 : 0.3), lineWidth: 1))
        }
    }

    private func loadOptions() async {
        guard client.hasIndexer else { return }
        let body: JSONValue = [
            "size": 0, "query": Q.bool([range.rangeClause] + extra),
            "aggs": ["a": ["terms": ["field": "agent.name", "size": 100, "order": ["_key": "asc"]]],
                     "g": ["terms": ["field": "rule.groups", "size": 40]]],
        ]
        if let r = try? await client.search("wazuh-alerts-*", body) {
            agentOptions = (r.path("aggregations.a.buckets")?.arrayValue ?? []).map { $0.str("key") }
            groupOptions = (r.path("aggregations.g.buckets")?.arrayValue ?? []).map { $0.str("key") }
        }
    }

    private func reload() async {
        guard client.hasIndexer else { return }
        loading = true
        defer { loading = false }
        do {
            let r = try await client.alerts(range: range, minLevel: minLevel, maxLevel: maxLevel, search: appliedSearch, agentID: agentID, extra: effectiveExtra)
            alerts = r.alerts
            total = r.total
            error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg; alerts = [] }
        }
        loaded = true
    }

    private func loadMore() async {
        guard !loadingMore, !loading, alerts.count < total, let after = alerts.last?.sortValues, !after.isEmpty else { return }
        loadingMore = true
        defer { loadingMore = false }
        if let r = try? await client.alerts(range: range, minLevel: minLevel, maxLevel: maxLevel, search: appliedSearch, agentID: agentID,
                                            extra: effectiveExtra, searchAfter: after) {
            let known = Set(alerts.map(\.id))
            alerts.append(contentsOf: r.alerts.filter { !known.contains($0.id) })
            total = r.total
        }
    }
}

struct AlertRow: View {
    let alert: WazuhAlert

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            LevelBadge(level: alert.level)
            VStack(alignment: .leading, spacing: 5) {
                Text(alert.description.isEmpty ? L("(không có mô tả)") : alert.description)
                    .font(.subheadline.weight(.medium))
                    .lineLimit(2)
                HStack(spacing: 6) {
                    Image(systemName: "desktopcomputer").font(.caption2)
                    Text(alert.agentName).lineLimit(1)
                    Spacer(minLength: 4)
                    Text(Fmt.ago(alert.timestamp)).monospacedDigit()
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    Text("#\(alert.ruleID)").font(.caption2.monospaced()).foregroundStyle(alert.severity.color.opacity(0.9))
                    if let tactic = alert.tactics.first {
                        Text(tactic).font(.caption2).foregroundStyle(Color.neonPink).lineLimit(1)
                    } else if let g = alert.groups.first {
                        Text(g).font(.caption2).foregroundStyle(.tertiary).lineLimit(1)
                    }
                }
            }
        }
        .padding(.vertical, 4)
    }
}

struct AlertDetailView: View {
    let client: WazuhClient
    let alert: WazuhAlert
    @State private var showAllFields = false

    var body: some View {
        let sev = alert.severity
        TechScroll {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    LevelBadge(level: alert.level, size: 52)
                    VStack(alignment: .leading, spacing: 4) {
                        Pill(text: sev.title, color: sev.color, icon: sev.icon)
                        Text("Rule #\(alert.ruleID)").font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                Text(alert.description).font(.title3.weight(.semibold))
                Text(Fmt.time(alert.timestamp) + L(" • ") + Fmt.ago(alert.timestamp))
                    .font(.footnote.monospacedDigit()).foregroundStyle(.secondary)
            }
            .card(glow: sev.color)

            VStack(alignment: .leading, spacing: 6) {
                CardHeader(title: L("Nguồn"), icon: "desktopcomputer")
                InfoRow(label: "Agent", value: alert.agentName)
                InfoRow(label: "ID agent", value: alert.agentID, mono: true)
                InfoRow(label: "IP", value: alert.agentIP, mono: true)
                InfoRow(label: L("Vị trí"), value: alert.location, mono: true)
                InfoRow(label: "Decoder", value: alert.decoder, mono: true)
                let src = alert.source.str("data.srcip")
                if !src.isEmpty { InfoRow(label: L("IP nguồn"), value: src, mono: true) }
                let user = alert.source.str("data.srcuser").isEmpty ? alert.source.str("data.dstuser") : alert.source.str("data.srcuser")
                if !user.isEmpty { InfoRow(label: L("Người dùng"), value: user, mono: true) }
            }
            .card()

            if !alert.groups.isEmpty || !alert.tactics.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    if !alert.tactics.isEmpty {
                        CardHeader(title: "MITRE ATT&CK", icon: "target", color: .neonPink)
                        FlowChips(items: alert.tactics + alert.techniques, color: .neonPink)
                        if !alert.mitreIDs.isEmpty {
                            Text(alert.mitreIDs.joined(separator: L(" • "))).font(.caption.monospaced()).foregroundStyle(.secondary)
                        }
                    }
                    if !alert.groups.isEmpty {
                        CardHeader(title: L("Nhóm rule"), icon: "tag.fill", color: .neonPurple)
                        FlowChips(items: alert.groups, color: .neonPurple)
                    }
                }
                .card()
            }

            quickActions

            if let data = alert.source["data"], !data.flattened().isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    CardHeader(title: L("Dữ liệu giải mã (data.*)"), icon: "curlybraces", color: .neonCyan)
                    ForEach(Array(data.flattened().prefix(60).enumerated()), id: \.offset) { _, kv in
                        InfoRow(label: kv.key, value: kv.value, mono: true)
                    }
                }
                .card()
            }

            if let geo = alert.source["GeoLocation"], !geo.flattened().isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    CardHeader(title: "GeoIP", icon: "globe.asia.australia.fill", color: .neonGreen)
                    ForEach(Array(geo.flattened().enumerated()), id: \.offset) { _, kv in
                        InfoRow(label: kv.key, value: kv.value, mono: true)
                    }
                }
                .card()
            }

            if !alert.fullLog.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        CardHeader(title: L("Log gốc"), icon: "doc.plaintext", color: .neonGreen)
                        Button {
                            #if os(iOS)
                            UIPasteboard.general.string = alert.fullLog
                            #endif
                            Haptics.success()
                        } label: { Image(systemName: "doc.on.doc") }
                    }
                    CodeBlock(text: alert.fullLog)
                }
                .card()
            }

            VStack(alignment: .leading, spacing: 8) {
                Button {
                    withAnimation { showAllFields.toggle() }
                } label: {
                    HStack {
                        CardHeader(title: L("Tất cả trường"), icon: "list.bullet.indent")
                        Image(systemName: showAllFields ? "chevron.up" : "chevron.down").foregroundStyle(.secondary)
                    }
                }
                .buttonStyle(.plain)
                if showAllFields {
                    ForEach(Array(alert.source.flattened().enumerated()), id: \.offset) { _, kv in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(kv.key).font(.caption2.monospaced()).foregroundStyle(Color.neonCyan.opacity(0.8))
                            Text(kv.value).font(.footnote.monospaced()).textSelection(.enabled)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 4)
                        Divider().opacity(0.3)
                    }
                }
            }
            .card()

            if !alert.agentID.isEmpty {
                NavigationLink {
                    AlertsView(client: client, initialRange: .d7, agentID: alert.agentID, agentName: alert.agentName)
                } label: {
                    Label(Lf("Cảnh báo khác của {0}", "\(alert.agentName)"), systemImage: "bell")
                }
                .buttonStyle(GlassButtonStyle(tint: .neonCyan))
            }
        }
        .navigationTitle(L("Chi tiết cảnh báo"))
        .inlineTitle()
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button {
                        UIPasteboard.general.string = alert.source.prettyString
                        Haptics.success()
                    } label: { Label(L("Sao chép JSON"), systemImage: "doc.on.doc") }
                    ShareLink(item: alert.source.prettyString) { Label(L("Chia sẻ JSON"), systemImage: "square.and.arrow.up") }
                } label: { Image(systemName: "ellipsis.circle") }
            }
        }
    }

    /// Lọc nhanh theo IP / rule / agent của cảnh báo này.
    @ViewBuilder private var quickActions: some View {
        let ips = ["data.srcip", "data.dstip", "data.src_ip"].compactMap { f -> (String, String)? in
            let v = alert.source.str(f); return v.isEmpty ? nil : (f, v)
        }
        VStack(alignment: .leading, spacing: 8) {
            CardHeader(title: L("Lọc nhanh"), icon: "line.3.horizontal.decrease.circle.fill", color: .neonPurple)
            ForEach(ips, id: \.1) { f, v in
                NavigationLink {
                    AlertsView(client: client, initialRange: .d7, extra: [["term": [f: .string(v)]]], title: v)
                } label: { Label(Lf("Lọc theo IP này ({0})", v), systemImage: "network") }
                .buttonStyle(GlassButtonStyle(tint: .neonCyan))
            }
            NavigationLink {
                AlertsView(client: client, initialRange: .d7, extra: [["term": ["rule.id": .string(alert.ruleID)]]], title: "Rule #\(alert.ruleID)")
            } label: { Label(Lf("Lọc theo rule này (#{0})", alert.ruleID), systemImage: "list.number") }
            .buttonStyle(GlassButtonStyle(tint: .neonPurple))
            NavigationLink { RawJSONView(json: alert.source) } label: {
                Label(L("JSON gốc"), systemImage: "curlybraces.square")
            }
            .buttonStyle(GlassButtonStyle(tint: .neonGreen))
        }
        .card()
    }
}

struct RawJSONView: View {
    let json: JSONValue
    var body: some View {
        ScrollView([.vertical, .horizontal]) {
            Text(json.prettyString)
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .padding()
        }
        .background(TechBackground())
        .navigationTitle("JSON")
        .inlineTitle()
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    UIPasteboard.general.string = json.prettyString
                    Haptics.success()
                } label: { Image(systemName: "doc.on.doc") }
            }
        }
    }
}

/// Các chip tự xuống dòng.
struct FlowChips: View {
    let items: [String]
    var color: Color = .neonCyan

    var body: some View {
        FlowLayout(spacing: 6) {
            ForEach(Array(items.enumerated()), id: \.offset) { _, t in
                Pill(text: t, color: color)
            }
        }
    }
}

struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? 320
        var x: CGFloat = 0, y: CGFloat = 0, rowH: CGFloat = 0
        for s in subviews {
            let size = s.sizeThatFits(.unspecified)
            if x > 0 && x + size.width > width { x = 0; y += rowH + spacing; rowH = 0 }
            x += size.width + spacing
            rowH = max(rowH, size.height)
        }
        return CGSize(width: width, height: y + rowH)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowH: CGFloat = 0
        for s in subviews {
            let size = s.sizeThatFits(.unspecified)
            if x > bounds.minX && x + size.width > bounds.maxX { x = bounds.minX; y += rowH + spacing; rowH = 0 }
            s.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            rowH = max(rowH, size.height)
        }
    }
}

extension View {
    @ViewBuilder func inlineTitleIf(_ condition: Bool) -> some View {
        if condition { self.inlineTitle() } else { self }
    }
}
