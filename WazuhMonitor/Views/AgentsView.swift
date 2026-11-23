import SwiftUI

struct AgentsView: View {
    let client: WazuhClient

    @State private var agents: [Agent] = []
    @State private var total = 0
    @State private var summary: AgentSummary?
    @State private var status: AgentStatus?
    @State private var search = ""
    @State private var appliedSearch = ""
    @State private var loading = false
    @State private var loadingMore = false
    @State private var loaded = false
    @State private var error: String?
    @State private var message: String?
    @State private var confirmRestart: Agent?
    @State private var managerVersion: String?

    var body: some View {
        List {
            if let error, agents.isEmpty {
                ErrorCard(message: error) { Task { await reload() } }
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            } else if loaded && agents.isEmpty {
                EmptyStateCard(icon: "desktopcomputer", title: L("Không có agent"), message: L("Không có agent nào khớp bộ lọc."))
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            }
            Section {
                ForEach(agents) { agent in
                    NavigationLink { AgentDetailView(client: client, agent: agent) } label: { AgentRow(agent: agent, managerVersion: managerVersion) }
                        .listRowBackground(Color.glassRow)
                        .listRowSeparatorTint(Color.glassStroke)
                        .swipeActions(edge: .trailing) {
                            if agent.status == .active {
                                Button { confirmRestart = agent } label: {
                                    Label(L("Khởi động lại"), systemImage: "arrow.clockwise")
                                }
                                .tint(.orange)
                            }
                        }
                        .onAppear {
                            if agent.id == agents.last?.id { Task { await loadMore() } }
                        }
                }
                if loadingMore { LoadingRow().listRowBackground(Color.clear) }
            } header: {
                if !agents.isEmpty { Text("\(total) agent").font(.caption.monospaced()) }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(TechBackground())
        .safeAreaInset(edge: .top, spacing: 0) {
            ChipBar {
                FilterChip(title: L("Tất cả"), count: summary.map { $0.total }, color: .neonCyan, selected: status == nil) { status = nil }
                ForEach(AgentStatus.allCases) { s in
                    FilterChip(title: s.title, count: summary.map { $0.count(s) },
                               color: s.color, selected: status == s) { status = s }
                }
            }
            .background(Color.headerBar)
        }
        .navigationTitle("Agent")
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: L("Tên, IP hoặc ID agent"))
        .onSubmit(of: .search) { appliedSearch = search }
        .onChange(of: search) { if $0.isEmpty && !appliedSearch.isEmpty { appliedSearch = "" } }
        .scrollDismissesKeyboard(.immediately)
        .refreshable { await reload() }
        .toolbar {
            ToolbarItem(placement: .primaryAction) { if loading { ProgressView() } }
        }
        .confirmationDialog(L("Khởi động lại agent?"), isPresented: Binding(get: { confirmRestart != nil }, set: { if !$0 { confirmRestart = nil } }),
                            titleVisibility: .visible, presenting: confirmRestart) { agent in
            Button(Lf("Khởi động lại {0}", "\(agent.name)"), role: .destructive) {
                Task {
                    do {
                        try await client.restartAgent(agent.id)
                        Haptics.success()
                        message = Lf("Đã gửi lệnh khởi động lại tới {0}.", "\(agent.name)")
                    } catch {
                        Haptics.error()
                        message = errorText(error)
                    }
                }
            }
        }
        .messageAlert(L("Thông báo"), $message)
        .task(id: "\(status?.rawValue ?? "all")|\(appliedSearch)") { await reload() }
        .task { managerVersion = (try? await client.managerInfo())?.str("version") }
    }

    private func reload() async {
        loading = true
        defer { loading = false }
        async let s = try? client.agentsSummary()
        do {
            let r = try await client.agents(offset: 0, search: appliedSearch, status: status?.rawValue)
            agents = r.agents
            total = r.total
            error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg; agents = [] }
        }
        if let s = await s { summary = s }
        loaded = true
    }

    private func loadMore() async {
        guard !loadingMore, !loading, agents.count < total else { return }
        loadingMore = true
        defer { loadingMore = false }
        if let r = try? await client.agents(offset: agents.count, search: appliedSearch, status: status?.rawValue) {
            let known = Set(agents.map(\.id))
            agents.append(contentsOf: r.agents.filter { !known.contains($0.id) })
            total = r.total
        }
    }
}

struct AgentRow: View {
    let agent: Agent
    var managerVersion: String? = nil

    private var outdated: Bool {
        guard let m = managerVersion?.replacingOccurrences(of: "v", with: ""), !m.isEmpty, !agent.version.isEmpty else { return false }
        return agent.version.replacingOccurrences(of: "v", with: "").compare(m, options: .numeric) == .orderedAscending
    }

    var body: some View {
        HStack(spacing: 12) {
            ZStack(alignment: .bottomTrailing) {
                Image(systemName: agent.osIcon)
                    .font(.system(size: 18))
                    .foregroundStyle(.primary)
                    .frame(width: 42, height: 42)
                    .background(Color.track, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                StatusDot(color: agent.statusColor, size: 11)
                    .overlay(Circle().stroke(Color.appBackground, lineWidth: 2))
                    .offset(x: 3, y: 3)
            }
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(agent.name).font(.body.weight(.semibold)).lineLimit(1)
                    Spacer(minLength: 4)
                    Text(agent.id).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                HStack(spacing: 6) {
                    Text(agent.ip).font(.caption.monospaced()).foregroundStyle(Color.neonCyan.opacity(0.85))
                    if !agent.version.isEmpty {
                        Text(agent.version).font(.caption2.monospaced())
                            .foregroundStyle(outdated ? Color.neonOrange : .secondary)
                        if outdated {
                            Image(systemName: "exclamationmark.triangle.fill").font(.caption2).foregroundStyle(Color.neonOrange)
                        }
                    }
                }
                HStack {
                    Text(agent.osText).lineLimit(1)
                    Spacer(minLength: 4)
                    Text(agent.status == .active ? agent.statusTitle : Fmt.ago(agent.lastKeepAlive))
                        .foregroundStyle(agent.statusColor)
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 3)
    }
}

// MARK: - Chi tiết agent

struct AgentDetailView: View {
    let client: WazuhClient
    @State var agent: Agent
    @Environment(\.dismiss) private var dismiss

    @State private var os: JSONValue?
    @State private var hardware: JSONValue?
    @State private var sca: [SCAPolicy] = []
    @State private var vulns: [String: Int]?
    @State private var alerts24h: Int?
    @State private var loading = false
    @State private var message: String?
    @State private var confirmRestart = false
    @State private var confirmDelete = false

    var body: some View {
        TechScroll {
            headerCard
            actions
            if client.hasIndexer {
                NavigationLink {
                    ModulesView(client: client, agentID: agent.id, agentName: agent.name)
                } label: {
                    Label(L("Dashboard theo module của agent"), systemImage: "square.stack.3d.up.fill")
                }
                .buttonStyle(GlassButtonStyle(tint: .neonPurple))
            }
            systemCard
            if !sca.isEmpty { scaCard }
            if client.hasIndexer { vulnCard }
            dangerZone
        }
        .navigationTitle(agent.name)
        .inlineTitle()
        .refreshable { await load() }
        .toolbar {
            ToolbarItem(placement: .primaryAction) { if loading { ProgressView() } }
        }
        .confirmationDialog(Lf("Khởi động lại agent {0}?", "\(agent.name)"), isPresented: $confirmRestart, titleVisibility: .visible) {
            Button(L("Khởi động lại"), role: .destructive) { Task { await restart() } }
        }
        .confirmationDialog(Lf("Xoá agent {0} khỏi manager?", "\(agent.name)"), isPresented: $confirmDelete, titleVisibility: .visible) {
            Button(L("Xoá agent"), role: .destructive) { Task { await delete() } }
        } message: {
            Text(L("Agent sẽ bị huỷ đăng ký. Thao tác này không thể hoàn tác — máy đó phải đăng ký lại mới gửi dữ liệu được."))
        }
        .messageAlert(L("Thông báo"), $message)
        .task { await load() }
    }

    private func load() async {
        loading = true
        defer { loading = false }
        if let a = try? await client.agent(agent.id) { agent = a }
        async let osT = try? client.syscollector(agent.id, "os")
        async let hwT = try? client.syscollector(agent.id, "hardware")
        async let scaT = try? client.sca(agent.id)
        os = await osT ?? nil
        hardware = await hwT ?? nil
        sca = await scaT ?? []
        if client.hasIndexer {
            async let v = try? client.vulnerabilitySummary(agentID: agent.id)
            async let a = try? client.alerts(range: .h24, minLevel: 0, search: "", agentID: agent.id, from: 0, size: 0)
            vulns = await v
            alerts24h = await a?.total
        }
    }

    private func restart() async {
        do {
            try await client.restartAgent(agent.id)
            Haptics.success()
            message = L("Đã gửi lệnh khởi động lại agent.")
        } catch {
            Haptics.error()
            message = errorText(error)
        }
    }

    private func delete() async {
        do {
            try await client.deleteAgent(agent.id)
            Haptics.success()
            dismiss()
        } catch {
            Haptics.error()
            message = errorText(error)
        }
    }

    private var headerCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                Image(systemName: agent.osIcon)
                    .font(.system(size: 26))
                    .frame(width: 56, height: 56)
                    .background(agent.statusColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(agent.statusColor.opacity(0.5)))
                VStack(alignment: .leading, spacing: 4) {
                    Text(agent.name).font(.title3.weight(.bold))
                    HStack(spacing: 6) {
                        Pill(text: agent.statusTitle, color: agent.statusColor)
                        Pill(text: "ID " + agent.id, color: .gray)
                    }
                }
                Spacer()
            }
            Divider().opacity(0.3)
            InfoRow(label: L("Địa chỉ IP"), value: agent.ip, mono: true)
            InfoRow(label: L("Hệ điều hành"), value: agent.osText)
            InfoRow(label: L("Phiên bản agent"), value: agent.version, mono: true)
            InfoRow(label: L("Liên lạc gần nhất"), value: Fmt.ago(agent.lastKeepAlive))
            InfoRow(label: L("Đăng ký lúc"), value: Fmt.time(agent.dateAdd))
            if !agent.node.isEmpty { InfoRow(label: "Node", value: agent.node, mono: true) }
            if !agent.groups.isEmpty {
                FlowChips(items: agent.groups, color: .neonPurple)
            }
        }
        .card(glow: agent.statusColor)
    }

    private var actions: some View {
        HStack(spacing: 10) {
            if client.hasIndexer {
                NavigationLink {
                    AlertsView(client: client, initialRange: .h24, agentID: agent.id, agentName: agent.name)
                } label: {
                    VStack(spacing: 4) {
                        Image(systemName: "bell.badge.fill")
                        Text(alerts24h.map { Lf("{0} cảnh báo", "\(Fmt.compact($0))") } ?? L("Cảnh báo")).font(.caption).lineLimit(1)
                    }
                }
                .buttonStyle(GlassButtonStyle(tint: .neonCyan))
            }
            NavigationLink {
                PackagesView(client: client, agentID: agent.id)
            } label: {
                VStack(spacing: 4) {
                    Image(systemName: "shippingbox.fill")
                    Text(L("Phần mềm")).font(.caption)
                }
            }
            .buttonStyle(GlassButtonStyle(tint: .neonPurple))
            Button { confirmRestart = true } label: {
                VStack(spacing: 4) {
                    Image(systemName: "arrow.clockwise")
                    Text(L("Khởi động lại")).font(.caption).lineLimit(1)
                }
            }
            .buttonStyle(GlassButtonStyle(tint: .neonOrange))
            .disabled(agent.status != .active)
        }
    }

    @ViewBuilder private var systemCard: some View {
        if os != nil || hardware != nil {
            VStack(alignment: .leading, spacing: 6) {
                CardHeader(title: L("Phần cứng & hệ thống"), icon: "cpu", color: .neonCyan)
                if let os {
                    InfoRow(label: L("Tên máy"), value: os.str("hostname"))
                    InfoRow(label: L("Kiến trúc"), value: os.str("architecture"), mono: true)
                    InfoRow(label: "Kernel", value: os.str("os.release").isEmpty ? os.str("release") : os.str("os.release"), mono: true)
                }
                if let hardware {
                    InfoRow(label: "CPU", value: hardware.str("cpu.name"))
                    InfoRow(label: L("Số nhân"), value: hardware.str("cpu.cores"))
                    if let totalKB = hardware.path("ram.total")?.doubleValue, totalKB > 0 {
                        let usage = hardware.path("ram.usage")?.doubleValue ?? 0
                        HStack {
                            Text("RAM").font(.subheadline).foregroundStyle(.secondary)
                            Spacer()
                            Text("\(Int(usage))% / \(Fmt.bytes(totalKB * 1024))").font(.subheadline.monospaced())
                        }
                        MeterBar(value: usage / 100, color: usage > 85 ? .neonRed : .neonCyan)
                    }
                }
            }
            .card()
        }
    }

    private var scaCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: L("Đánh giá cấu hình (SCA)"), icon: "checklist", color: .neonGreen)
            ForEach(sca) { p in
                NavigationLink {
                    SCAChecksView(client: client, agentID: agent.id, policy: p)
                } label: {
                    HStack(spacing: 12) {
                        ZStack {
                            RingGauge(value: Double(p.score) / 100, color: p.scoreColor, lineWidth: 5)
                            Text("\(p.score)%").font(.caption2.weight(.bold).monospacedDigit())
                        }
                        .frame(width: 46, height: 46)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(p.name).font(.subheadline.weight(.medium)).lineLimit(2).multilineTextAlignment(.leading)
                            HStack(spacing: 10) {
                                Label("\(p.pass)", systemImage: "checkmark.circle.fill").foregroundStyle(Color.neonGreen)
                                Label("\(p.fail)", systemImage: "xmark.circle.fill").foregroundStyle(Color.neonRed)
                                Label("\(p.invalid)", systemImage: "minus.circle.fill").foregroundStyle(.secondary)
                            }
                            .font(.caption.monospacedDigit())
                        }
                        Spacer(minLength: 0)
                        Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .card()
    }

    private var vulnCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: L("Lỗ hổng (CVE)"), icon: "ladybug.fill", color: .neonRed)
            if let vulns {
                let total = vulns.values.reduce(0, +)
                if total == 0 {
                    Label(L("Không phát hiện lỗ hổng"), systemImage: "checkmark.seal.fill").foregroundStyle(Color.neonGreen)
                } else {
                    HStack(spacing: 8) {
                        ForEach(VulnSeverity.allCases) { s in
                            NavigationLink {
                                VulnerabilitiesView(client: client, agentID: agent.id, initialSeverity: s)
                            } label: {
                                VStack(spacing: 3) {
                                    Text(Fmt.compact(vulns[s.rawValue] ?? 0))
                                        .font(.system(size: 19, weight: .bold, design: .rounded))
                                        .foregroundStyle(s.color)
                                    Text(s.title).font(.caption2).foregroundStyle(.secondary).lineLimit(1).minimumScaleFactor(0.8)
                                }
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 10)
                                .background(s.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    NavigationLink {
                        VulnerabilitiesView(client: client, agentID: agent.id, initialSeverity: nil)
                    } label: {
                        Label(Lf("Xem tất cả {0} lỗ hổng", "\(total)"), systemImage: "list.bullet")
                    }
                    .buttonStyle(GlassButtonStyle(tint: .neonRed))
                }
            } else {
                Text(loading ? L("Đang tải…") : L("Không có dữ liệu lỗ hổng (cần Wazuh 4.8+).")).font(.footnote).foregroundStyle(.secondary)
            }
        }
        .card()
    }

    private var dangerZone: some View {
        Button(role: .destructive) { confirmDelete = true } label: {
            Label(L("Xoá agent"), systemImage: "trash")
        }
        .buttonStyle(GlassButtonStyle(tint: .neonRed))
        .disabled(agent.id == "000")
        .padding(.top, 8)
    }
}

// MARK: - SCA

struct SCAChecksView: View {
    let client: WazuhClient
    let agentID: String
    let policy: SCAPolicy

    @State private var result: String? = "failed"
    @State private var checks: [SCACheck] = []
    @State private var loading = false
    @State private var error: String?
    @State private var expanded: Set<String> = []

    var body: some View {
        List {
            if let error {
                ErrorCard(message: error) { Task { await load() } }.listRowBackground(Color.clear)
            }
            Section {
                ForEach(checks) { c in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(alignment: .top, spacing: 10) {
                            StatusDot(color: c.resultColor, size: 9).padding(.top, 5)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(c.title).font(.subheadline)
                                Text(Lf("#{0} • {1}", "\(c.id)", "\(c.resultTitle)")).font(.caption.monospaced()).foregroundStyle(c.resultColor)
                            }
                            Spacer(minLength: 0)
                            Image(systemName: expanded.contains(c.id) ? "chevron.up" : "chevron.down")
                                .font(.caption).foregroundStyle(.tertiary)
                        }
                        if expanded.contains(c.id) {
                            if !c.rationale.isEmpty {
                                Text(L("Lý do")).techLabel()
                                Text(c.rationale).font(.footnote).foregroundStyle(.secondary)
                            }
                            if !c.remediation.isEmpty {
                                Text(L("Cách khắc phục")).techLabel()
                                Text(c.remediation).font(.footnote)
                            }
                        }
                    }
                    .padding(.vertical, 4)
                    .contentShape(Rectangle())
                    .onTapGesture {
                        withAnimation(.easeOut(duration: 0.2)) {
                            if expanded.contains(c.id) { expanded.remove(c.id) } else { expanded.insert(c.id) }
                        }
                    }
                    .listRowBackground(Color.glassRow)
                }
            } header: {
                Text(policy.name)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(TechBackground())
        .safeAreaInset(edge: .top, spacing: 0) {
            ChipBar {
                FilterChip(title: L("Không đạt"), count: policy.fail, color: .neonRed, selected: result == "failed") { result = "failed" }
                FilterChip(title: L("Đạt"), count: policy.pass, color: .neonGreen, selected: result == "passed") { result = "passed" }
                FilterChip(title: L("Tất cả"), color: .neonCyan, selected: result == nil) { result = nil }
            }
            .background(Color.headerBar)
        }
        .navigationTitle(L("Kiểm tra SCA"))
        .inlineTitle()
        .toolbar { ToolbarItem(placement: .primaryAction) { if loading { ProgressView() } } }
        .refreshable { await load() }
        .task(id: result) { await load() }
    }

    private func load() async {
        loading = true
        defer { loading = false }
        do {
            checks = try await client.scaChecks(agentID, policy: policy.id, result: result)
            error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg }
        }
    }
}

// MARK: - Phần mềm đã cài

struct PackagesView: View {
    let client: WazuhClient
    let agentID: String

    @State private var items: [JSONValue] = []
    @State private var total = 0
    @State private var search = ""
    @State private var appliedSearch = ""
    @State private var error: String?
    @State private var loadingMore = false

    var body: some View {
        GlassList {
            if let error {
                ErrorCard(message: error) { Task { await reload() } }
            }
            Section {
                ForEach(Array(items.enumerated()), id: \.offset) { i, p in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(p.str("name")).font(.subheadline.weight(.medium)).lineLimit(1)
                            Spacer()
                            Text(p.str("architecture")).font(.caption2.monospaced()).foregroundStyle(.tertiary)
                        }
                        Text(p.str("version")).font(.caption.monospaced()).foregroundStyle(Color.neonCyan.opacity(0.85))
                        if !p.str("vendor").isEmpty {
                            Text(p.str("vendor")).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                    .onAppear { if i == items.count - 1 { Task { await loadMore() } } }
                }
            } header: {
                Text(Lf("{0} gói", "\(total)")).font(.caption.monospaced())
            }
        }
        .navigationTitle(L("Phần mềm"))
        .inlineTitle()
        .searchable(text: $search, prompt: L("Tên gói"))
        .onSubmit(of: .search) { appliedSearch = search }
        .onChange(of: search) { if $0.isEmpty && !appliedSearch.isEmpty { appliedSearch = "" } }
        .task(id: appliedSearch) { await reload() }
    }

    private func reload() async {
        do {
            let r = try await client.packages(agentID, offset: 0, search: appliedSearch)
            items = r.items; total = r.total; error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg }
        }
    }

    private func loadMore() async {
        guard !loadingMore, items.count < total else { return }
        loadingMore = true
        defer { loadingMore = false }
        if let r = try? await client.packages(agentID, offset: items.count, search: appliedSearch) {
            items.append(contentsOf: r.items)
            total = r.total
        }
    }
}

// MARK: - Lỗ hổng

struct VulnerabilitiesView: View {
    let client: WazuhClient
    let agentID: String
    @State var initialSeverity: VulnSeverity?

    @State private var items: [Vulnerability] = []
    @State private var total = 0
    @State private var error: String?
    @State private var loading = false
    @State private var selected: Vulnerability?

    var body: some View {
        List {
            if let error {
                ErrorCard(message: error) { Task { await load() } }.listRowBackground(Color.clear)
            }
            Section {
                ForEach(items) { v in
                    Button { selected = v } label: {
                        HStack(alignment: .top, spacing: 12) {
                            Text(v.score.map { String(format: "%.1f", $0) } ?? L("–"))
                                .font(.system(.subheadline, design: .monospaced).weight(.bold))
                                .foregroundStyle(VulnSeverity.color(for: v.severity))
                                .frame(width: 44, height: 34)
                                .background(VulnSeverity.color(for: v.severity).opacity(0.13), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                            VStack(alignment: .leading, spacing: 3) {
                                Text(v.cve).font(.subheadline.monospaced().weight(.semibold))
                                Text("\(v.packageName) \(v.packageVersion)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                            Spacer(minLength: 0)
                        }
                    }
                    .buttonStyle(.plain)
                    .listRowBackground(Color.glassRow)
                }
            } header: {
                Text(Lf("{0} lỗ hổng", "\(total)")).font(.caption.monospaced())
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(TechBackground())
        .safeAreaInset(edge: .top, spacing: 0) {
            ChipBar {
                FilterChip(title: L("Tất cả"), color: .neonCyan, selected: initialSeverity == nil) { initialSeverity = nil }
                ForEach(VulnSeverity.allCases) { s in
                    FilterChip(title: s.title, color: s.color, selected: initialSeverity == s) { initialSeverity = s }
                }
            }
            .background(Color.headerBar)
        }
        .navigationTitle(L("Lỗ hổng"))
        .inlineTitle()
        .toolbar { ToolbarItem(placement: .primaryAction) { if loading { ProgressView() } } }
        .refreshable { await load() }
        .sheet(item: $selected) { v in
            NavigationStack { VulnDetailView(v: v) }
                .presentationDetents([.medium, .large])
        }
        .task(id: initialSeverity) { await load() }
    }

    private func load() async {
        loading = true
        defer { loading = false }
        do {
            let r = try await client.vulnerabilities(agentID: agentID, severity: initialSeverity?.rawValue)
            items = r.items; total = r.total; error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg }
        }
    }
}

struct VulnDetailView: View {
    let v: Vulnerability
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        TechScroll {
            VStack(alignment: .leading, spacing: 8) {
                Text(v.cve).font(.title2.monospaced().weight(.bold))
                HStack {
                    Pill(text: VulnSeverity(rawValue: v.severity)?.title ?? v.severity, color: VulnSeverity.color(for: v.severity))
                    if let s = v.score { Pill(text: "CVSS \(String(format: "%.1f", s))", color: .gray) }
                }
                InfoRow(label: L("Gói"), value: v.packageName, mono: true)
                InfoRow(label: L("Phiên bản"), value: v.packageVersion, mono: true)
                if !v.agentName.isEmpty { InfoRow(label: "Agent", value: v.agentName) }
                if !v.os.isEmpty { InfoRow(label: L("Hệ điều hành"), value: v.os) }
                if !v.published.isEmpty { InfoRow(label: L("Công bố"), value: Fmt.time(v.published)) }
                if !v.detected.isEmpty { InfoRow(label: L("Phát hiện"), value: Fmt.time(v.detected)) }
            }
            .card(glow: VulnSeverity.color(for: v.severity))
            if !v.description.isEmpty {
                Text(v.description).font(.callout).card()
            }
            if !v.reference.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    CardHeader(title: L("Tham khảo"), icon: "link", color: .neonCyan)
                    Text(v.reference.replacingOccurrences(of: ", ", with: "\n")).font(.caption.monospaced()).textSelection(.enabled)
                }
                .card()
            }
            if let url = URL(string: v.reference.components(separatedBy: ",").first?.trimmed ?? ""), url.scheme != nil {
                Link(destination: url) { Label(L("Mở tài liệu tham khảo"), systemImage: "safari") }
                    .buttonStyle(GlassButtonStyle(tint: .neonCyan))
            }
        }
        .navigationTitle(L("Chi tiết CVE"))
        .inlineTitle()
        .toolbar { ToolbarItem(placement: .cancellationAction) { Button(L("Đóng")) { dismiss() } } }
    }
}
