import SwiftUI

struct SystemView: View {
    let client: WazuhClient
    @EnvironmentObject private var store: ServerStore
    @AppStorage("dashboard.refreshSeconds") private var refreshSeconds = 60
    @AppStorage(AppLanguage.storageKey) private var lang = AppLanguage.vi.rawValue
    @AppStorage(AppAppearance.storageKey) private var appearance = AppAppearance.system.rawValue

    @State private var info: JSONValue?
    @State private var daemons: [Daemon] = []
    @State private var cluster: JSONValue?
    @State private var nodes: [JSONValue] = []
    @State private var error: String?
    @State private var loading = false
    @State private var confirmRestart = false
    @State private var message: String?
    @State private var summary: AgentSummary?
    @State private var outdated = 0

    var body: some View {
        TechScroll {
            if let error { ErrorCard(message: error) { Task { await load() } } }

            NavigationLink { ServerListView() } label: {
                HStack(spacing: 12) {
                    Image(systemName: "server.rack")
                        .font(.title3)
                        .foregroundStyle(Color.neonCyan)
                        .neonGlow(.neonCyan, radius: 6)
                        .frame(width: 44, height: 44)
                        .background(Color.neonCyan.opacity(0.1), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(store.activeServer?.displayName ?? L("—")).font(.headline)
                        Text(store.activeServer?.url ?? "").font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                        Text(client.hasIndexer ? L("Indexer: đã kết nối") : L("Indexer: chưa cấu hình"))
                            .font(.caption2)
                            .foregroundStyle(client.hasIndexer ? Color.neonGreen : Color.neonOrange)
                    }
                    Spacer()
                    Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                }
                .card()
            }
            .buttonStyle(.plain)

            if let info {
                VStack(alignment: .leading, spacing: 6) {
                    CardHeader(title: "Manager", icon: "shield.lefthalf.filled", color: .neonCyan)
                    InfoRow(label: L("Phiên bản"), value: info.str("version"), mono: true)
                    InfoRow(label: L("Loại"), value: info.str("type"))
                    InfoRow(label: L("Múi giờ"), value: info.str("tz_name"))
                    InfoRow(label: L("Thư mục"), value: info.str("path"), mono: true)
                    if let cluster {
                        InfoRow(label: "Cluster", value: cluster.str("enabled") == "yes"
                                ? (cluster.str("running") == "yes" ? L("Đang chạy") : L("Đã bật, không chạy")) : L("Không dùng"))
                    }
                }
                .card()
            }

            if !daemons.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    CardHeader(title: L("Dịch vụ"), icon: "gearshape.2.fill", color: .neonGreen)
                    LazyVGrid(columns: [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)], spacing: 8) {
                        ForEach(daemons) { d in
                            let running = d.state == "running"
                            HStack(spacing: 6) {
                                StatusDot(color: running ? .neonGreen : .gray, size: 7)
                                Text(d.name.replacingOccurrences(of: "wazuh-", with: ""))
                                    .font(.caption.monospaced())
                                    .foregroundStyle(running ? .primary : .secondary)
                                    .lineLimit(1)
                                Spacer(minLength: 0)
                            }
                            .padding(.horizontal, 10)
                            .frame(minHeight: 34)
                            .background(running ? Color.track : Color.track.opacity(0.4), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                        }
                    }
                }
                .card()
            }

            if !nodes.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    CardHeader(title: "Node cluster", icon: "point.3.connected.trianglepath.dotted", color: .neonPurple)
                    ForEach(Array(nodes.enumerated()), id: \.offset) { _, n in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(n.str("name")).font(.subheadline.weight(.medium))
                                Text(n.str("ip")).font(.caption.monospaced()).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Pill(text: n.str("type"), color: n.str("type") == "master" ? .neonPurple : .neonCyan)
                        }
                    }
                }
                .card()
            }

            NavigationLink { AgentsView(client: client) } label: {
                HStack(spacing: 12) {
                    Image(systemName: "desktopcomputer").font(.title3).foregroundStyle(Color.neonGreen)
                        .frame(width: 44, height: 44)
                        .background(Color.neonGreen.opacity(0.1), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Agent").font(.headline)
                        Text(Lf("{0} hoạt động • {1} mất kết nối • {2} tổng", "\(summary?.active ?? 0)", "\(summary?.disconnected ?? 0)", "\(summary?.total ?? 0)"))
                            .font(.caption).foregroundStyle(.secondary)
                        if outdated > 0 {
                            Text(Lf("{0} agent cũ hơn manager", "\(outdated)")).font(.caption2).foregroundStyle(Color.neonOrange)
                        }
                    }
                    Spacer()
                    Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                }
                .card()
            }
            .buttonStyle(.plain)

            VStack(spacing: 10) {
                NavigationLink { ManagerLogsView(client: client) } label: {
                    Label(L("Nhật ký manager"), systemImage: "doc.text.magnifyingglass")
                }
                .buttonStyle(GlassButtonStyle(tint: .neonCyan))
                Button { confirmRestart = true } label: {
                    Label(L("Khởi động lại manager"), systemImage: "power")
                }
                .buttonStyle(GlassButtonStyle(tint: .neonOrange))
            }

            VStack(alignment: .leading, spacing: 10) {
                CardHeader(title: L("Ứng dụng"), icon: "iphone", color: .neonPurple)
                HStack {
                    Text(L("Tự làm mới tổng quan")).font(.subheadline)
                    Spacer()
                    Picker(L("Tự làm mới"), selection: $refreshSeconds) {
                        Text(L("Tắt")).tag(0)
                        Text(L("30 giây")).tag(30)
                        Text(L("1 phút")).tag(60)
                        Text(L("5 phút")).tag(300)
                    }
                    .pickerStyle(.menu)
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text(L("Giao diện")).font(.subheadline)
                    Picker(L("Giao diện"), selection: $appearance) {
                        ForEach(AppAppearance.allCases) { a in
                            Label(a.title, systemImage: a.icon).tag(a.rawValue)
                        }
                    }
                    .pickerStyle(.segmented)
                }
                HStack {
                    Text(L("Ngôn ngữ")).font(.subheadline)
                    Spacer()
                    Picker(L("Ngôn ngữ"), selection: $lang) {
                        ForEach(AppLanguage.allCases) { Text($0.title).tag($0.rawValue) }
                    }
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 200)
                }
                InfoRow(label: L("Phiên bản app"), value: (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0")
                        + " (" + (Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1") + ")", mono: true)
            }
            .card()
        }
        .navigationTitle(L("Hệ thống"))
        .refreshable { await load() }
        .toolbar { ToolbarItem(placement: .primaryAction) { if loading { ProgressView() } } }
        .confirmationDialog(L("Khởi động lại Wazuh manager?"), isPresented: $confirmRestart, titleVisibility: .visible) {
            Button(L("Khởi động lại"), role: .destructive) {
                Task {
                    do {
                        try await client.restartManager()
                        Haptics.success()
                        message = L("Đã gửi lệnh khởi động lại. Manager sẽ tạm ngưng khoảng 1 phút.")
                    } catch {
                        Haptics.error()
                        message = errorText(error)
                    }
                }
            }
        } message: {
            Text(L("Trong lúc khởi động lại, manager sẽ không nhận dữ liệu từ agent."))
        }
        .messageAlert(L("Thông báo"), $message)
        .task { await load() }
    }

    private func load() async {
        loading = true
        defer { loading = false }
        do {
            async let i = client.managerInfo()
            async let d = client.managerStatus()
            let (iv, dv) = try await (i, d)
            info = iv
            daemons = dv
            error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg }
        }
        summary = try? await client.agentsSummary()
        if let v = info?.str("version"), !v.isEmpty, let all = try? await client.allAgents() {
            outdated = all.filter { !$0.version.isEmpty && $0.version.compare(v.replacingOccurrences(of: "v", with: ""), options: .numeric) == .orderedAscending }.count
        }
        cluster = try? await client.clusterStatus()
        if cluster?.str("running") == "yes" {
            nodes = (try? await client.clusterNodes()) ?? []
        }
    }
}

struct ManagerLogsView: View {
    let client: WazuhClient

    @State private var level: String?
    @State private var logs: [LogEntry] = []
    @State private var total = 0
    @State private var search = ""
    @State private var appliedSearch = ""
    @State private var error: String?
    @State private var loading = false
    @State private var loadingMore = false

    private static var levels: [(String?, String, Color)] { [
        (nil, L("Tất cả"), .neonCyan), ("error", L("Lỗi"), .neonRed), ("warning", L("Cảnh báo"), .neonOrange), ("info", L("Thông tin"), .neonGreen),
    ] }

    var body: some View {
        List {
            if let error {
                ErrorCard(message: error) { Task { await reload() } }.listRowBackground(Color.clear)
            }
            Section {
                ForEach(logs) { log in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Text(log.level.uppercased())
                                .font(.caption2.monospaced().weight(.bold))
                                .foregroundStyle(log.color)
                            Text(log.tag).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                            Spacer()
                            Text(Fmt.time(log.timestamp)).font(.caption2.monospacedDigit()).foregroundStyle(.tertiary)
                        }
                        Text(log.text).font(.footnote.monospaced()).textSelection(.enabled)
                    }
                    .padding(.vertical, 2)
                    .listRowBackground(Color.glassRow)
                    .onAppear { if log.id == logs.last?.id { Task { await loadMore() } } }
                }
                if loadingMore { LoadingRow().listRowBackground(Color.clear) }
            } header: {
                Text(Lf("{0} dòng", "\(total)")).font(.caption.monospaced())
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(TechBackground())
        .safeAreaInset(edge: .top, spacing: 0) {
            ChipBar {
                ForEach(0..<Self.levels.count, id: \.self) { i in
                    let l = Self.levels[i]
                    FilterChip(title: l.1, color: l.2, selected: level == l.0) { level = l.0 }
                }
            }
            .background(Color.headerBar)
        }
        .navigationTitle(L("Nhật ký manager"))
        .inlineTitle()
        .searchable(text: $search, prompt: L("Tìm trong nhật ký"))
        .onSubmit(of: .search) { appliedSearch = search }
        .onChange(of: search) { if $0.isEmpty && !appliedSearch.isEmpty { appliedSearch = "" } }
        .refreshable { await reload() }
        .toolbar { ToolbarItem(placement: .primaryAction) { if loading { ProgressView() } } }
        .task(id: "\(level ?? "all")|\(appliedSearch)") { await reload() }
    }

    private func reload() async {
        loading = true
        defer { loading = false }
        do {
            let r = try await client.managerLogs(offset: 0, level: level, search: appliedSearch)
            logs = r.logs; total = r.total; error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg }
        }
    }

    private func loadMore() async {
        guard !loadingMore, !loading, logs.count < total else { return }
        loadingMore = true
        defer { loadingMore = false }
        if let r = try? await client.managerLogs(offset: logs.count, level: level, search: appliedSearch) {
            logs.append(contentsOf: r.logs)
            total = r.total
        }
    }
}
