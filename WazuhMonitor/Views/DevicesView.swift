import SwiftUI

/// Khối "Thiết bị" trong tab Dashboard: mỗi thiết bị cuối (agent hoặc thiết bị gửi syslog) một ô,
/// nhóm theo loại (tường lửa, NAS, máy chủ…). Giữ tay để đổi tên / loại.
struct DevicesSection: View {
    let client: WazuhClient
    let range: TimeRange
    @EnvironmentObject private var store: ServerStore

    @State private var devices: [DeviceStat] = []
    @State private var error: String?
    @State private var editing: DeviceStat?
    @State private var labelsVersion = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let error {
                Text(error).font(.caption).foregroundStyle(Color.neonOrange)
            }
            let groups = grouped()
            if groups.isEmpty && error == nil {
                Text(L("Đang tải…")).font(.footnote).foregroundStyle(.secondary)
            }
            ForEach(groups) { g in
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 6) {
                        Image(systemName: g.type.icon).font(.caption).foregroundStyle(g.type.color)
                        Text(g.type.title).techLabel()
                        Text("\(g.items.count)").font(.caption2.monospacedDigit()).foregroundStyle(.tertiary)
                    }
                    .padding(.leading, 4)
                    LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
                        ForEach(g.items) { d in
                            NavigationLink {
                                ModuleDashboardView(client: client, module: module(for: d),
                                                    agentID: d.kind == .agent ? d.key : nil, agentName: nil)
                            } label: {
                                DeviceTile(device: d, label: label(d))
                            }
                            .buttonStyle(.plain)
                            .contextMenu {
                                Button { editing = d } label: { Label(L("Đổi tên / loại"), systemImage: "pencil") }
                                if DeviceLabels.get(server: store.activeID, device: d.id) != nil {
                                    Button(role: .destructive) {
                                        DeviceLabels.set(nil, server: store.activeID, device: d.id)
                                        labelsVersion += 1
                                    } label: { Label(L("Khôi phục tên tự động"), systemImage: "arrow.uturn.backward") }
                                }
                            }
                        }
                    }
                }
            }
            if !devices.isEmpty {
                Text(L("Giữ tay vào một thiết bị để đổi tên hoặc chọn loại."))
                    .font(.caption2).foregroundStyle(.tertiary).padding(.leading, 4)
            }
        }
        .id(labelsVersion)
        .sheet(item: $editing) { d in
            NavigationStack {
                DeviceEditSheet(device: d, initial: label(d)) { newLabel in
                    DeviceLabels.set(newLabel, server: store.activeID, device: d.id)
                    labelsVersion += 1
                }
            }
            .presentationDetents([.medium])
        }
        .task(id: range) { await load() }
    }

    private func label(_ d: DeviceStat) -> DeviceLabel {
        DeviceLabels.get(server: store.activeID, device: d.id)
            ?? DeviceLabel(name: d.autoName, type: DeviceType.guess(name: d.autoName, hint: d.hint, isAgent: d.kind == .agent))
    }

    private struct DeviceGroup: Identifiable {
        let type: DeviceType
        let items: [DeviceStat]
        var id: String { type.rawValue }
    }

    private func grouped() -> [DeviceGroup] {
        _ = labelsVersion
        let byType = Dictionary(grouping: devices) { label($0).type }
        return DeviceType.allCases.compactMap { t in
            guard let items = byType[t], !items.isEmpty else { return nil }
            return DeviceGroup(type: t, items: items.sorted { ($0.maxLevel, $0.alerts) > ($1.maxLevel, $1.alerts) })
        }
    }

    private func module(for d: DeviceStat) -> WazuhModule {
        let l = label(d)
        let subtitle = l.type.title + (d.address.isEmpty ? "" : " • " + d.address)
        switch d.kind {
        case .syslog:
            let filter: JSONValue = ["bool": ["filter": [
                ["term": ["agent.id": "000"]], ["term": ["location": .string(d.key)]],
            ]]]
            return WazuhModule(id: "device-" + d.id, title: l.name, subtitle: subtitle, icon: l.type.icon, color: l.type.color,
                               filter: filter,
                               fields: [.init(field: "rule.description", title: L("Sự kiện")),
                                        .init(field: "data.srcip", title: L("IP nguồn")),
                                        .init(field: "data.dstip", title: L("IP đích")),
                                        .init(field: "data.dstport", title: L("Cổng đích")),
                                        .init(field: "data.action", title: L("Hành động")),
                                        .init(field: "data.srcuser", title: L("Người dùng")),
                                        .init(field: "predecoder.program_name", title: L("Chương trình"))],
                               section: .network)
        case .agent:
            return WazuhModule(id: "device-" + d.id, title: l.name, subtitle: subtitle + " • ID " + d.key,
                               icon: l.type.icon, color: l.type.color, filter: nil,
                               fields: [.init(field: "rule.description", title: L("Sự kiện")),
                                        .init(field: "rule.groups", title: L("Nhóm rule")),
                                        .init(field: "rule.mitre.tactic", title: L("Chiến thuật")),
                                        .init(field: "data.srcip", title: L("IP nguồn")),
                                        .init(field: "syscheck.path", title: L("Đường dẫn")),
                                        .init(field: "data.win.system.eventID", title: "Event ID")],
                               section: .system)
        }
    }

    private func load() async {
        do {
            var stats = try await client.deviceStats(range: range)
            // Thêm cả agent chưa có cảnh báo nào trong khoảng thời gian.
            if let agents = try? await client.agents(offset: 0, limit: 500) {
                let known = Set(stats.filter { $0.kind == .agent }.map(\.key))
                for a in agents.agents where !known.contains(a.id) {
                    stats.append(DeviceStat(kind: .agent, key: a.id, autoName: a.name, address: a.ip,
                                            alerts: 0, maxLevel: 0, hint: a.osText))
                }
            }
            devices = stats
            error = nil
        } catch {
            if let msg = errorText(error) { self.error = msg }
        }
    }
}

struct DeviceTile: View {
    let device: DeviceStat
    let label: DeviceLabel

    var body: some View {
        let sev = Severity(level: device.maxLevel)
        let hot = device.alerts > 0 && device.maxLevel >= 12
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top) {
                Image(systemName: label.type.icon)
                    .font(.title3)
                    .foregroundStyle(label.type.color)
                    .frame(width: 36, height: 36)
                    .background(label.type.color.opacity(0.12), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                Spacer()
                if device.alerts > 0 {
                    LevelBadge(level: device.maxLevel, size: 26)
                }
            }
            Text(label.name)
                .font(.subheadline.weight(.semibold))
                .lineLimit(1)
            Text(device.address.isEmpty ? (device.kind == .agent ? "ID " + device.key : device.key) : device.address)
                .font(.caption2.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(1)
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text(Fmt.compact(device.alerts))
                    .font(.system(size: 18, weight: .bold, design: .rounded))
                    .foregroundStyle(device.alerts > 0 ? sev.color : .secondary)
                Text(L("cảnh báo")).font(.caption2).foregroundStyle(.secondary)
                Spacer(minLength: 0)
                Image(systemName: device.kind == .syslog ? "antenna.radiowaves.left.and.right" : "shield.lefthalf.filled")
                    .font(.caption2).foregroundStyle(.tertiary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card(glow: hot ? sev.color : nil)
    }
}

struct DeviceEditSheet: View {
    let device: DeviceStat
    let initial: DeviceLabel
    let onSave: (DeviceLabel) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var type: DeviceType = .other

    var body: some View {
        GlassForm {
            Section {
                TextField(L("Tên thiết bị"), text: $name)
                Picker(L("Loại thiết bị"), selection: $type) {
                    ForEach(DeviceType.allCases) { t in
                        Label(t.title, systemImage: t.icon).tag(t)
                    }
                }
            } footer: {
                Text(device.kind == .syslog ? "Syslog • \(device.key)" : "Agent • ID \(device.key)")
            }
        }
        .navigationTitle(L("Đổi tên / loại"))
        .inlineTitle()
        .onAppear { name = initial.name; type = initial.type }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button(L("Huỷ")) { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button(L("Lưu")) {
                    onSave(DeviceLabel(name: name.trimmed.isEmpty ? device.autoName : name.trimmed, type: type))
                    dismiss()
                }
            }
        }
    }
}
