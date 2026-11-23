import SwiftUI

/// Một thiết bị trên SOC Home — thêm thiết bị mới = thêm một cấu hình.
struct DeviceConfig: Identifiable, Hashable {
    enum Kind: String, Hashable { case firewall, nas, wifi, agent }

    let id: String
    let title: String
    let address: String
    let icon: String
    let color: Color
    /// Bộ lọc dạng KQL / query_string, vd. `rule.groups:fortigate`.
    let filter: String
    let kind: Kind
    /// Tên agent (cho thiết bị cài agent) — dùng để lấy CVE, SCA, inventory.
    var agentName: String? = nil
    var groups: [PanelGroup] = []

    func hash(into h: inout Hasher) { h.combine(id) }
    static func == (a: DeviceConfig, b: DeviceConfig) -> Bool { a.id == b.id }
}

private let fgAccept = "data.action:(accept OR close OR timeout OR server-rst OR client-rst OR permit OR allow)"
private let fgDeny = "data.action:(deny OR denied OR blocked OR block OR dropped OR drop)"
private let sent = NumField(primary: "data.sentdelta", fallback: "data.sentbyte")
private let rcvd = NumField(primary: "data.rcvddelta", fallback: "data.rcvdbyte")
private let authOK = "rule.groups:authentication_success"
private let authFail = "rule.groups:(authentication_failed OR authentication_failures OR win_authentication_failed OR invalid_login)"

extension DeviceConfig {
    /// Các mục chung cho mọi thiết bị.
    static var commonGroup: PanelGroup {
        PanelGroup(title: L("Tổng quan sự kiện"), icon: "square.grid.2x2.fill", panels: [
            Panel(title: L("Chỉ số"), icon: "number", kind: .kpis([
                KPI(title: L("Sự kiện"), icon: "waveform.path.ecg", kind: .total),
                KPI(title: L("Cảnh báo ≥ 7"), icon: "exclamationmark.circle.fill", kind: .levelGTE(7), alert: true),
                KPI(title: L("Cao ≥ 12"), icon: "exclamationmark.triangle.fill", kind: .levelGTE(12), alert: true),
                KPI(title: L("Nghiêm trọng ≥ 15"), icon: "flame.fill", kind: .levelGTE(15), alert: true),
            ])),
            Panel(title: L("Sự kiện theo thời gian"), icon: "chart.bar.xaxis", kind: .levelTimeline),
            Panel(title: L("Rule kích hoạt nhiều"), icon: "list.number", kind: .topRules),
            Panel(title: L("Phân bố cấp độ"), icon: "chart.pie.fill", kind: .levelDonut),
            .bars(L("Chiến thuật MITRE"), "target", ["rule.mitre.tactic"], size: 8),
            .feed(L("Sự kiện mới nhất"), "clock.arrow.circlepath"),
        ])
    }

    static var catalog: [DeviceConfig] { [fortigate, nas, dc, unifi, proxmox, webserver] }

    // MARK: FortiGate

    static var fortigate: DeviceConfig {
        DeviceConfig(id: "fortigate", title: "FortiGate", address: "10.0.0.1", icon: "flame.fill", color: .neonOrange,
                     filter: "rule.groups:fortigate", kind: .firewall, groups: [
            PanelGroup(title: L("Lưu lượng & phiên"), icon: "arrow.left.arrow.right", panels: [
                Panel(title: L("Chỉ số tường lửa"), icon: "number", kind: .kpis([
                    KPI(title: L("Tổng sự kiện"), icon: "waveform.path.ecg", kind: .total),
                    KPI(title: L("Cho phép"), icon: "checkmark.circle.fill", kind: .query(fgAccept)),
                    KPI(title: L("Chặn"), icon: "hand.raised.fill", kind: .query(fgDeny), alert: true),
                    KPI(title: L("IP nguồn"), icon: "person.2.fill", kind: .cardinality("data.srcip")),
                    KPI(title: L("IP đích"), icon: "scope", kind: .cardinality("data.dstip")),
                    KPI(title: L("Đã gửi"), icon: "arrow.up.circle.fill", kind: .sum([sent]), unit: .bytes),
                    KPI(title: L("Đã nhận"), icon: "arrow.down.circle.fill", kind: .sum([rcvd]), unit: .bytes),
                    KPI(title: "IPS / UTM", icon: "shield.lefthalf.filled", kind: .query("data.type:utm OR data.subtype:(ips OR virus OR webfilter OR app-ctrl OR dns OR anomaly)"), alert: true),
                    KPI(title: "VPN", icon: "lock.shield.fill", kind: .query("data.subtype:vpn OR data.action:(tunnel-up OR tunnel-down OR tunnel-stats OR ssl-login-fail)")),
                    KPI(title: L("Đăng nhập admin"), icon: "person.badge.key.fill", kind: .query("data.subtype:system AND data.action:(login OR logout)")),
                ])),
                Panel(title: L("So sánh theo thời gian"), icon: "arrow.left.and.right.righttriangle.left.righttriangle.right.fill", kind: .compare),
                Panel(title: L("Sự kiện: cho phép / chặn"), icon: "chart.bar.fill", kind: .filterBars([[L("Cho phép"), fgAccept], [L("Chặn"), fgDeny]])),
            ]),
            PanelGroup(title: L("Băng thông"), icon: "speedometer", panels: [
                Panel(title: L("Băng thông theo thời gian"), icon: "chart.xyaxis.line", kind: .series(metric: .sum([sent, rcvd]), unit: .bytes, split: nil)),
                Panel(title: L("Băng thông theo interface"), icon: "point.3.connected.trianglepath.dotted", kind: .series(metric: .sum([sent, rcvd]), unit: .bytes, split: ["data.srcintf"])),
                .bars(L("Interface nguồn"), "arrow.up.right", ["data.srcintf"], size: 10, metric: .sum([sent, rcvd]), unit: .bytes),
                .bars(L("Interface đích"), "arrow.down.right", ["data.dstintf"], size: 10, metric: .sum([sent, rcvd]), unit: .bytes),
                .bars(L("Top talkers (IP nguồn)"), "person.wave.2.fill", ["data.srcip"], size: 10, metric: .sum([sent, rcvd]), unit: .bytes),
                .bars(L("Top đích (IP)"), "scope", ["data.dstip"], size: 10, metric: .sum([sent, rcvd]), unit: .bytes),
                .bars(L("Top đích (hostname)"), "globe", ["data.hostname"], size: 10),
            ]),
            PanelGroup(title: L("Ứng dụng & chính sách"), icon: "app.connected.to.app.below.fill", panels: [
                .bars(L("Top 20 ứng dụng"), "app.badge.fill", ["data.app"], size: 20),
                .donut(L("Nhóm ứng dụng"), "square.grid.3x3.fill", ["data.appcat"]),
                .bars(L("Vùng (zone)"), "square.split.2x2.fill", ["data.srcintfrole", "data.srczone", "data.srcintf"], size: 8),
                .bars(L("Nguồn bị chặn nhiều"), "hand.raised.fill", ["data.srcip"], size: 10, filter: fgDeny),
                .bars(L("Chính sách"), "list.bullet.rectangle.fill", ["data.policyname", "data.policyid"], size: 10),
                .bars(L("Dịch vụ"), "network", ["data.service"], size: 10),
                .bars(L("Cổng đích"), "number", ["data.dstport"], size: 10),
                .donut(L("Hướng lưu lượng"), "arrow.triangle.swap", ["data.direction", "data.dir", "data.srcintfrole"]),
                .bars(L("Đích VPN"), "lock.shield.fill", ["data.remip", "data.tunnelip", "data.dstip"], size: 10, filter: "data.subtype:vpn"),
            ]),
            PanelGroup(title: L("Địa lý & thời gian"), icon: "globe.asia.australia.fill", panels: [
                .bars(L("Quốc gia nguồn"), "flag.fill", ["data.srccountry", "GeoLocation.country_name"], size: 12),
                Panel(title: L("Bản đồ nguồn truy cập"), icon: "map.fill", kind: .geo(field: "GeoLocation.location")),
                Panel(title: L("Bản đồ nhiệt giờ × ngày"), icon: "square.grid.4x3.fill", kind: .heatHourDay),
            ]),
        ])
    }

    // MARK: NAS

    static var nas: DeviceConfig {
        let file = "data.category:(*ile* OR SMB OR AFP OR FTP OR WebDAV OR Drive OR NFS) OR rule.groups:(file OR fileaccess)"
        return DeviceConfig(id: "nas", title: "NAS DS920+", address: "10.0.0.20", icon: "externaldrive.fill.badge.wifi", color: .neonPurple,
                            filter: "rule.groups:synology", kind: .nas, groups: [
            PanelGroup(title: L("Hoạt động NAS"), icon: "externaldrive.fill", panels: [
                .donut(L("Hoạt động theo loại"), "chart.pie.fill", ["data.category", "data.type", "data.program"]),
                Panel(title: L("Người dùng × giờ"), icon: "square.grid.4x3.fill", kind: .heatHour(fields: ["data.user", "data.dstuser", "data.srcuser"])),
                .bars(L("Truy cập tệp theo IP nguồn"), "doc.on.doc.fill", ["data.srcip", "data.ip", "data.client_ip"], size: 10, filter: file),
                .bars(L("Người dùng hoạt động nhiều"), "person.3.fill", ["data.user", "data.dstuser", "data.srcuser"], size: 10),
                Panel(title: L("Đăng nhập"), icon: "person.badge.key.fill", kind: .filterBars([[L("Thành công"), authOK], [L("Thất bại"), authFail]])),
                .feed(L("Sự kiện hệ thống & lưu trữ"), "internaldrive.fill",
                      filter: "data.category:(System OR Storage OR Disk OR Volume OR Backup OR \"Hyper Backup\") OR rule.groups:(storage OR disk OR raid)"),
            ]),
        ])
    }

    // MARK: UniFi

    static var unifi: DeviceConfig {
        DeviceConfig(id: "unifi", title: "UniFi AP", address: "10.0.0.30", icon: "wifi.router.fill", color: .neonCyan,
                     filter: "rule.groups:unifi", kind: .wifi, groups: [
            PanelGroup(title: L("Client Wi-Fi"), icon: "wifi", panels: [
                Panel(title: L("Kết nối / ngắt kết nối"), icon: "arrow.left.arrow.right", kind: .filterBars([
                    [L("Kết nối"), "full_log:(*associated* OR *connected* OR *assoc*) AND NOT full_log:(*disassociated* OR *disconnected* OR *disassoc*)"],
                    [L("Ngắt kết nối"), "full_log:(*disassociated* OR *disconnected* OR *disassoc* OR *deauth*)"],
                ])),
                .bars(L("Client (MAC)"), "iphone.radiowaves.left.and.right", ["data.srcmac", "data.mac", "data.client_mac"], size: 12),
                Panel(title: L("Client × giờ"), icon: "square.grid.4x3.fill", kind: .heatHour(fields: ["data.srcmac", "data.mac"])),
            ]),
            PanelGroup(title: L("Access point"), icon: "wifi.router", panels: [
                .bars(L("Model AP"), "wifi.router.fill", ["data.ap_model"], size: 6),
                .bars(L("MAC AP"), "barcode", ["data.ap_mac"], size: 6),
                Panel(title: L("Radio / VAP theo thời gian"), icon: "chart.xyaxis.line", kind: .series(metric: .count, unit: .count, split: ["data.vap", "data.radio"])),
                .bars(L("Tiến trình AP"), "gearshape.2.fill", ["data.ap_process", "data.program_name", "predecoder.program_name"], size: 10),
                .bars("RADIUS", "person.badge.shield.checkmark.fill", ["data.radius_type"], size: 8),
            ]),
        ])
    }

    // MARK: Agents

    private static func agentGroups(_ name: String) -> [PanelGroup] {
        [
            PanelGroup(title: L("Lỗ hổng (CVE)"), icon: "ladybug.fill", panels: [Panel(title: L("Lỗ hổng của agent"), icon: "ladybug.fill", kind: .cve)]),
            PanelGroup(title: L("Bảo mật"), icon: "lock.shield.fill", panels: [
                Panel(title: L("Xác thực"), icon: "person.badge.key.fill", kind: .filterBars([
                    [L("Thành công"), authOK], [L("Thất bại"), authFail],
                    [L("Sudo / leo quyền"), "rule.groups:(sudo OR su OR privilege_escalation) OR rule.id:(5401 OR 5402 OR 5403)"],
                ])),
                .bars(L("Tệp thay đổi (FIM)"), "doc.badge.gearshape.fill", ["syscheck.path"], size: 10, filter: "rule.groups:syscheck"),
                .donut(L("Loại thay đổi FIM"), "chart.pie.fill", ["syscheck.event"], filter: "rule.groups:syscheck"),
                Panel(title: L("Đánh giá cấu hình (SCA / CIS)"), icon: "checklist", kind: .sca),
            ]),
            PanelGroup(title: L("Kiểm kê máy chủ"), icon: "cpu", panels: [
                Panel(title: L("Inventory"), icon: "cpu", kind: .inventory),
                .feed(L("Thay đổi gói phần mềm"), "shippingbox.fill",
                      filter: "rule.groups:(dpkg OR yum OR config_changed OR windows_application) OR rule.id:(2902 OR 2903 OR 2904 OR 60602 OR 60609 OR 60612)"),
            ]),
        ]
    }

    static var dc: DeviceConfig {
        DeviceConfig(id: "dc01", title: "DC01", address: "10.0.0.10", icon: "pc", color: .neonCyan,
                     filter: "agent.name:DC01", kind: .agent, agentName: "DC01",
                     groups: agentGroups("DC01") + [
            PanelGroup(title: "Windows", icon: "pc", panels: [
                .bars("Event ID", "number", ["data.win.system.eventID"], size: 15),
                .donut(L("Kiểu đăng nhập"), "person.badge.key.fill", ["data.win.eventdata.logonType"], filter: "data.win.system.eventID:(4624 OR 4625)"),
                Panel(title: L("Tài khoản"), icon: "person.crop.circle.badge.exclamationmark", kind: .kpis([
                    KPI(title: L("Khoá tài khoản"), icon: "lock.fill", kind: .query("data.win.system.eventID:4740"), alert: true),
                    KPI(title: L("Đăng nhập lỗi"), icon: "xmark.shield.fill", kind: .query("data.win.system.eventID:4625"), alert: true),
                    KPI(title: L("Đổi nhóm"), icon: "person.3.fill", kind: .query("data.win.system.eventID:(4728 OR 4729 OR 4732 OR 4733 OR 4756 OR 4757)")),
                    KPI(title: L("Tạo / xoá user"), icon: "person.crop.circle.badge.plus", kind: .query("data.win.system.eventID:(4720 OR 4726)")),
                ])),
                .bars(L("Tài khoản bị khoá"), "lock.fill", ["data.win.eventdata.targetUserName"], size: 10, filter: "data.win.system.eventID:4740"),
                .feed(L("Thay đổi nhóm bảo mật"), "person.3.fill", filter: "data.win.system.eventID:(4728 OR 4729 OR 4732 OR 4733 OR 4756 OR 4757)"),
            ]),
        ])
    }

    static var proxmox: DeviceConfig {
        DeviceConfig(id: "proxmox", title: "Proxmox", address: "10.0.0.11", icon: "server.rack", color: .neonOrange,
                     filter: "agent.name:pve01", kind: .agent, agentName: "pve01",
                     groups: agentGroups("pve01") + [
            PanelGroup(title: "Proxmox", icon: "square.stack.3d.up.fill", panels: [
                .bars(L("VM / CT"), "shippingbox.fill", ["data.vmid"], size: 12),
                .bars(L("Loại tác vụ"), "list.bullet.rectangle.fill", ["data.task_type"], size: 10),
                .donut(L("Trạng thái tác vụ"), "checkmark.circle.fill", ["data.task_state"]),
                .feed(L("Cảnh báo lưu trữ"), "internaldrive.fill", filter: "full_log:(*storage* OR *zfs* OR *disk* OR *lvm* OR *ceph*)"),
            ]),
        ])
    }

    static var webserver: DeviceConfig {
        let access = "data.type:webapp_access"
        let attacks = [
            [L("Scanner"), "rule.id:100435"], ["SQLi", "rule.id:100436"], ["XSS", "rule.id:100437"],
            [L("Traversal"), "rule.id:100438"], ["RCE", "rule.id:100439"], [L("UA scanner"), "rule.id:100440"],
        ]
        return DeviceConfig(id: "webserver", title: "web01", address: "10.0.1.10", icon: "globe", color: .neonGreen,
                            filter: "agent.name:web01", kind: .agent, agentName: "web01",
                            groups: agentGroups("web01") + [
            PanelGroup(title: L("Web (webapp)"), icon: "globe", panels: [
                Panel(title: L("Chỉ số web"), icon: "number", kind: .kpis([
                    KPI(title: L("Request"), icon: "arrow.left.arrow.right", kind: .query(access)),
                    KPI(title: "4xx", icon: "exclamationmark.circle", kind: .query(access + " AND data.http_status:4*"), alert: true),
                    KPI(title: "5xx", icon: "xmark.octagon.fill", kind: .query(access + " AND data.http_status:5*"), alert: true),
                    KPI(title: L("IP truy cập"), icon: "person.2.fill", kind: .cardinality("data.srcip")),
                    KPI(title: L("Dung lượng trả về"), icon: "arrow.down.circle.fill", kind: .sum([NumField(primary: "data.bytes", fallback: "data.size")]), unit: .bytes),
                    KPI(title: L("Tấn công web"), icon: "bolt.shield.fill", kind: .query("rule.id:[100435 TO 100440]"), alert: true),
                    KPI(title: L("Brute force / 4xx flood"), icon: "hammer.fill", kind: .query("rule.id:[100445 TO 100447]"), alert: true),
                    KPI(title: L("Lỗi PM2"), icon: "ant.fill", kind: .query("rule.id:[100400 TO 100413]"), alert: true),
                ])),
                Panel(title: L("Request theo thời gian"), icon: "chart.xyaxis.line", kind: .series(metric: .count, unit: .count, split: nil), filter: access),
                Panel(title: L("Mã trạng thái HTTP"), icon: "number.square.fill", kind: .filterBars([
                    ["2xx", access + " AND data.http_status:2*"], ["3xx", access + " AND data.http_status:3*"],
                    ["4xx", access + " AND data.http_status:4*"], ["5xx", access + " AND data.http_status:5*"],
                ])),
                .bars(L("Đường dẫn nhiều nhất"), "link", ["data.req_path"], size: 12, filter: access),
                .bars(L("IP truy cập nhiều"), "person.2.fill", ["data.srcip"], size: 10, filter: access),
                .bars(L("Quốc gia"), "flag.fill", ["data.srccountry", "GeoLocation.country_name"], size: 10, filter: access),
                Panel(title: L("Request chậm nhất"), icon: "tortoise.fill", kind: .slowest(field: "data.ms", show: ["data.req_path", "data.ms"]), filter: access),
                .bars("User agent", "safari.fill", ["data.ua"], size: 8, filter: access),
            ]),
            PanelGroup(title: L("Tấn công & ứng dụng"), icon: "bolt.shield.fill", panels: [
                Panel(title: L("Tấn công web"), icon: "bolt.shield.fill", kind: .filterBars(attacks)),
                .feed(L("Brute force / 4xx flood"), "hammer.fill", filter: "rule.id:[100445 TO 100447]"),
                .feed(L("PM2: lỗi / khởi động lại"), "ant.fill", filter: "rule.id:[100400 TO 100413]"),
                .feed(L("FIM web-root /var/www/webapp"), "doc.badge.gearshape.fill", filter: "rule.id:[100420 TO 100424]"),
            ]),
        ])
    }
}
