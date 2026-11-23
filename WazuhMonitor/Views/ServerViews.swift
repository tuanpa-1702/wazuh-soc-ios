import SwiftUI

struct ServerListView: View {
    @EnvironmentObject private var store: ServerStore
    @Environment(\.dismiss) private var dismiss
    @State private var editing: ServerConfig?
    @State private var adding = false
    @AppStorage(AppLanguage.storageKey) private var lang = AppLanguage.vi.rawValue

    var body: some View {
        GlassList {
            if store.servers.isEmpty {
                Section {
                    VStack(spacing: 12) {
                        Image(systemName: "eye.trianglebadge.exclamationmark.fill")
                            .font(.system(size: 60))
                            .foregroundStyle(LinearGradient(colors: [.neonCyan, .neonPurple], startPoint: .top, endPoint: .bottom))
                            .neonGlow(.neonCyan, radius: 14)
                        Text("WAZUH MONITOR").font(.system(size: 22, weight: .heavy, design: .monospaced)).tracking(2)
                        Text(L("Thêm máy chủ Wazuh để theo dõi cảnh báo bảo mật, agent và lỗ hổng ngay trên iPhone."))
                            .multilineTextAlignment(.center)
                            .foregroundStyle(.secondary)
                        Button {
                            adding = true
                        } label: {
                            Label(L("Thêm máy chủ"), systemImage: "plus").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(GlassButtonStyle(tint: .neonCyan, prominent: true))
                    }
                    .padding(.vertical)
                }
            }
            if !store.servers.isEmpty {
                Section {
                    ForEach(store.servers) { server in
                        Button {
                            store.activeID = server.id
                            dismiss()
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(server.displayName).foregroundStyle(.primary)
                                    Text(server.url).font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if server.id == store.activeID {
                                    Image(systemName: "checkmark.circle.fill").foregroundStyle(Color.neonGreen).neonGlow(.neonGreen, radius: 5)
                                }
                            }
                        }
                        .swipeActions {
                            Button(role: .destructive) { store.delete(server) } label: {
                                Label(L("Xoá"), systemImage: "trash")
                            }
                            Button { editing = server } label: {
                                Label(L("Sửa"), systemImage: "pencil")
                            }
                            .tint(.blue)
                        }
                        .contextMenu {
                            Button { editing = server } label: { Label(L("Sửa"), systemImage: "pencil") }
                            Button(role: .destructive) { store.delete(server) } label: { Label(L("Xoá"), systemImage: "trash") }
                        }
                    }
                } header: {
                    Text(L("Máy chủ"))
                } footer: {
                    Text(L("Chạm để chuyển máy chủ. Vuốt sang trái để sửa hoặc xoá."))
                }
            }
        }
        .navigationTitle(L("Máy chủ"))
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { adding = true } label: { Image(systemName: "plus") }
            }
            ToolbarItem(placement: .navigationBarLeading) {
                Menu {
                    Picker(L("Ngôn ngữ"), selection: $lang) {
                        ForEach(AppLanguage.allCases) { Text($0.title).tag($0.rawValue) }
                    }
                } label: { Image(systemName: "globe") }
            }
        }
        .sheet(isPresented: $adding) {
            NavigationStack { ServerEditView(server: nil) }
        }
        .sheet(item: $editing) { server in
            NavigationStack { ServerEditView(server: server) }
        }
    }
}

struct ServerEditView: View {
    @EnvironmentObject private var store: ServerStore
    @Environment(\.dismiss) private var dismiss

    let original: ServerConfig?
    @State private var name: String
    @State private var url: String
    @State private var username: String
    @State private var password: String = ""
    @State private var indexerURL: String
    @State private var indexerUsername: String
    @State private var indexerPassword: String = ""
    @State private var allowInsecure: Bool
    @State private var cfClientID: String
    @State private var cfSecret: String = ""
    @State private var testing = false
    @State private var results: [(ok: Bool, text: String)] = []

    init(server: ServerConfig?) {
        original = server
        _name = State(initialValue: server?.name ?? "Wazuh")
        _url = State(initialValue: server?.url ?? "https://192.168.1.10:55000")
        _username = State(initialValue: server?.username ?? "wazuh-wui")
        _indexerURL = State(initialValue: server?.indexerURL ?? "https://192.168.1.10:9200")
        _indexerUsername = State(initialValue: server?.indexerUsername ?? "admin")
        _allowInsecure = State(initialValue: server?.allowInsecure ?? true)
        _cfClientID = State(initialValue: server?.cfClientID ?? "")
    }

    private var draft: ServerConfig {
        var s = original ?? ServerConfig(name: "", url: "", username: "")
        s.name = name.trimmed
        s.url = url.trimmed
        s.username = username.trimmed
        s.indexerURL = indexerURL.trimmed
        s.indexerUsername = indexerUsername.trimmed
        s.allowInsecure = allowInsecure
        s.cfClientID = CFToken.clean(cfClientID)
        return s
    }

    var body: some View {
        GlassForm {
            Section {
                TextField(L("Tên hiển thị"), text: $name)
            } header: {
                Text(L("Tên"))
            }
            Section {
                TextField("https://192.168.1.10:55000", text: $url)
                    .urlKeyboard()
                    .plainInput()
                TextField(L("Tên đăng nhập API"), text: $username).plainInput()
                SecureField(L("Mật khẩu API"), text: $password)
            } header: {
                Text("Wazuh server API")
            } footer: {
                Text(L("Cổng mặc định 55000, hoặc địa chỉ tunnel như https://wazuh-api.ten-mien.vn. Tài khoản API mặc định là wazuh-wui hoặc wazuh. Dùng để xem agent, SCA, phần mềm, dịch vụ và khởi động lại."))
            }
            Section {
                TextField("https://192.168.1.10:9200", text: $indexerURL)
                    .urlKeyboard()
                    .plainInput()
                TextField(L("Tên đăng nhập Indexer"), text: $indexerUsername).plainInput()
                SecureField(L("Mật khẩu Indexer"), text: $indexerPassword)
            } header: {
                Text(L("Wazuh Indexer (tuỳ chọn)"))
            } footer: {
                Text(L("Cổng mặc định 9200 (hoặc https://wazuh-idx.ten-mien.vn qua tunnel) — cùng tài khoản đăng nhập Wazuh dashboard (thường là admin). Cần để xem cảnh báo, biểu đồ và lỗ hổng. Để trống nếu không dùng."))
            }
            Section {
                TextField(L("Client ID (….access)"), text: $cfClientID)
                    .plainInput()
                    .font(.system(.footnote, design: .monospaced))
                SecureField("Client Secret", text: $cfSecret)
                if let p = CFToken.idProblem(cfClientID) ?? CFToken.secretProblem(cfSecret, hasID: !CFToken.clean(cfClientID).isEmpty) {
                    Label(p, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(Color.neonOrange)
                } else if !CFToken.clean(cfClientID).isEmpty {
                    Label(Lf("Token đúng định dạng (ID …{0}, secret {1} ký tự)", "\(CFToken.clean(cfClientID).suffix(12))", "\(CFToken.clean(cfSecret).count)"),
                          systemImage: "checkmark.seal.fill")
                        .font(.caption)
                        .foregroundStyle(Color.neonGreen)
                }
            } header: {
                Text(L("Cloudflare Access (tuỳ chọn)"))
            } footer: {
                Text(L("Dùng khi API/Indexer đi qua Cloudflare Tunnel có bật Zero Trust Access. Tạo Service Token trong Zero Trust → Access → Service Auth, rồi thêm policy có Action = SERVICE AUTH (không phải Allow) chứa token này vào CẢ HAI ứng dụng Access (API và Indexer). Dán cả dòng “CF-Access-Client-Id: …” cũng được, app tự lọc. App gửi token qua header CF-Access-Client-Id / CF-Access-Client-Secret cho mọi request."))
            }
            Section {
                Toggle(L("Chấp nhận chứng chỉ tự ký"), isOn: $allowInsecure)
            } footer: {
                Text(L("Wazuh cài mặc định dùng chứng chỉ tự ký — nên để bật trừ khi bạn đã cài chứng chỉ hợp lệ."))
            }
            Section {
                Button {
                    Task { await test() }
                } label: {
                    HStack {
                        Label(L("Kiểm tra kết nối"), systemImage: "bolt.horizontal.circle")
                        if testing { Spacer(); ProgressView() }
                    }
                }
                .disabled(testing || url.trimmed.isEmpty)
                ForEach(Array(results.enumerated()), id: \.offset) { _, r in
                    Label(r.text, systemImage: r.ok ? "checkmark.circle.fill" : "xmark.octagon.fill")
                        .font(.callout)
                        .foregroundStyle(r.ok ? Color.neonGreen : Color.neonRed)
                }
            }
        }
        .navigationTitle(original == nil ? L("Thêm máy chủ") : L("Sửa máy chủ"))
        .inlineTitle()
        .onAppear {
            if let original {
                password = store.password(for: original)
                indexerPassword = store.indexerPassword(for: original)
                cfSecret = store.cfSecret(for: original)
            }
        }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(L("Huỷ")) { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(L("Lưu")) {
                    store.upsert(draft, password: password, indexerPassword: indexerPassword, cfSecret: cfSecret)
                    dismiss()
                }
                .disabled(url.trimmed.isEmpty)
            }
        }
    }

    private func test() async {
        testing = true
        defer { testing = false }
        results = []
        let client = WazuhClient(server: draft, password: password, indexerPassword: indexerPassword, cfSecret: cfSecret)
        do {
            let v = try await client.testAPI()
            results.append((true, Lf("Wazuh API: kết nối thành công — {0}", "\(v)")))
        } catch {
            let msg = errorText(error) ?? L("đã huỷ"); results.append((false, msg.hasPrefix("Wazuh API") ? msg : "Wazuh API: " + msg))
        }
        if client.hasIndexer {
            do {
                let n = try await client.testIndexer()
                results.append((true, Lf("Indexer: kết nối thành công — {0} cảnh báo", "\(n.formatted())")))
            } catch {
                results.append((false, errorText(error) ?? L("Indexer: đã huỷ")))
            }
        }
        if results.allSatisfy({ $0.ok }) { Haptics.success() } else { Haptics.error() }
    }
}
