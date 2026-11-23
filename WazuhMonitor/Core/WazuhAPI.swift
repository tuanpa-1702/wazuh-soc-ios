import Foundation

enum APIError: LocalizedError {
    case invalidURL
    case unauthorized
    case forbidden(String)
    case http(Int, String)
    case server(String)
    case decoding(String)
    case network(String)
    case noIndexer
    case cloudflare(String)

    var errorDescription: String? {
        switch self {
        case .invalidURL: return L("Địa chỉ máy chủ không hợp lệ.")
        case .unauthorized: return L("Sai tên đăng nhập hoặc mật khẩu (HTTP 401).")
        case .forbidden(let msg): return msg.isEmpty ? L("Tài khoản không có quyền thực hiện thao tác này (HTTP 403).") : Lf("Không có quyền: {0}", "\(msg)")
        case .http(let code, let msg): return msg.isEmpty ? Lf("Máy chủ trả lỗi HTTP {0}.", "\(code)") : "HTTP \(code): \(msg)"
        case .server(let msg): return msg
        case .decoding(let msg): return Lf("Không đọc được dữ liệu từ máy chủ: {0}", "\(msg)")
        case .network(let msg): return Lf("Không kết nối được máy chủ: {0}", "\(msg)")
        case .cloudflare(let msg): return msg
        case .noIndexer: return L("Chưa cấu hình Wazuh Indexer cho máy chủ này. Cần Indexer (cổng 9200) để xem cảnh báo và lỗ hổng.")
        }
    }
}

/// Làm sạch Service Token khi người dùng dán: bỏ tiền tố "CF-Access-Client-Id:", dấu ngoặc, khoảng trắng và ký tự ẩn.
enum CFToken {
    static func clean(_ raw: String) -> String {
        let edge = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "\u{200B}\u{200C}\u{200D}\u{FEFF}"))
        // Bỏ khoảng trắng / ký tự ẩn ở HAI ĐẦU, và tiền tố header nếu dán cả dòng — giữ nguyên mọi ký tự bên trong.
        var s = raw.trimmingCharacters(in: edge)
        for prefix in ["cf-access-client-id:", "cf-access-client-secret:"] {
            if let r = s.range(of: prefix, options: [.caseInsensitive, .anchored]) {
                s = String(s[r.upperBound...])
            }
        }
        return s.trimmingCharacters(in: edge)
    }

    static func idProblem(_ raw: String) -> String? {
        let v = clean(raw)
        if v.isEmpty { return nil }
        return v.hasSuffix(".access") ? nil : L("Client ID thường có dạng xxxxxxxx.access — hãy kiểm tra lại.")
    }

    static func secretProblem(_ raw: String, hasID: Bool) -> String? {
        if hasID && clean(raw).isEmpty { return L("Chưa nhập Client Secret.") }
        return nil
    }
}

/// Delegate của phiên: tuỳ chọn chấp nhận chứng chỉ tự ký và KHÔNG tự đi theo chuyển hướng,
/// để phát hiện khi Cloudflare Access chuyển tới trang đăng nhập.
final class SessionDelegate: NSObject, URLSessionTaskDelegate {
    let allowInsecure: Bool
    init(allowInsecure: Bool) { self.allowInsecure = allowInsecure }

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if allowInsecure,
           challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

/// Tầng HTTP dùng chung cho Wazuh API và Wazuh Indexer.
final class HTTPClient: @unchecked Sendable {
    let baseURL: String
    let label: String
    private let session: URLSession
    private let extraHeaders: [String: String]

    init(url: String, insecure: Bool, extraHeaders: [String: String] = [:], label: String) {
        var base = url.trimmed
        let lower = base.lowercased()
        if !lower.hasPrefix("http://") && !lower.hasPrefix("https://") { base = "https://" + base }
        while base.hasSuffix("/") { base.removeLast() }
        baseURL = base
        self.label = label
        self.extraHeaders = extraHeaders
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.waitsForConnectivity = false
        config.httpCookieAcceptPolicy = .always   // giữ cookie CF_Authorization trong phiên
        session = URLSession(configuration: config, delegate: SessionDelegate(allowInsecure: insecure), delegateQueue: nil)
    }

    func send(_ method: String, _ path: String, query: [URLQueryItem] = [], body: Data? = nil,
              headers: [String: String] = [:]) async throws -> (Data, Int) {
        guard var comps = URLComponents(string: baseURL + path) else { throw APIError.invalidURL }
        if !query.isEmpty {
            comps.queryItems = query
            // URLQueryItem không mã hoá "+", máy chủ sẽ hiểu thành dấu cách (vd. sort=+name → " name").
            comps.percentEncodedQuery = comps.percentEncodedQuery?.replacingOccurrences(of: "+", with: "%2B")
        }
        guard let url = comps.url else { throw APIError.invalidURL }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        for (k, v) in extraHeaders { req.setValue(v, forHTTPHeaderField: k) }
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        if let body {
            req.httpBody = body
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let data: Data
        let http: HTTPURLResponse
        do {
            let (d, response) = try await session.data(for: req)
            guard let h = response as? HTTPURLResponse else { throw APIError.network(L("Phản hồi không hợp lệ")) }
            data = d
            http = h
        } catch let e as APIError {
            throw e
        } catch {
            if (error as? URLError)?.code == .cancelled || error is CancellationError { throw CancellationError() }
            throw APIError.network("\(label): \(error.localizedDescription)")
        }
        if let cf = cloudflareProblem(http, data) { throw APIError.cloudflare("\(label): \(cf)") }
        return (data, http.statusCode)
    }

    /// Giải mã tham số `meta` (JWT) trong URL đăng nhập của Cloudflare Access để biết token có được nhận ra không.
    static func accessMeta(_ location: String) -> JSONValue? {
        guard let comps = URLComponents(string: location),
              let meta = comps.queryItems?.first(where: { $0.name == "meta" })?.value else { return nil }
        let parts = meta.split(separator: ".")
        guard parts.count >= 2 else { return nil }
        var b64 = String(parts[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64 += "=" }
        guard let data = Data(base64Encoded: b64) else { return nil }
        return try? JSONDecoder().decode(JSONValue.self, from: data)
    }

    /// Nhận diện lỗi do Cloudflare Tunnel / Access (không phải từ Wazuh).
    private func cloudflareProblem(_ http: HTTPURLResponse, _ data: Data) -> String? {
        let code = http.statusCode
        let location = http.value(forHTTPHeaderField: "Location") ?? ""
        if (300..<400).contains(code) {
            if location.contains("cloudflareaccess.com") || location.contains("/cdn-cgi/access/") {
                guard let cid = extraHeaders["CF-Access-Client-Id"] else {
                    return L("Cloudflare Access yêu cầu đăng nhập. Hãy nhập Service Token (Client ID + Secret) trong cài đặt máy chủ.")
                }
                let host = URL(string: baseURL)?.host ?? baseURL
                let meta = Self.accessMeta(location)
                let tokenOK = meta?["service_token_status"]?.boolValue
                let aud = meta?.str("aud").prefix(8) ?? ""
                switch tokenOK {
                case true?:
                    return Lf("Token HỢP LỆ nhưng ứng dụng Access của {0} (AUD {1}…) chưa cho qua. Vào Zero Trust → Access → Applications → ứng dụng này → Policies: thêm policy Action = SERVICE AUTH, Include = Service Token …{2} (policy Allow sẽ không dùng được với token), và đặt policy này lên đầu.", "\(host)", "\(aud)", "\(cid.suffix(14))")
                case false?:
                    return Lf("Cloudflare chưa xác thực token cho {0} (service_token_status = false). Hai khả năng: (1) ứng dụng Access này CHƯA có policy Action = Service Auth chứa token …{1} — khi đó Cloudflare bỏ qua token; (2) Client ID và Secret không thuộc cùng một token đang hiệu lực (đã Refresh/xoá/hết hạn).", "\(host)", "\(cid.suffix(14))")
                case nil:
                    return Lf("Cloudflare Access chuyển {0} sang trang đăng nhập dù đã gửi token …{1}. Kiểm tra policy Service Auth của ứng dụng.", "\(host)", "\(cid.suffix(14))")
                }
            }
            return Lf("Máy chủ chuyển hướng tới {0}. Kiểm tra lại địa chỉ (http/https, đường dẫn).", "\(location.isEmpty ? L("địa chỉ khác") : location)")
        }
        let server = (http.value(forHTTPHeaderField: "Server") ?? "").lowercased()
        let isCloudflare = server.contains("cloudflare") || http.value(forHTTPHeaderField: "CF-RAY") != nil
        let isHTML = (http.value(forHTTPHeaderField: "Content-Type") ?? "").contains("text/html")
        guard isCloudflare, isHTML else { return nil }
        switch code {
        case 401, 403:
            return Lf("Cloudflare Access từ chối truy cập (HTTP {0}). Service Token sai, hết hạn, hoặc chưa được thêm vào policy (Service Auth) của ứng dụng này.", "\(code)")
        case 530:
            return L("Tunnel không hoạt động (HTTP 530 / lỗi 1033). Kiểm tra cloudflared đang chạy và hostname đã gắn đúng tunnel.")
        case 502, 504:
            return Lf("cloudflared không tới được Wazuh (HTTP {0}). Kiểm tra Service URL trong tunnel (vd. https://localhost:55000) và bật No TLS Verify vì Wazuh dùng chứng chỉ tự ký.", "\(code)")
        case 520...529:
            return Lf("Cloudflare không nhận được phản hồi hợp lệ từ Wazuh (HTTP {0}).", "\(code)")
        default:
            if code >= 400 {
                let body = String(decoding: data.prefix(2000), as: UTF8.self)
                if body.contains("Attention Required") || body.contains("challenge") {
                    return Lf("Cloudflare chặn bằng WAF/Bot challenge (HTTP {0}). Tạo rule bỏ qua (Skip) cho hostname này hoặc cho request có header CF-Access-Client-Id.", "\(code)")
                }
                return Lf("Cloudflare trả lỗi HTTP {0}.", "\(code)")
            }
            return nil
        }
    }
}

private actor TokenStore {
    private var token: String?
    private var pending: Task<String, Error>?

    func get(_ fetch: @escaping @Sendable () async throws -> String) async throws -> String {
        if let token { return token }
        if let pending { return try await pending.value }
        let task = Task { try await fetch() }
        pending = task
        do {
            let value = try await task.value
            token = value
            pending = nil
            return value
        } catch {
            pending = nil
            throw error
        }
    }

    func invalidate() { token = nil }
}

private func basicAuth(_ user: String, _ pass: String) -> String {
    "Basic " + Data("\(user):\(pass)".utf8).base64EncodedString()
}

private func decodeJSON(_ data: Data) -> JSONValue? {
    try? JSONDecoder().decode(JSONValue.self, from: data)
}

/// Lấy thông báo lỗi dễ đọc từ phản hồi của Wazuh API / OpenSearch.
private func errorMessage(_ json: JSONValue?) -> String {
    guard let json else { return "" }
    if let d = json["detail"]?.stringValue { return d }
    if let t = json["title"]?.stringValue { return t }
    if let r = json.path("error.reason")?.stringValue { return r }
    if let r = json.path("error.root_cause")?.arrayValue?.first?["reason"]?.stringValue { return r }
    if let m = json["message"]?.stringValue { return m }
    return ""
}

/// Client cho Wazuh server API (cổng 55000, JWT) và Wazuh Indexer (cổng 9200, OpenSearch).
final class WazuhClient: @unchecked Sendable {
    private let api: HTTPClient
    private let indexer: HTTPClient?
    private let apiAuth: String
    private let indexerAuth: String
    private let tokens = TokenStore()

    var hasIndexer: Bool { indexer != nil }

    init(server: ServerConfig, password: String, indexerPassword: String, cfSecret: String = "") {
        var cf: [String: String] = [:]
        let cid = CFToken.clean(server.cfClientID)
        if !cid.isEmpty {
            cf["CF-Access-Client-Id"] = cid
            cf["CF-Access-Client-Secret"] = CFToken.clean(cfSecret)
        }
        api = HTTPClient(url: server.url, insecure: server.allowInsecure, extraHeaders: cf, label: "Wazuh API")
        apiAuth = basicAuth(server.username, password)
        let iu = server.indexerURL.trimmed
        indexer = iu.isEmpty ? nil : HTTPClient(url: iu, insecure: server.allowInsecure, extraHeaders: cf, label: "Indexer")
        indexerAuth = basicAuth(server.indexerUsername, indexerPassword)
    }

    // MARK: - Wazuh API

    private func authenticate() async throws -> String {
        var (data, status) = try await api.send("POST", "/security/user/authenticate", headers: ["Authorization": apiAuth])
        if status == 405 {
            (data, status) = try await api.send("GET", "/security/user/authenticate", headers: ["Authorization": apiAuth])
        }
        if status == 401 { throw APIError.unauthorized }
        let json = decodeJSON(data)
        guard (200..<300).contains(status) else { throw APIError.http(status, errorMessage(json)) }
        guard let token = json?.path("data.token")?.stringValue else {
            throw APIError.decoding(L("không thấy token đăng nhập — địa chỉ có đúng là Wazuh API (cổng 55000)?"))
        }
        return token
    }

    /// Gọi Wazuh API, trả về trường `data` của phản hồi. Tự đăng nhập lại khi token hết hạn.
    @discardableResult
    func call(_ method: String, _ path: String, query: [URLQueryItem] = [], body: JSONValue? = nil) async throws -> JSONValue {
        let bodyData = try body.map { try JSONEncoder().encode($0) }
        var retried = false
        while true {
            let token = try await tokens.get { [self] in try await authenticate() }
            let (data, status) = try await api.send(method, path, query: query, body: bodyData,
                                                    headers: ["Authorization": "Bearer \(token)"])
            if status == 401 && !retried {
                await tokens.invalidate()
                retried = true
                continue
            }
            let json = decodeJSON(data)
            if status == 401 { throw APIError.unauthorized }
            if status == 403 { throw APIError.forbidden(errorMessage(json)) }
            guard (200..<300).contains(status) else { throw APIError.http(status, errorMessage(json)) }
            guard let json else { throw APIError.decoding(L("phản hồi không phải JSON")) }
            let payload = json["data"] ?? json
            // error = 1: mọi phần tử đều thất bại.
            if json["error"]?.intValue == 1, (payload["total_affected_items"]?.intValue ?? 0) == 0 {
                let failed = payload["failed_items"]?.arrayValue?.first
                let msg = failed?.path("error.message")?.stringValue ?? json["message"]?.stringValue ?? L("Thao tác thất bại.")
                throw APIError.server(msg)
            }
            return payload
        }
    }

    func testAPI() async throws -> String {
        let info = try await managerInfo()
        return info.str("version")
    }

    func managerInfo() async throws -> JSONValue {
        try await call("GET", "/manager/info").items.first ?? .object([:])
    }

    func managerStatus() async throws -> [Daemon] {
        let item = try await call("GET", "/manager/status").items.first?.objectValue ?? [:]
        return item.map { Daemon(name: $0.key, state: $0.value.displayString) }.sorted { $0.name < $1.name }
    }

    func clusterStatus() async throws -> JSONValue {
        try await call("GET", "/cluster/status")
    }

    func clusterNodes() async throws -> [JSONValue] {
        try await call("GET", "/cluster/nodes").items
    }

    /// Đếm agent theo trạng thái — luôn loại agent 000 (manager), không phụ thuộc phiên bản Wazuh.
    func agentsSummary() async throws -> AgentSummary {
        async let all = agentCount(nil)
        async let active = agentCount("active")
        async let disconnected = agentCount("disconnected")
        async let never = agentCount("never_connected")
        async let pending = agentCount("pending")
        var s = AgentSummary()
        s.total = try await all
        s.active = try await active
        s.disconnected = try await disconnected
        s.neverConnected = try await never
        s.pending = try await pending
        return s
    }

    private func agentCount(_ status: String?) async throws -> Int {
        var q = [URLQueryItem(name: "limit", value: "1"),
                 URLQueryItem(name: "select", value: "id"),
                 URLQueryItem(name: "q", value: "id!=000")]
        if let status { q.append(URLQueryItem(name: "status", value: status)) }
        return try await call("GET", "/agents", query: q)["total_affected_items"]?.intValue ?? 0
    }

    func agents(offset: Int, limit: Int = 50, search: String = "", status: String? = nil) async throws -> (agents: [Agent], total: Int) {
        var q = [URLQueryItem(name: "offset", value: String(offset)),
                 URLQueryItem(name: "limit", value: String(limit)),
                 URLQueryItem(name: "sort", value: "name"),
                 URLQueryItem(name: "q", value: "id!=000")]
        if !search.trimmed.isEmpty { q.append(URLQueryItem(name: "search", value: search.trimmed)) }
        if let status { q.append(URLQueryItem(name: "status", value: status)) }
        let data = try await call("GET", "/agents", query: q)
        return (data.items.map(Agent.init), data["total_affected_items"]?.intValue ?? 0)
    }

    func agent(_ id: String) async throws -> Agent? {
        try await call("GET", "/agents", query: [URLQueryItem(name: "agents_list", value: id)]).items.first.map(Agent.init)
    }

    func restartAgent(_ id: String) async throws {
        try await call("PUT", "/agents/\(id)/restart")
    }

    func deleteAgent(_ id: String) async throws {
        try await call("DELETE", "/agents", query: [URLQueryItem(name: "agents_list", value: id),
                                                     URLQueryItem(name: "status", value: "all"),
                                                     URLQueryItem(name: "older_than", value: "0s")])
    }

    func restartManager() async throws {
        try await call("PUT", "/manager/restart")
    }

    func managerLogs(offset: Int, limit: Int = 100, level: String?, search: String) async throws -> (logs: [LogEntry], total: Int) {
        var q = [URLQueryItem(name: "offset", value: String(offset)),
                 URLQueryItem(name: "limit", value: String(limit)),
                 URLQueryItem(name: "sort", value: "-timestamp")]
        if let level { q.append(URLQueryItem(name: "level", value: level)) }
        if !search.trimmed.isEmpty { q.append(URLQueryItem(name: "search", value: search.trimmed)) }
        let data = try await call("GET", "/manager/logs", query: q)
        return (data.items.map(LogEntry.init), data["total_affected_items"]?.intValue ?? 0)
    }

    func sca(_ agentID: String) async throws -> [SCAPolicy] {
        try await call("GET", "/sca/\(agentID)").items.map(SCAPolicy.init)
    }

    func scaChecks(_ agentID: String, policy: String, result: String?) async throws -> [SCACheck] {
        var q = [URLQueryItem(name: "limit", value: "500")]
        if let result { q.append(URLQueryItem(name: "result", value: result)) }
        return try await call("GET", "/sca/\(agentID)/checks/\(policy)", query: q).items.map(SCACheck.init)
    }

    func syscollector(_ agentID: String, _ kind: String) async throws -> JSONValue? {
        try await call("GET", "/syscollector/\(agentID)/\(kind)").items.first
    }

    func packages(_ agentID: String, offset: Int, search: String) async throws -> (items: [JSONValue], total: Int) {
        var q = [URLQueryItem(name: "offset", value: String(offset)),
                 URLQueryItem(name: "limit", value: "100"),
                 URLQueryItem(name: "sort", value: "name")]
        if !search.trimmed.isEmpty { q.append(URLQueryItem(name: "search", value: search.trimmed)) }
        let data = try await call("GET", "/syscollector/\(agentID)/packages", query: q)
        return (data.items, data["total_affected_items"]?.intValue ?? 0)
    }

    // MARK: - Wazuh Indexer (OpenSearch)

    func search(_ index: String, _ body: JSONValue) async throws -> JSONValue {
        guard let indexer else { throw APIError.noIndexer }
        let (data, status) = try await indexer.send("POST", "/\(index)/_search",
                                                    query: [URLQueryItem(name: "ignore_unavailable", value: "true")],
                                                    body: try JSONEncoder().encode(body),
                                                    headers: ["Authorization": indexerAuth])
        let json = decodeJSON(data)
        if status == 401 { throw APIError.server(L("Indexer: sai tên đăng nhập hoặc mật khẩu (HTTP 401).")) }
        if status == 403 { throw APIError.forbidden(L("Indexer — ") + errorMessage(json)) }
        guard (200..<300).contains(status) else { throw APIError.http(status, "Indexer: " + errorMessage(json)) }
        guard let json else { throw APIError.decoding(L("phản hồi Indexer không phải JSON")) }
        return json
    }

    func testIndexer() async throws -> Int {
        let r = try await search("wazuh-alerts-*", ["size": 0, "track_total_hits": true])
        return r.path("hits.total.value")?.intValue ?? 0
    }

    private func alertFilters(range: TimeRange, minLevel: Int, agentID: String?, extra: [JSONValue] = []) -> [JSONValue] {
        var f: [JSONValue] = [range.rangeClause] + extra
        if minLevel > 0 { f.append(["range": ["rule.level": ["gte": .number(Double(minLevel))]]]) }
        if let agentID { f.append(["term": ["agent.id": .string(agentID)]]) }
        return f
    }

    func alerts(range: TimeRange, minLevel: Int, maxLevel: Int? = nil, search text: String, agentID: String?, from: Int = 0, size: Int = 50,
                extra: [JSONValue] = [], searchAfter: [JSONValue]? = nil) async throws -> (alerts: [WazuhAlert], total: Int) {
        var filters = alertFilters(range: range, minLevel: minLevel, agentID: agentID, extra: extra)
        if let maxLevel { filters.append(["range": ["rule.level": ["lte": .number(Double(maxLevel))]]]) }
        var boolQuery: JSONObject = ["filter": .array(filters)]
        if !text.trimmed.isEmpty {
            boolQuery["must"] = [["query_string": ["query": .string(text.trimmed), "default_operator": "AND", "lenient": true]]]
        }
        var body: JSONObject = [
            "size": .number(Double(size)), "track_total_hits": true,
            "sort": [["timestamp": ["order": "desc"]], ["id": ["order": "desc", "unmapped_type": "keyword"]]],
            "query": ["bool": .object(boolQuery)],
        ]
        // search_after: cuộn vô hạn không giới hạn 10.000 bản ghi như from/size.
        if let searchAfter { body["search_after"] = .array(searchAfter) } else if from > 0 { body["from"] = .number(Double(from)) }
        let r = try await search("wazuh-alerts-*", .object(body))
        let hits = r.path("hits.hits")?.arrayValue ?? []
        return (hits.map(WazuhAlert.init), r.path("hits.total.value")?.intValue ?? hits.count)
    }

    /// Tìm agent theo tên (dùng cho màn hình thiết bị cấu hình theo agent.name).
    func agent(named name: String) async throws -> Agent? {
        try await call("GET", "/agents", query: [URLQueryItem(name: "name", value: name)]).items.first.map(Agent.init)
    }

    /// Toàn bộ agent (phân trang theo offset tới khi đủ).
    func allAgents(status: String? = nil) async throws -> [Agent] {
        var out: [Agent] = []
        var offset = 0
        while true {
            var q = [URLQueryItem(name: "offset", value: String(offset)), URLQueryItem(name: "limit", value: "500"),
                     URLQueryItem(name: "sort", value: "name"), URLQueryItem(name: "q", value: "id!=000")]
            if let status { q.append(URLQueryItem(name: "status", value: status)) }
            let data = try await call("GET", "/agents", query: q)
            let page = data.items.map(Agent.init)
            out += page
            let total = data["total_affected_items"]?.intValue ?? out.count
            offset += page.count
            if page.isEmpty || out.count >= total { break }
        }
        return out
    }

    /// Danh sách phần tử syscollector (ports, processes, netiface…).
    func syscollectorList(_ agentID: String, _ kind: String, limit: Int = 500, query extra: [URLQueryItem] = []) async throws -> [JSONValue] {
        try await call("GET", "/syscollector/\(agentID)/\(kind)", query: [URLQueryItem(name: "limit", value: String(limit))] + extra).items
    }

    func alertStats(range: TimeRange, agentID: String? = nil, extra: [JSONValue] = []) async throws -> AlertStats {
        let terms: (String) -> JSONValue = { field in ["terms": ["field": .string(field), "size": 6]] }
        let body: JSONValue = [
            "size": 0, "track_total_hits": true,
            "query": ["bool": ["filter": .array(alertFilters(range: range, minLevel: 0, agentID: agentID, extra: extra))]],
            "aggs": [
                "levels": ["range": ["field": "rule.level", "ranges": [
                    ["key": "low", "to": 7], ["key": "medium", "from": 7, "to": 12],
                    ["key": "high", "from": 12, "to": 15], ["key": "critical", "from": 15]]]],
                "timeline": ["date_histogram": ["field": "timestamp", "fixed_interval": .string(range.interval), "min_doc_count": 0],
                             "aggs": ["high": ["filter": ["range": ["rule.level": ["gte": 12]]]]]],
                "rules": terms("rule.description"),
                "agents": terms("agent.name"),
                "tactics": terms("rule.mitre.tactic"),
                "auth_fail": ["filter": ["term": ["rule.groups": "authentication_failed"]]],
            ],
        ]
        return AlertStats(try await search("wazuh-alerts-*", body))
    }

    /// Top giá trị của một trường trong cảnh báo (mỗi trường một truy vấn để trường lỗi không làm hỏng cả trang).
    func topValues(_ field: String, range: TimeRange, agentID: String?, extra: [JSONValue], size: Int = 6) async throws -> [Bucket] {
        let body: JSONValue = [
            "size": 0,
            "query": ["bool": ["filter": .array(alertFilters(range: range, minLevel: 0, agentID: agentID, extra: extra))]],
            "aggs": ["top": ["terms": ["field": .string(field), "size": .number(Double(size))]]],
        ]
        let r = try await search("wazuh-alerts-*", body)
        return (r.path("aggregations.top.buckets")?.arrayValue ?? []).map { Bucket(key: $0.str("key"), count: $0["doc_count"]?.intValue ?? 0) }
    }

    /// Đếm số cảnh báo của từng module trong một truy vấn.
    func moduleCounts(_ modules: [WazuhModule], range: TimeRange, agentID: String?) async throws -> [String: Int] {
        var filters: JSONObject = [:]
        for m in modules where m.filter != nil { filters[m.id] = m.filter! }
        let body: JSONValue = [
            "size": 0, "track_total_hits": true,
            "query": ["bool": ["filter": .array(alertFilters(range: range, minLevel: 0, agentID: agentID))]],
            "aggs": ["mods": ["filters": ["filters": .object(filters)]]],
        ]
        let r = try await search("wazuh-alerts-*", body)
        var out: [String: Int] = ["all": r.path("hits.total.value")?.intValue ?? 0]
        for (k, v) in r.path("aggregations.mods.buckets")?.objectValue ?? [:] {
            out[k] = v["doc_count"]?.intValue ?? 0
        }
        return out
    }

    /// Thống kê cảnh báo theo từng thiết bị: thiết bị gửi syslog (theo IP) và từng agent.
    func deviceStats(range: TimeRange) async throws -> [DeviceStat] {
        let sub: JSONValue = [
            "maxlvl": ["max": ["field": "rule.level"]],
            "host": ["terms": ["field": "predecoder.hostname", "size": 1]],
            "dec": ["terms": ["field": "decoder.name", "size": 1]],
            "name": ["terms": ["field": "agent.name", "size": 1]],
            "ip": ["terms": ["field": "agent.ip", "size": 1]],
        ]
        let body: JSONValue = [
            "size": 0,
            "query": ["bool": ["filter": .array(alertFilters(range: range, minLevel: 0, agentID: nil))]],
            "aggs": [
                "syslog": ["filter": WazuhModule.syslogFilter,
                           "aggs": ["dev": ["terms": ["field": "location", "size": 80], "aggs": sub]]],
                "agents": ["filter": ["bool": ["must_not": [["term": ["agent.id": "000"]]]]],
                           "aggs": ["dev": ["terms": ["field": "agent.id", "size": 300], "aggs": sub]]],
            ],
        ]
        let r = try await search("wazuh-alerts-*", body)
        func first(_ b: JSONValue, _ name: String) -> String {
            b.path("\(name).buckets")?.arrayValue?.first?.str("key") ?? ""
        }
        var out: [DeviceStat] = []
        for b in r.path("aggregations.syslog.dev.buckets")?.arrayValue ?? [] {
            let ip = b.str("key")
            out.append(DeviceStat(kind: .syslog, key: ip, autoName: first(b, "host").isEmpty ? ip : first(b, "host"),
                                  address: ip, alerts: b["doc_count"]?.intValue ?? 0,
                                  maxLevel: b.path("maxlvl.value")?.intValue ?? 0, hint: first(b, "dec")))
        }
        for b in r.path("aggregations.agents.dev.buckets")?.arrayValue ?? [] {
            let id = b.str("key")
            out.append(DeviceStat(kind: .agent, key: id, autoName: first(b, "name").isEmpty ? id : first(b, "name"),
                                  address: first(b, "ip"), alerts: b["doc_count"]?.intValue ?? 0,
                                  maxLevel: b.path("maxlvl.value")?.intValue ?? 0, hint: ""))
        }
        return out
    }

    /// Tổng hợp lỗ hổng toàn hệ thống: theo mức độ, CVE, gói, agent.
    func vulnerabilityOverview() async throws -> (severity: [String: Int], cves: [Bucket], packages: [Bucket], agents: [Bucket], total: Int) {
        let body: JSONValue = [
            "size": 0, "track_total_hits": true,
            "aggs": [
                "sev": ["terms": ["field": "vulnerability.severity", "size": 8]],
                "cve": ["terms": ["field": "vulnerability.id", "size": 8]],
                "pkg": ["terms": ["field": "package.name", "size": 8]],
                "agent": ["terms": ["field": "agent.name", "size": 8]],
            ],
        ]
        let r = try await search("wazuh-states-vulnerabilities-*", body)
        func b(_ n: String) -> [Bucket] {
            (r.path("aggregations.\(n).buckets")?.arrayValue ?? []).map { Bucket(key: $0.str("key"), count: $0["doc_count"]?.intValue ?? 0) }
        }
        var sev: [String: Int] = [:]
        for x in b("sev") { sev[x.key] = x.count }
        return (sev, b("cve"), b("pkg"), b("agent"), r.path("hits.total.value")?.intValue ?? 0)
    }

    func vulnerabilitySummary(agentID: String? = nil) async throws -> [String: Int] {
        var body: JSONValue = ["size": 0, "aggs": ["sev": ["terms": ["field": "vulnerability.severity", "size": 8]]]]
        if let agentID, case .object(var o) = body {
            o["query"] = ["term": ["agent.id": .string(agentID)]]
            body = .object(o)
        }
        let r = try await search("wazuh-states-vulnerabilities-*", body)
        var out: [String: Int] = [:]
        for b in r.path("aggregations.sev.buckets")?.arrayValue ?? [] {
            out[b.str("key")] = b["doc_count"]?.intValue ?? 0
        }
        return out
    }

    func vulnerabilities(agentID: String, severity: String?) async throws -> (items: [Vulnerability], total: Int) {
        var filter: [JSONValue] = [["term": ["agent.id": .string(agentID)]]]
        if let severity { filter.append(["term": ["vulnerability.severity": .string(severity)]]) }
        let body: JSONValue = [
            "size": 500, "track_total_hits": true,
            "sort": [["vulnerability.score.base": ["order": "desc", "unmapped_type": "float"]]],
            "query": ["bool": ["filter": .array(filter)]],
        ]
        let r = try await search("wazuh-states-vulnerabilities-*", body)
        let hits = r.path("hits.hits")?.arrayValue ?? []
        return (hits.map(Vulnerability.init), r.path("hits.total.value")?.intValue ?? hits.count)
    }
}

extension JSONValue {
    /// `affected_items` trong phản hồi của Wazuh API.
    var items: [JSONValue] { self["affected_items"]?.arrayValue ?? [] }
}
