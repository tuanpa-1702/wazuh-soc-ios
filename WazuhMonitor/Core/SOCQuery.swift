import Foundation

// MARK: - Query builder (OpenSearch)

/// Trường số được lưu dạng keyword trong wazuh-alerts (data.*): cộng bằng script painless.
/// `fallback` chỉ dùng khi log không phải bản ghi tạm (interim, FortiGate logid 0000000020).
struct NumField: Hashable {
    let primary: String
    var fallback: String? = nil
}

enum Metric: Hashable {
    case count
    case sum([NumField])
    case cardinality(String)
}

enum ValueUnit: Hashable {
    case count, bytes, ms

    func format(_ v: Double) -> String {
        switch self {
        case .count: return Fmt.compact(Int(v.rounded()))
        case .bytes: return Fmt.bytes(v)
        case .ms: return v >= 1000 ? String(format: "%.1f s", v / 1000) : "\(Int(v)) ms"
        }
    }
}

enum Q {
    static func qs(_ q: String) -> JSONValue {
        ["query_string": ["query": .string(q), "analyze_wildcard": true, "default_operator": "AND", "lenient": true]]
    }

    static func bool(_ filters: [JSONValue]) -> JSONValue { ["bool": ["filter": .array(filters)]] }

    static func n(_ v: Int) -> JSONValue { .number(Double(v)) }

    static func terms(_ field: String, size: Int, orderBy: String? = nil, aggs: JSONObject? = nil) -> JSONValue {
        var t: JSONObject = ["field": .string(field), "size": n(size)]
        if let orderBy { t["order"] = [orderBy: "desc"] }
        var o: JSONObject = ["terms": .object(t)]
        if let aggs { o["aggs"] = .object(aggs) }
        return .object(o)
    }

    static func dateHistogram(_ range: TimeRange, interval: String? = nil, aggs: JSONObject? = nil) -> JSONValue {
        var h: JSONObject = ["field": "timestamp", "fixed_interval": .string(interval ?? range.interval), "min_doc_count": 0,
                             "time_zone": .string(TimeZone.current.identifier),
                             "extended_bounds": ["min": .string(range.gte), "max": .string(range.lte)]]
        var o: JSONObject = ["date_histogram": .object(h)]
        if let aggs { o["aggs"] = .object(aggs) }
        return .object(o)
    }

    static func filter(_ clause: JSONValue, aggs: JSONObject? = nil) -> JSONValue {
        var o: JSONObject = ["filter": clause]
        if let aggs { o["aggs"] = .object(aggs) }
        return .object(o)
    }

    static func levelGTE(_ lv: Int) -> JSONValue { ["range": ["rule.level": ["gte": n(lv)]]] }

    /// Script painless đọc trường số từ keyword, cộng nhiều trường.
    static func numScript(_ fields: [NumField]) -> JSONValue {
        var src = "double p(def d, String f) { if (!d.containsKey(f) || d[f].size() == 0) { return -1; } "
        src += "try { return Double.parseDouble(d[f].value.toString()); } catch (NumberFormatException e) { return -1; } } "
        src += "boolean interim = doc.containsKey('data.logid') && doc['data.logid'].size() > 0 && doc['data.logid'].value.toString() == '0000000020'; "
        src += "double t = 0; double v; "
        for f in fields {
            src += "v = p(doc, '\(f.primary)'); "
            if let fb = f.fallback { src += "if (v < 0 && !interim) { v = p(doc, '\(fb)'); } " }
            src += "if (v > 0) { t += v; } "
        }
        src += "return t;"
        return ["source": .string(src), "lang": "painless"]
    }

    static func metricAgg(_ m: Metric) -> JSONValue? {
        switch m {
        case .count: return nil
        case .sum(let f): return ["sum": ["script": numScript(f)]]
        case .cardinality(let f): return ["cardinality": ["field": .string(f)]]
        }
    }

    static func metricValue(_ b: JSONValue, _ m: Metric, key: String = "m") -> Double {
        switch m {
        case .count: return b["doc_count"]?.doubleValue ?? 0
        default: return b.path("\(key).value")?.doubleValue ?? 0
        }
    }
}

// MARK: - Panel model

struct KPI: Hashable {
    enum Kind: Hashable {
        case total
        case query(String)
        case levelGTE(Int)
        case cardinality(String)
        case sum([NumField])
    }
    let title: String
    let icon: String
    var kind: Kind
    var unit: ValueUnit = .count
    /// Màu khi > 0 (nil = màu thiết bị).
    var alert: Bool = false
    /// Bộ lọc khi chạm để xem cảnh báo.
    var drill: String? {
        switch kind {
        case .query(let q): return q
        case .levelGTE(let l): return "rule.level:>=\(l)"
        default: return nil
        }
    }
}

enum PanelKind: Hashable {
    case kpis([KPI])
    case levelTimeline
    case topRules
    case levelDonut
    case bars(fields: [String], size: Int, metric: Metric, unit: ValueUnit)
    case donut(fields: [String], size: Int)
    case filterBars([[String]])                // [[nhãn, query]]
    case series(metric: Metric, unit: ValueUnit, split: [String]?)
    case heatHourDay
    case heatHour(fields: [String])
    case compare
    case feed(fields: [String])
    case slowest(field: String, show: [String])
    case geo(field: String)
    // Panel đọc Wazuh API / chỉ mục khác — view tự tải.
    case cve
    case sca
    case inventory
}

struct Panel: Identifiable, Hashable {
    let title: String
    let icon: String
    let kind: PanelKind
    /// Lọc thêm (query_string) chỉ cho panel này.
    var filter: String? = nil
    var id: String { title + "|" + (filter ?? "") }

    static func bars(_ title: String, _ icon: String, _ fields: [String], size: Int = 10, metric: Metric = .count,
                     unit: ValueUnit = .count, filter: String? = nil) -> Panel {
        Panel(title: title, icon: icon, kind: .bars(fields: fields, size: size, metric: metric, unit: unit), filter: filter)
    }
    static func donut(_ title: String, _ icon: String, _ fields: [String], size: Int = 8, filter: String? = nil) -> Panel {
        Panel(title: title, icon: icon, kind: .donut(fields: fields, size: size), filter: filter)
    }
    static func feed(_ title: String, _ icon: String, filter: String? = nil, fields: [String] = []) -> Panel {
        Panel(title: title, icon: icon, kind: .feed(fields: fields), filter: filter)
    }
}

struct PanelGroup: Identifiable, Hashable {
    let title: String
    let icon: String
    let panels: [Panel]
    var collapsed = false
    var id: String { title }
}

// MARK: - Panel data

struct BarItem: Identifiable, Hashable {
    let key: String
    let value: Double
    var level: Int? = nil
    var detail: String? = nil
    /// Query để xem cảnh báo của mục này.
    var drill: String? = nil
    var id: String { key }
}

struct SeriesPoint: Identifiable, Hashable {
    let date: Date
    let series: String
    let value: Double
    var id: String { "\(date.timeIntervalSince1970)|\(series)" }
}

struct HeatCell: Identifiable, Hashable {
    let x: String
    let y: String
    let value: Double
    var id: String { x + "|" + y }
}

struct GeoPoint: Identifiable, Hashable {
    let lat: Double
    let lon: Double
    let count: Double
    var id: String { "\(lat),\(lon)" }
}

struct CompareItem: Identifiable, Hashable {
    let title: String
    let value: Double
    let current: Double
    var id: String { title }
    var change: Double? { value > 0 ? (current - value) / value : nil }
}

enum PanelData {
    case kpis([Double])
    case series([SeriesPoint])
    case bars([BarItem], unit: ValueUnit, field: String?)
    case donut([BarItem], field: String?)
    case heat(rows: [String], cols: [String], cells: [HeatCell])
    case feed([WazuhAlert])
    case compare(current: Double, items: [CompareItem])
    case geo([GeoPoint])
    case none

    var isEmpty: Bool {
        switch self {
        case .kpis(let v): return v.isEmpty
        case .series(let p): return p.allSatisfy { $0.value == 0 }
        case .bars(let b, _, _), .donut(let b, _): return b.isEmpty
        case .heat(_, _, let c): return c.allSatisfy { $0.value == 0 }
        case .feed(let a): return a.isEmpty
        case .compare(let c, let i): return c == 0 && i.allSatisfy { $0.value == 0 }
        case .geo(let g): return g.isEmpty
        case .none: return false
        }
    }
}

// MARK: - Executor

extension WazuhClient {
    /// Bộ lọc gốc: thời gian + bộ lọc thiết bị + bộ lọc panel.
    func socFilters(range: TimeRange?, device: String?, panel: String?) -> [JSONValue] {
        var f: [JSONValue] = []
        if let range { f.append(range.rangeClause) }
        if let device, !device.isEmpty { f.append(Q.qs(device)) }
        if let panel, !panel.isEmpty { f.append(Q.qs(panel)) }
        return f
    }

    private func aggSearch(_ filters: [JSONValue], _ aggs: JSONObject, size: Int = 0) async throws -> JSONValue {
        try await search("wazuh-alerts-*", ["size": Q.n(size), "track_total_hits": true,
                                            "query": Q.bool(filters), "aggs": .object(aggs)])
    }

    func runPanel(_ panel: Panel, deviceFilter: String?, range: TimeRange) async throws -> PanelData {
        let base = socFilters(range: range, device: deviceFilter, panel: panel.filter)
        func drill(_ field: String, _ key: String) -> String {
            let esc = key.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            return "\(field):\"\(esc)\""
        }

        switch panel.kind {
        case .kpis(let kpis):
            var aggs: JSONObject = [:]
            for (i, k) in kpis.enumerated() {
                switch k.kind {
                case .total: break
                case .query(let q): aggs["k\(i)"] = Q.filter(Q.qs(q))
                case .levelGTE(let l): aggs["k\(i)"] = Q.filter(Q.levelGTE(l))
                case .cardinality(let f): aggs["k\(i)"] = ["cardinality": ["field": .string(f)]]
                case .sum(let f): aggs["k\(i)"] = ["sum": ["script": Q.numScript(f)]]
                }
            }
            if aggs.isEmpty { aggs["none"] = ["max": ["field": "rule.level"]] }
            let r = try await aggSearch(base, aggs)
            let total = r.path("hits.total.value")?.doubleValue ?? 0
            let ag = r["aggregations"] ?? .null
            return .kpis(kpis.enumerated().map { i, k in
                switch k.kind {
                case .total: return total
                case .query, .levelGTE: return ag.path("k\(i).doc_count")?.doubleValue ?? 0
                default: return ag.path("k\(i).value")?.doubleValue ?? 0
                }
            })

        case .levelTimeline:
            let r = try await aggSearch(base, ["t": Q.dateHistogram(range, aggs: ["lv": severityRanges])])
            return .series(Self.levelSeries(r.path("aggregations.t.buckets")?.arrayValue ?? []))

        case .topRules:
            let r = try await aggSearch(base, ["r": Q.terms("rule.description", size: 10, aggs: [
                "lv": ["max": ["field": "rule.level"]], "id": Q.terms("rule.id", size: 1),
            ])])
            return .bars((r.path("aggregations.r.buckets")?.arrayValue ?? []).map { b in
                BarItem(key: b.str("key"), value: b["doc_count"]?.doubleValue ?? 0, level: b.path("lv.value")?.intValue,
                        detail: b.path("id.buckets")?.arrayValue?.first.map { "#" + $0.str("key") }, drill: drill("rule.description", b.str("key")))
            }, unit: .count, field: "rule.description")

        case .levelDonut:
            let r = try await aggSearch(base, ["l": Q.terms("rule.level", size: 20)])
            let items = (r.path("aggregations.l.buckets")?.arrayValue ?? []).map { b in
                BarItem(key: b.str("key"), value: b["doc_count"]?.doubleValue ?? 0, level: b["key"]?.intValue, drill: "rule.level:\(b.str("key"))")
            }
            return .donut(items.sorted { ($0.level ?? 0) > ($1.level ?? 0) }, field: "rule.level")

        case .bars(let fields, let size, let metric, let unit):
            for f in fields {
                var sub: JSONObject? = nil
                if let m = Q.metricAgg(metric) { sub = ["m": m] }
                let r = try await aggSearch(base, ["b": Q.terms(f, size: size, orderBy: metric == .count ? nil : "m", aggs: sub)])
                let items = (r.path("aggregations.b.buckets")?.arrayValue ?? []).map { b in
                    BarItem(key: b.str("key"), value: Q.metricValue(b, metric), drill: drill(f, b.str("key")))
                }.filter { $0.value > 0 }
                if !items.isEmpty || f == fields.last { return .bars(items, unit: unit, field: f) }
            }
            return .bars([], unit: unit, field: nil)

        case .donut(let fields, let size):
            for f in fields {
                let r = try await aggSearch(base, ["b": Q.terms(f, size: size)])
                let items = (r.path("aggregations.b.buckets")?.arrayValue ?? []).map { b in
                    BarItem(key: b.str("key"), value: b["doc_count"]?.doubleValue ?? 0, drill: drill(f, b.str("key")))
                }
                if !items.isEmpty || f == fields.last { return .donut(items, field: f) }
            }
            return .donut([], field: nil)

        case .filterBars(let defs):
            var filters: JSONObject = [:]
            for (i, d) in defs.enumerated() where d.count == 2 { filters["f\(i)"] = Q.qs(d[1]) }
            let r = try await aggSearch(base, ["f": ["filters": ["filters": .object(filters)]]])
            return .bars(defs.enumerated().compactMap { i, d in
                guard d.count == 2 else { return nil }
                return BarItem(key: d[0], value: r.path("aggregations.f.buckets.f\(i).doc_count")?.doubleValue ?? 0, drill: d[1])
            }, unit: .count, field: nil)

        case .series(let metric, _, let split):
            var leaf: JSONObject? = nil
            if let m = Q.metricAgg(metric) { leaf = ["m": m] }
            if let split {
                for f in split {
                    let r = try await aggSearch(base, ["s": Q.terms(f, size: 6, aggs: ["t": Q.dateHistogram(range, aggs: leaf)])])
                    var pts: [SeriesPoint] = []
                    for sb in r.path("aggregations.s.buckets")?.arrayValue ?? [] {
                        for b in sb.path("t.buckets")?.arrayValue ?? [] {
                            guard let ms = b["key"]?.doubleValue else { continue }
                            pts.append(SeriesPoint(date: Date(timeIntervalSince1970: ms / 1000), series: sb.str("key"), value: Q.metricValue(b, metric)))
                        }
                    }
                    if !pts.isEmpty || f == split.last { return .series(pts) }
                }
                return .series([])
            }
            let r = try await aggSearch(base, ["t": Q.dateHistogram(range, aggs: leaf)])
            return .series((r.path("aggregations.t.buckets")?.arrayValue ?? []).compactMap { b in
                guard let ms = b["key"]?.doubleValue else { return nil }
                return SeriesPoint(date: Date(timeIntervalSince1970: ms / 1000), series: panel.title, value: Q.metricValue(b, metric))
            })

        case .heatHourDay:
            let r = try await aggSearch(base, ["t": Q.dateHistogram(range, interval: "1h")])
            var cells: [String: Double] = [:]
            let cal = Calendar.current
            for b in r.path("aggregations.t.buckets")?.arrayValue ?? [] {
                guard let ms = b["key"]?.doubleValue else { continue }
                let d = Date(timeIntervalSince1970: ms / 1000)
                let wd = Self.weekdayName(cal.component(.weekday, from: d))
                let h = String(format: "%02d", cal.component(.hour, from: d))
                cells[wd + "|" + h, default: 0] += b["doc_count"]?.doubleValue ?? 0
            }
            let rows = Self.weekdayOrder.map(Self.weekdayName)
            let cols = (0..<24).map { String(format: "%02d", $0) }
            return .heat(rows: rows, cols: cols, cells: cells.map { k, v in
                let p = k.split(separator: "|").map(String.init)
                return HeatCell(x: p[1], y: p[0], value: v)
            })

        case .heatHour(let fields):
            for f in fields {
                let r = try await aggSearch(base, ["s": Q.terms(f, size: 10, aggs: ["t": Q.dateHistogram(range, interval: "1h")])])
                let buckets = r.path("aggregations.s.buckets")?.arrayValue ?? []
                if buckets.isEmpty && f != fields.last { continue }
                var cells: [String: Double] = [:]
                var rows: [String] = []
                for sb in buckets {
                    let row = sb.str("key")
                    rows.append(row)
                    for b in sb.path("t.buckets")?.arrayValue ?? [] {
                        guard let ms = b["key"]?.doubleValue else { continue }
                        let h = String(format: "%02d", Calendar.current.component(.hour, from: Date(timeIntervalSince1970: ms / 1000)))
                        cells[row + "|" + h, default: 0] += b["doc_count"]?.doubleValue ?? 0
                    }
                }
                let cols = (0..<24).map { String(format: "%02d", $0) }
                return .heat(rows: rows, cols: cols, cells: cells.map { k, v in
                    let p = k.split(separator: "|", maxSplits: 1).map(String.init)
                    return HeatCell(x: p.count > 1 ? p[1] : "", y: p[0], value: v)
                })
            }
            return .heat(rows: [], cols: [], cells: [])

        case .compare:
            let noTime = socFilters(range: nil, device: deviceFilter, panel: panel.filter)
            func win(_ from: Int, _ to: Int) -> JSONValue {
                Q.filter(["range": ["timestamp": ["gte": .string("now-\(from)h"), "lt": .string(to == 0 ? "now" : "now-\(to)h")]]])
            }
            let r = try await aggSearch(noTime + [["range": ["timestamp": ["gte": "now-169h"]]]], [
                "cur": win(1, 0), "h1": win(2, 1), "d1": win(25, 24), "d7": win(169, 168),
            ])
            func v(_ k: String) -> Double { r.path("aggregations.\(k).doc_count")?.doubleValue ?? 0 }
            let cur = v("cur")
            return .compare(current: cur, items: [
                CompareItem(title: L("1 giờ trước đó"), value: v("h1"), current: cur),
                CompareItem(title: L("Cùng giờ hôm qua"), value: v("d1"), current: cur),
                CompareItem(title: L("Cùng giờ tuần trước"), value: v("d7"), current: cur),
            ])

        case .feed:
            let r = try await search("wazuh-alerts-*", ["size": 15, "sort": [["timestamp": ["order": "desc"]]], "query": Q.bool(base)])
            return .feed((r.path("hits.hits")?.arrayValue ?? []).map(WazuhAlert.init))

        case .slowest(let field, _):
            let script: JSONValue = ["source": .string("if (!doc.containsKey('\(field)') || doc['\(field)'].size() == 0) { return 0; } try { return Double.parseDouble(doc['\(field)'].value.toString()); } catch (NumberFormatException e) { return 0; }"), "lang": "painless"]
            let r = try await search("wazuh-alerts-*", ["size": 10, "query": Q.bool(base + [["exists": ["field": .string(field)]]]),
                                                        "sort": [["_script": ["type": "number", "order": "desc", "script": script]]]])
            return .feed((r.path("hits.hits")?.arrayValue ?? []).map(WazuhAlert.init))

        case .geo(let field):
            let r = try await aggSearch(base, ["g": ["geotile_grid": ["field": .string(field), "precision": 4, "size": 300],
                                                     "aggs": ["c": ["geo_centroid": ["field": .string(field)]]]]])
            return .geo((r.path("aggregations.g.buckets")?.arrayValue ?? []).compactMap { b in
                guard let lat = b.path("c.location.lat")?.doubleValue, let lon = b.path("c.location.lon")?.doubleValue else { return nil }
                return GeoPoint(lat: lat, lon: lon, count: b["doc_count"]?.doubleValue ?? 0)
            })

        case .cve, .sca, .inventory:
            return .none
        }
    }

    var severityRanges: JSONValue {
        ["range": ["field": "rule.level", "ranges": [
            ["key": "low", "to": 7], ["key": "medium", "from": 7, "to": 12],
            ["key": "high", "from": 12, "to": 15], ["key": "critical", "from": 15]]]]
    }

    static func levelSeries(_ buckets: [JSONValue]) -> [SeriesPoint] {
        var out: [SeriesPoint] = []
        for b in buckets {
            guard let ms = b["key"]?.doubleValue else { continue }
            let d = Date(timeIntervalSince1970: ms / 1000)
            for lb in b.path("lv.buckets")?.arrayValue ?? [] {
                guard let s = Severity(rawValue: lb.str("key")) else { continue }
                out.append(SeriesPoint(date: d, series: s.title, value: lb["doc_count"]?.doubleValue ?? 0))
            }
        }
        return out
    }

    /// Thứ hai → chủ nhật.
    static let weekdayOrder = [2, 3, 4, 5, 6, 7, 1]
    static func weekdayName(_ wd: Int) -> String {
        let vi = ["CN", "T2", "T3", "T4", "T5", "T6", "T7"]
        let en = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
        let i = max(0, min(6, wd - 1))
        return AppLanguage.current == .en ? en[i] : vi[i]
    }

    // MARK: Overview

    struct DeviceSummary {
        var events = 0, medium = 0, high = 0
        var spark: [Double] = []
    }

    /// Số sự kiện / ≥7 / ≥12 và sparkline cho từng thiết bị, một truy vấn.
    func deviceSummaries(_ devices: [DeviceConfig], range: TimeRange) async throws -> [String: DeviceSummary] {
        var aggs: JSONObject = [:]
        for d in devices {
            aggs[d.id] = Q.filter(Q.qs(d.filter), aggs: [
                "a7": Q.filter(Q.levelGTE(7)), "a12": Q.filter(Q.levelGTE(12)), "t": Q.dateHistogram(range),
            ])
        }
        let r = try await aggSearch([range.rangeClause], aggs)
        var out: [String: DeviceSummary] = [:]
        for d in devices {
            let b = r.path("aggregations.\(d.id)") ?? .null
            out[d.id] = DeviceSummary(events: b["doc_count"]?.intValue ?? 0, medium: b.path("a7.doc_count")?.intValue ?? 0,
                                      high: b.path("a12.doc_count")?.intValue ?? 0,
                                      spark: (b.path("t.buckets")?.arrayValue ?? []).map { $0["doc_count"]?.doubleValue ?? 0 })
        }
        return out
    }

    func severityTimeline(range: TimeRange) async throws -> [SeriesPoint] {
        let r = try await aggSearch([range.rangeClause], ["t": Q.dateHistogram(range, aggs: ["lv": severityRanges])])
        return Self.levelSeries(r.path("aggregations.t.buckets")?.arrayValue ?? [])
    }
}
