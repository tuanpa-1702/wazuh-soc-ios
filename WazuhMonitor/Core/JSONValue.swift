import Foundation

/// Kiểu JSON tổng quát, dùng để giữ nguyên các trường không biết trước khi sửa và gửi lại cho máy chủ.
enum JSONValue: Codable, Hashable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .null
        } else if let v = try? c.decode(Bool.self) {
            self = .bool(v)
        } else if let v = try? c.decode(Double.self) {
            self = .number(v)
        } else if let v = try? c.decode(String.self) {
            self = .string(v)
        } else if let v = try? c.decode([JSONValue].self) {
            self = .array(v)
        } else if let v = try? c.decode([String: JSONValue].self) {
            self = .object(v)
        } else {
            throw DecodingError.dataCorruptedError(in: c, debugDescription: L("Kiểu JSON không hỗ trợ"))
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let v): try c.encode(v)
        case .number(let v):
            if v.rounded() == v && abs(v) < 9e15 { try c.encode(Int64(v)) } else { try c.encode(v) }
        case .bool(let v): try c.encode(v)
        case .object(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .null: try c.encodeNil()
        }
    }

    var stringValue: String? { if case .string(let v) = self { return v }; return nil }
    var boolValue: Bool? { if case .bool(let v) = self { return v }; return nil }
    var doubleValue: Double? {
        switch self {
        case .number(let v): return v
        case .string(let s): return Double(s)
        default: return nil
        }
    }
    var intValue: Int? { doubleValue.map { Int($0) } }
    var arrayValue: [JSONValue]? { if case .array(let v) = self { return v }; return nil }
    var objectValue: [String: JSONValue]? { if case .object(let v) = self { return v }; return nil }
    var stringArray: [String] { arrayValue?.compactMap { $0.stringValue } ?? [] }

    subscript(key: String) -> JSONValue? { objectValue?[key] }

    var displayString: String {
        switch self {
        case .string(let v): return v
        case .number(let v): return v.rounded() == v ? String(Int64(v)) : String(v)
        case .bool(let v): return v ? L("Có") : L("Không")
        case .array(let v): return v.map { $0.displayString }.joined(separator: ", ")
        case .object(let v): return v.map { "\($0.key): \($0.value.displayString)" }.sorted().joined(separator: ", ")
        case .null: return ""
        }
    }
}

typealias JSONObject = [String: JSONValue]

extension Array where Element == String {
    var jsonValue: JSONValue { .array(map { .string($0) }) }
}

extension String {
    /// Tách chuỗi nhiều dòng thành mảng, bỏ dòng trống.
    var nonEmptyLines: [String] {
        split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}

// MARK: - Viết truy vấn JSON gọn bằng literal

extension JSONValue: ExpressibleByStringLiteral, ExpressibleByIntegerLiteral, ExpressibleByFloatLiteral,
                     ExpressibleByBooleanLiteral, ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral {
    init(stringLiteral value: String) { self = .string(value) }
    init(integerLiteral value: Int) { self = .number(Double(value)) }
    init(floatLiteral value: Double) { self = .number(value) }
    init(booleanLiteral value: Bool) { self = .bool(value) }
    init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
    init(dictionaryLiteral elements: (String, JSONValue)...) {
        self = .object(Dictionary(elements, uniquingKeysWith: { _, b in b }))
    }
}

extension JSONValue {
    /// Truy cập theo đường dẫn "a.b.c".
    func path(_ p: String) -> JSONValue? {
        var cur: JSONValue? = self
        for k in p.split(separator: ".") { cur = cur?[String(k)] }
        return cur
    }

    func str(_ p: String) -> String { path(p)?.displayString ?? "" }

    /// Làm phẳng thành danh sách (khoá, giá trị) — dùng để hiển thị mọi trường của cảnh báo.
    func flattened(prefix: String = "") -> [(key: String, value: String)] {
        switch self {
        case .object(let o):
            return o.keys.sorted().flatMap { k in
                o[k]!.flattened(prefix: prefix.isEmpty ? k : prefix + "." + k)
            }
        case .array(let a) where a.contains(where: { $0.objectValue != nil }):
            return a.enumerated().flatMap { i, v in v.flattened(prefix: "\(prefix)[\(i)]") }
        default:
            return [(prefix, displayString)]
        }
    }

    var prettyString: String {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let d = try? enc.encode(self) else { return displayString }
        return String(decoding: d, as: UTF8.self)
    }
}
