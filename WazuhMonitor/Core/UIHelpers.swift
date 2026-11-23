import SwiftUI

// MARK: - Khác biệt nền tảng (để mã cũng biên dịch được trên macOS khi kiểm tra)

extension View {
    @ViewBuilder func inlineTitle() -> some View {
        #if os(iOS)
        self.navigationBarTitleDisplayMode(.inline)
        #else
        self
        #endif
    }

    @ViewBuilder func plainInput() -> some View {
        #if os(iOS)
        self.textInputAutocapitalization(.never).autocorrectionDisabled()
        #else
        self.autocorrectionDisabled()
        #endif
    }

    @ViewBuilder func urlKeyboard() -> some View {
        #if os(iOS)
        self.keyboardType(.URL)
        #else
        self
        #endif
    }

    @ViewBuilder func numberKeyboard() -> some View {
        #if os(iOS)
        self.keyboardType(.numberPad)
        #else
        self
        #endif
    }

    /// Hộp thoại hiển thị thông báo khi `message` khác nil.
    func messageAlert(_ title: String, _ message: Binding<String?>) -> some View {
        alert(title, isPresented: Binding(get: { message.wrappedValue != nil },
                                          set: { if !$0 { message.wrappedValue = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(message.wrappedValue ?? "")
        }
    }

    func errorAlert(_ message: Binding<String?>) -> some View {
        messageAlert(L("Có lỗi xảy ra"), message)
    }
}

extension Color {
    static var cardBackground: Color {
        #if os(iOS)
        Color(uiColor: .secondarySystemGroupedBackground)
        #else
        Color(nsColor: .controlBackgroundColor)
        #endif
    }

    static var groupedBackground: Color {
        #if os(iOS)
        Color(uiColor: .systemGroupedBackground)
        #else
        Color(nsColor: .windowBackgroundColor)
        #endif
    }
}

/// Trả về nil nếu là lỗi huỷ tác vụ (không cần báo cho người dùng).
func errorText(_ error: Error) -> String? {
    if error is CancellationError { return nil }
    if let u = error as? URLError, u.code == .cancelled { return nil }
    return error.localizedDescription
}

// MARK: - Định dạng

enum Fmt {
    static func number(_ n: Int?) -> String { (n ?? 0).formatted() }

    static func percent(_ part: Int?, of total: Int?) -> String {
        guard let total, total > 0 else { return "0%" }
        let p = Double(part ?? 0) / Double(total)
        return p.formatted(.percent.precision(.fractionLength(1)))
    }

    static func duration(ms: Int) -> String {
        let total = ms / 1000
        let h = total / 3600, m = (total % 3600) / 60, s = total % 60
        if h > 0 { return Lf("{0} giờ {1} phút", "\(h)", "\(m)") }
        if m > 0 { return Lf("{0} phút {1} giây", "\(m)", "\(s)") }
        return Lf("{0} giây", "\(s)")
    }

    private static let isoParser: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    private static let fallbackParser: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
        return f
    }()

    private static let spaceParser: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f
    }()

    /// Wazuh trả thời gian nhiều kiểu: ...+07:00, ...+0700, ...Z, có/không phần thập phân, hoặc "yyyy-MM-dd HH:mm:ss".
    static func parseDate(_ s: String?) -> Date? {
        guard var s, !s.isEmpty else { return nil }
        if let dot = s.firstIndex(of: ".") {
            var end = s.index(after: dot)
            while end < s.endIndex, s[end].isNumber { end = s.index(after: end) }
            s.removeSubrange(dot..<end)
        }
        return isoParser.date(from: s) ?? fallbackParser.date(from: s) ?? spaceParser.date(from: s)
    }

    static func time(_ s: String?) -> String {
        guard let d = parseDate(s) else { return s ?? "" }
        if Calendar.current.isDateInToday(d) {
            return d.formatted(date: .omitted, time: .standard)
        }
        return d.formatted(.dateTime.day().month().hour().minute().second())
    }

    private static var relative: RelativeDateTimeFormatter {
        let f = RelativeDateTimeFormatter()
        f.locale = AppLanguage.current.locale
        f.unitsStyle = .short
        return f
    }

    static func ago(_ s: String?) -> String {
        guard let d = parseDate(s) else { return (s?.isEmpty ?? true) ? L("—") : s! }
        if abs(d.timeIntervalSinceNow) < 45 { return L("vừa xong") }
        return relative.localizedString(for: d, relativeTo: Date())
    }

    /// 12.3K, 4.5M — gọn cho màn hình nhỏ.
    static func compact(_ n: Int) -> String {
        n.formatted(.number.notation(.compactName).locale(Locale(identifier: "en_US")))
    }

    static func bytes(_ v: Double) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(v), countStyle: .memory)
    }
}

// MARK: - Thành phần dùng chung

struct ErrorCard: View {
    let message: String
    var retry: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(L("Không tải được dữ liệu"), systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(Color.neonOrange)
            Text(message).font(.callout).foregroundStyle(.secondary)
            if let retry {
                Button(L("Thử lại"), action: retry).buttonStyle(GlassButtonStyle(tint: .neonOrange))
            }
        }
        .card()
    }
}

struct LoadingRow: View {
    var body: some View {
        HStack { Spacer(); ProgressView(); Spacer() }
    }
}

/// Ô nhập nhiều dòng (mỗi dòng một giá trị).
struct LinesField: View {
    let title: String
    @Binding var text: String
    var footer: String?
    var minHeight: CGFloat = 110

    var body: some View {
        Section {
            TextEditor(text: $text)
                .font(.system(.footnote, design: .monospaced))
                .frame(minHeight: minHeight)
                .plainInput()
        } header: {
            Text(title)
        } footer: {
            if let footer { Text(footer) }
        }
    }
}
