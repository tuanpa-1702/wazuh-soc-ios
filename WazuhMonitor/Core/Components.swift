import SwiftUI
#if os(iOS)
import UIKit
#endif

enum Haptics {
    static func tap() {
        #if os(iOS)
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
        #endif
    }

    static func success() {
        #if os(iOS)
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        #endif
    }

    static func error() {
        #if os(iOS)
        UINotificationFeedbackGenerator().notificationOccurred(.error)
        #endif
    }
}

/// Ô vuông hiển thị cấp độ rule của cảnh báo.
struct LevelBadge: View {
    let level: Int
    var size: CGFloat = 38

    var body: some View {
        let color = Severity(level: level).color
        Text("\(level)")
            .font(.system(size: size * 0.42, weight: .bold, design: .monospaced))
            .foregroundStyle(color)
            .frame(width: size, height: size)
            .background(color.opacity(0.14), in: RoundedRectangle(cornerRadius: size * 0.28, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: size * 0.28, style: .continuous).strokeBorder(color.opacity(0.6), lineWidth: 1))
    }
}

struct StatusDot: View {
    let color: Color
    var size: CGFloat = 9

    var body: some View {
        Circle().fill(color).frame(width: size, height: size).neonGlow(color, radius: 4)
    }
}

/// Nhãn bo tròn nhỏ (trạng thái, nhóm, MITRE...).
struct Pill: View {
    let text: String
    var color: Color = .neonCyan
    var icon: String?

    var body: some View {
        HStack(spacing: 4) {
            if let icon { Image(systemName: icon).font(.caption2) }
            Text(text).lineLimit(1)
        }
        .font(.caption.weight(.semibold))
        .foregroundStyle(color)
        .padding(.horizontal, 9)
        .padding(.vertical, 4)
        .background(color.opacity(0.13), in: Capsule())
        .overlay(Capsule().strokeBorder(color.opacity(0.4), lineWidth: 0.8))
    }
}

/// Nút lọc dạng chip — vùng chạm lớn, cuộn ngang được.
struct FilterChip: View {
    let title: String
    var count: Int?
    var color: Color = .neonCyan
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button {
            Haptics.tap()
            action()
        } label: {
            HStack(spacing: 6) {
                Text(title)
                if let count {
                    Text(Fmt.compact(count))
                        .font(.caption.monospacedDigit().weight(.bold))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background((selected ? Color.onAccent : color).opacity(0.18), in: Capsule())
                }
            }
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(selected ? Color.onAccent : color)
            .padding(.horizontal, 14)
            .frame(minHeight: 36)
            .background(
                Capsule().fill(selected ? color : Color.chipFill)
            )
            .overlay(Capsule().strokeBorder(color.opacity(selected ? 0 : 0.3), lineWidth: 1))
        }
        .buttonStyle(.plain)
    }
}

struct ChipBar<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) { content }
                .padding(.horizontal, 16)
                .padding(.vertical, 6)
        }
    }
}

/// Một dòng nhãn — giá trị trong thẻ.
struct InfoRow: View {
    let label: String
    let value: String
    var mono = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label).font(.subheadline).foregroundStyle(.secondary)
            Spacer(minLength: 8)
            Text(value.isEmpty ? L("—") : value)
                .font(mono ? .system(.subheadline, design: .monospaced) : .subheadline.weight(.medium))
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
        .padding(.vertical, 3)
    }
}

struct CardHeader: View {
    let title: String
    let icon: String
    var color: Color = .neonCyan

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon).foregroundStyle(color).neonGlow(color, radius: 5)
            Text(title).techLabel()
            Spacer()
        }
    }
}

/// Danh sách "top" với thanh ngang phát sáng.
struct TopBarsCard: View {
    let title: String
    let icon: String
    let items: [Bucket]
    var color: Color = .neonCyan

    var body: some View {
        let maxCount = max(items.map(\.count).max() ?? 1, 1)
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: title, icon: icon, color: color)
            if items.isEmpty {
                Text(L("Chưa có dữ liệu")).font(.footnote).foregroundStyle(.secondary)
            }
            ForEach(items) { item in
                VStack(alignment: .leading, spacing: 5) {
                    HStack(alignment: .firstTextBaseline) {
                        Text(item.key.isEmpty ? L("(trống)") : item.key)
                            .font(.footnote)
                            .lineLimit(2)
                        Spacer(minLength: 8)
                        Text(item.count.formatted())
                            .font(.system(.footnote, design: .monospaced).weight(.semibold))
                            .foregroundStyle(color.opacity(0.9))
                            .layoutPriority(1)
                    }
                    GeometryReader { geo in
                        ZStack(alignment: .leading) {
                            Capsule().fill(Color.track)
                            Capsule()
                                .fill(LinearGradient(colors: [color.opacity(0.5), color], startPoint: .leading, endPoint: .trailing))
                                .frame(width: max(4, geo.size.width * CGFloat(item.count) / CGFloat(maxCount)))
                        }
                    }
                    .frame(height: 5)
                }
            }
        }
        .card()
    }
}

struct EmptyStateCard: View {
    let icon: String
    let title: String
    let message: String
    var color: Color = .neonCyan

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 40))
                .foregroundStyle(color)
                .neonGlow(color, radius: 10)
            Text(title).font(.headline)
            Text(message).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity)
        .card()
    }
}

/// Thanh tiến độ kính.
struct MeterBar: View {
    let value: Double // 0...1
    var color: Color = .neonCyan
    var height: CGFloat = 8

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.track)
                Capsule()
                    .fill(LinearGradient(colors: [color.opacity(0.55), color], startPoint: .leading, endPoint: .trailing))
                    .frame(width: max(height, geo.size.width * min(max(value, 0), 1)))
            }
        }
        .frame(height: height)
    }
}

/// Vòng tròn tỷ lệ.
struct RingGauge: View {
    let value: Double // 0...1
    var color: Color = .neonGreen
    var lineWidth: CGFloat = 10

    var body: some View {
        ZStack {
            Circle().stroke(Color.track, lineWidth: lineWidth)
            Circle()
                .trim(from: 0, to: min(max(value, 0), 1))
                .stroke(AngularGradient(colors: [color.opacity(0.4), color], center: .center),
                        style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
                .rotationEffect(.degrees(-90))
        }
    }
}

/// Đoạn chữ dạng nhật ký, chạm để sao chép.
struct CodeBlock: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(.footnote, design: .monospaced))
            .foregroundStyle(Color.codeText)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(Color.codeBackground, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.glassStroke, lineWidth: 1))
    }
}

/// Bọc nội dung ScrollView lên nền công nghệ.
struct TechScroll<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        ScrollView {
            VStack(spacing: 14) { content }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
                .frame(maxWidth: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(TechBackground())
    }
}
