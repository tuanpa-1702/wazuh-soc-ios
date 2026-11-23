import SwiftUI

// MARK: - Bảng màu neon

#if canImport(UIKit)
import UIKit
#endif

extension Color {
    /// Màu tự đổi theo chế độ Sáng / Tối.
    static func adaptive(light: (CGFloat, CGFloat, CGFloat, CGFloat), dark: (CGFloat, CGFloat, CGFloat, CGFloat)) -> Color {
        #if canImport(UIKit)
        return Color(UIColor { t in
            let c = t.userInterfaceStyle == .dark ? dark : light
            return UIColor(red: c.0, green: c.1, blue: c.2, alpha: c.3)
        })
        #else
        return Color(red: dark.0, green: dark.1, blue: dark.2, opacity: dark.3)
        #endif
    }

    static func gray(_ light: CGFloat, _ dark: CGFloat, alpha: CGFloat = 1) -> Color {
        adaptive(light: (light, light, light, alpha), dark: (dark, dark, dark, alpha))
    }

    // Bảng màu dịu: xanh dương chủ đạo, cam, đỏ. Chế độ sáng dùng tông đậm hơn để đủ tương phản.
    static let neonCyan = adaptive(light: (0.18, 0.42, 0.80, 1), dark: (0.42, 0.62, 0.93, 1))    // xanh dương
    static let neonPurple = adaptive(light: (0.33, 0.39, 0.70, 1), dark: (0.52, 0.58, 0.84, 1))  // xanh xám
    static let neonGreen = adaptive(light: (0.18, 0.56, 0.34, 1), dark: (0.45, 0.76, 0.56, 1))   // xanh lá
    static let neonPink = adaptive(light: (0.78, 0.30, 0.32, 1), dark: (0.88, 0.46, 0.46, 1))    // đỏ hồng
    static let neonOrange = adaptive(light: (0.85, 0.46, 0.18, 1), dark: (0.94, 0.62, 0.38, 1))  // cam
    static let neonYellow = adaptive(light: (0.72, 0.53, 0.10, 1), dark: (0.91, 0.74, 0.40, 1))  // hổ phách
    // Màu mức độ theo Wazuh SOC: Critical #C62828, High #E64A19, Medium #F9A825, Low #00897B, OK #2E7D32
    static let sevCritical = Color(red: 0xC6/255, green: 0x28/255, blue: 0x28/255)
    static let sevHigh = Color(red: 0xE6/255, green: 0x4A/255, blue: 0x19/255)
    static let sevMedium = Color(red: 0xF9/255, green: 0xA8/255, blue: 0x25/255)
    static let sevLow = Color(red: 0x00/255, green: 0x89/255, blue: 0x7B/255)
    static let sevOK = Color(red: 0x2E/255, green: 0x7D/255, blue: 0x32/255)
    static let neonRed = adaptive(light: (0.80, 0.24, 0.24, 1), dark: (0.88, 0.38, 0.38, 1))     // đỏ

    static let appBackground = gray(0.95, 0.0)
    static let cardFill = gray(1.0, 0.075)
    static let glassRow = gray(1.0, 0.085)
    static let glassStroke = adaptive(light: (0, 0, 0, 0.08), dark: (1, 1, 1, 0.08))
    static let track = adaptive(light: (0, 0, 0, 0.07), dark: (1, 1, 1, 0.08))
    static let chipFill = gray(1.0, 0.10)
    static let barBackground = gray(0.98, 0.04)
    static let headerBar = adaptive(light: (0.95, 0.95, 0.95, 0.94), dark: (0, 0, 0, 0.92))
    static let codeBackground = gray(0.96, 0.04)
    static let codeText = gray(0.20, 0.82)
    /// Chữ trên nền màu nhấn (nút/chip được chọn).
    static let onAccent = gray(1.0, 0.0)
}

// MARK: - Nền công nghệ

struct GridPattern: Shape {
    var step: CGFloat = 30

    func path(in rect: CGRect) -> Path {
        var p = Path()
        var x: CGFloat = 0
        while x <= rect.width {
            p.move(to: CGPoint(x: x, y: 0))
            p.addLine(to: CGPoint(x: x, y: rect.height))
            x += step
        }
        var y: CGFloat = 0
        while y <= rect.height {
            p.move(to: CGPoint(x: 0, y: y))
            p.addLine(to: CGPoint(x: rect.width, y: y))
            y += step
        }
        return p
    }
}

/// Nền đen phẳng.
struct TechBackground: View {
    var body: some View {
        Color.appBackground.ignoresSafeArea()
    }
}

// MARK: - Thẻ kính mờ

struct GlassCardModifier: ViewModifier {
    var glow: Color?
    var cornerRadius: CGFloat = 18

    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        return content
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(shape.fill(Color.cardFill))
            .background(shape.fill((glow ?? .clear).opacity(0.06)))
            .overlay(shape.strokeBorder(glow.map { $0.opacity(0.32) } ?? Color.glassStroke, lineWidth: 1))
    }
}

extension View {
    func card(glow: Color? = nil) -> some View {
        modifier(GlassCardModifier(glow: glow))
    }

    /// Chữ nhỏ viết hoa, giãn cách — phong cách bảng điều khiển.
    func techLabel() -> some View {
        self.font(.system(size: 11, weight: .semibold, design: .monospaced))
            .textCase(.uppercase)
            .tracking(1.2)
            .foregroundStyle(.secondary)
    }

    /// Giữ API cũ nhưng không còn phát sáng (giao diện dịu, phẳng).
    func neonGlow(_ color: Color, radius: CGFloat = 8) -> some View {
        self
    }
}

// MARK: - Nút kính

struct GlassButtonStyle: ButtonStyle {
    var tint: Color = .neonCyan
    var prominent = false

    func makeBody(configuration: Configuration) -> some View {
        let shape = RoundedRectangle(cornerRadius: 12, style: .continuous)
        return configuration.label
            .font(.callout.weight(.semibold))
            .foregroundStyle(prominent ? Color.onAccent : tint)
            .padding(.vertical, 12)
            .padding(.horizontal, 16)
            .frame(maxWidth: .infinity)
            .background(shape.fill(prominent ? tint : tint.opacity(0.12)))
            .overlay(shape.strokeBorder(tint.opacity(prominent ? 0 : 0.28), lineWidth: 1))
            .opacity(configuration.isPressed ? 0.7 : 1)
            .animation(.easeOut(duration: 0.15), value: configuration.isPressed)
    }
}

// MARK: - List / Form trong suốt trên nền công nghệ

struct GlassList<Content: View>: View {
    private let content: Content
    init(@ViewBuilder content: () -> Content) { self.content = content() }

    var body: some View {
        List {
            Group { content }
                .listRowBackground(Color.glassRow)
                .listRowSeparatorTint(Color.glassStroke)
        }
        .scrollContentBackground(.hidden)
        .background(TechBackground())
    }
}

struct GlassForm<Content: View>: View {
    private let content: Content
    init(@ViewBuilder content: () -> Content) { self.content = content() }

    var body: some View {
        Form {
            Group { content }
                .listRowBackground(Color.glassRow)
                .listRowSeparatorTint(Color.glassStroke)
        }
        .scrollContentBackground(.hidden)
        .background(TechBackground())
    }
}
