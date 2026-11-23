import SwiftUI
import Charts
import MapKit

// MARK: - Thanh chọn khoảng thời gian (15m … 30d + tuỳ chọn)

struct RangeBar: View {
    @Binding var rangeRaw: String
    var color: Color = .neonCyan
    @AppStorage(CustomRange.fromKey) private var fromTS = 0.0
    @AppStorage(CustomRange.toKey) private var toTS = 0.0
    @State private var showCustom = false

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(TimeRange.presets) { r in
                    FilterChip(title: r.short, color: color, selected: r.rawValue == rangeRaw) { rangeRaw = r.rawValue }
                }
                FilterChip(title: rangeRaw == TimeRange.custom.rawValue ? CustomRange.label : L("Tuỳ chọn"), color: color,
                           selected: rangeRaw == TimeRange.custom.rawValue) { showCustom = true }
            }
        }
        .sheet(isPresented: $showCustom) {
            CustomRangeSheet { from, to in
                fromTS = from.timeIntervalSince1970
                toTS = to.timeIntervalSince1970
                rangeRaw = TimeRange.custom.rawValue
            }
            .presentationDetents([.medium])
        }
    }
}

struct CustomRangeSheet: View {
    let onApply: (Date, Date) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var from = CustomRange.from
    @State private var to = CustomRange.to

    var body: some View {
        NavigationStack {
            Form {
                DatePicker(L("Từ"), selection: $from, in: ...Date())
                DatePicker(L("Đến"), selection: $to, in: from...Date())
            }
            .navigationTitle(L("Khoảng thời gian"))
            .inlineTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L("Huỷ")) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L("Áp dụng")) { onApply(from, max(to, from.addingTimeInterval(60))); dismiss() }
                }
            }
        }
    }
}

// MARK: - KPI

struct KPITile: View {
    let title: String
    let icon: String
    let value: String
    var color: Color = .neonCyan
    var lit = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: icon).font(.caption).foregroundStyle(color)
                Text(title).font(.caption).foregroundStyle(.secondary).lineLimit(1).minimumScaleFactor(0.8)
                Spacer(minLength: 0)
            }
            Text(value)
                .font(.system(size: 22, weight: .bold, design: .rounded))
                .foregroundStyle(lit ? color : .primary)
                .lineLimit(1).minimumScaleFactor(0.6)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.track.opacity(0.55), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(lit ? color.opacity(0.5) : .clear, lineWidth: 1))
    }
}

/// Lưới KPI: 2 cột trên iPhone, 3–4 cột trên iPad / màn hình ngang.
struct KPIGrid<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: 10)], spacing: 10) { content }
    }
}

// MARK: - Biểu đồ cảnh báo theo mức độ (xếp chồng)

struct SeverityStackChart: View {
    let points: [SeriesPoint]
    let range: TimeRange
    var height: CGFloat = 190

    var body: some View {
        Chart(points) { p in
            BarMark(x: .value(L("Thời gian"), p.date, unit: range.barUnit), y: .value(L("Số lượng"), p.value))
                .foregroundStyle(by: .value(L("Mức độ"), p.series))
        }
        .chartForegroundStyleScale(domain: Severity.allCases.reversed().map(\.title),
                                   range: Severity.allCases.reversed().map(\.color))
        .socAxes(range: range, unit: .count)
        .chartLegend(position: .bottom, alignment: .leading)
        .frame(height: height)
    }
}

/// Biểu đồ đường theo thời gian (một hoặc nhiều chuỗi).
struct SeriesChart: View {
    let points: [SeriesPoint]
    let range: TimeRange
    let unit: ValueUnit
    var color: Color = .neonCyan

    var body: some View {
        let multi = Set(points.map(\.series)).count > 1
        Chart(points) { p in
            if multi {
                LineMark(x: .value(L("Thời gian"), p.date), y: .value(L("Giá trị"), p.value))
                    .foregroundStyle(by: .value(L("Chuỗi"), p.series))
                    .interpolationMethod(.monotone)
            } else {
                AreaMark(x: .value(L("Thời gian"), p.date), y: .value(L("Giá trị"), p.value))
                    .foregroundStyle(LinearGradient(colors: [color.opacity(0.45), color.opacity(0.03)], startPoint: .top, endPoint: .bottom))
                    .interpolationMethod(.monotone)
                LineMark(x: .value(L("Thời gian"), p.date), y: .value(L("Giá trị"), p.value))
                    .foregroundStyle(color)
                    .interpolationMethod(.monotone)
            }
        }
        .socAxes(range: range, unit: unit)
        .chartLegend(position: .bottom, alignment: .leading)
        .frame(height: 180)
    }
}

extension View {
    func socAxes(range: TimeRange, unit: ValueUnit) -> some View {
        self
            .chartYAxis {
                AxisMarks(position: .leading) { v in
                    AxisGridLine().foregroundStyle(Color.track)
                    AxisValueLabel {
                        if let n = v.as(Double.self) { Text(unit.format(n)).font(.caption2.monospaced()) }
                    }
                }
            }
            .chartXAxis {
                AxisMarks(values: .automatic(desiredCount: 4)) { v in
                    AxisGridLine().foregroundStyle(Color.track)
                    AxisValueLabel {
                        if let d = v.as(Date.self) { Text(socAxisLabel(d, range)).font(.caption2.monospacedDigit()).fixedSize() }
                    }
                }
            }
    }
}

func socAxisLabel(_ d: Date, _ range: TimeRange) -> String {
    let c = Calendar.current.dateComponents([.day, .month, .hour, .minute], from: d)
    if range.span <= 6 * 3600 { return String(format: "%02d:%02d", c.hour ?? 0, c.minute ?? 0) }
    if range.showsTime { return "\(c.hour ?? 0)h" }
    return "\(c.day ?? 0)/\(c.month ?? 0)"
}

// MARK: - Sparkline

struct Sparkline: View {
    let values: [Double]
    var color: Color = .neonCyan

    var body: some View {
        Chart(Array(values.enumerated()), id: \.offset) { i, v in
            AreaMark(x: .value("i", i), y: .value("v", v))
                .foregroundStyle(LinearGradient(colors: [color.opacity(0.4), color.opacity(0.02)], startPoint: .top, endPoint: .bottom))
                .interpolationMethod(.monotone)
            LineMark(x: .value("i", i), y: .value("v", v))
                .foregroundStyle(color)
                .lineStyle(StrokeStyle(lineWidth: 1.5))
                .interpolationMethod(.monotone)
        }
        .chartXAxis(.hidden)
        .chartYAxis(.hidden)
        .chartLegend(.hidden)
    }
}

// MARK: - Donut

struct DonutChart: View {
    let items: [BarItem]
    var colorFor: (BarItem, Int) -> Color
    var onTap: ((BarItem) -> Void)? = nil

    static let palette: [Color] = [.neonCyan, .neonOrange, .neonPurple, .neonGreen, .neonPink, .neonYellow, .neonRed, .gray, .mint, .indigo]

    var body: some View {
        let total = max(items.reduce(0) { $0 + $1.value }, 1)
        HStack(alignment: .center, spacing: 16) {
            Chart(Array(items.enumerated()), id: \.element.key) { i, it in
                SectorMark(angle: .value(L("Số lượng"), it.value), innerRadius: .ratio(0.6), angularInset: 1.2)
                    .foregroundStyle(colorFor(it, i))
                    .cornerRadius(3)
            }
            .chartLegend(.hidden)
            .frame(width: 130, height: 130)
            .overlay {
                VStack(spacing: 0) {
                    Text(Fmt.compact(Int(total))).font(.system(size: 18, weight: .bold, design: .rounded))
                    Text(L("tổng")).font(.caption2).foregroundStyle(.secondary)
                }
            }
            VStack(alignment: .leading, spacing: 6) {
                ForEach(Array(items.prefix(8).enumerated()), id: \.element.key) { i, it in
                    Button { onTap?(it) } label: {
                        HStack(spacing: 6) {
                            Circle().fill(colorFor(it, i)).frame(width: 8, height: 8)
                            Text(it.key.isEmpty ? L("(trống)") : it.key).font(.caption).lineLimit(1)
                            Spacer(minLength: 4)
                            Text(String(format: "%.0f%%", it.value / total * 100))
                                .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }
}

// MARK: - Bản đồ nhiệt

struct HeatmapChart: View {
    let rows: [String]
    let cols: [String]
    let cells: [HeatCell]
    var color: Color = .neonOrange

    var body: some View {
        let maxV = max(cells.map(\.value).max() ?? 1, 1)
        let lookup = Dictionary(cells.map { ($0.x + "|" + $0.y, $0.value) }, uniquingKeysWith: +)
        VStack(alignment: .leading, spacing: 2) {
            ForEach(rows, id: \.self) { r in
                HStack(spacing: 2) {
                    Text(r).font(.system(size: 9).monospaced()).foregroundStyle(.secondary)
                        .frame(width: 64, alignment: .leading).lineLimit(1).truncationMode(.middle)
                    ForEach(cols, id: \.self) { c in
                        let v = lookup[c + "|" + r] ?? 0
                        RoundedRectangle(cornerRadius: 2)
                            .fill(v == 0 ? Color.track.opacity(0.5) : color.opacity(0.15 + 0.85 * v / maxV))
                            .frame(maxWidth: .infinity)
                            .frame(height: 14)
                    }
                }
            }
            HStack(spacing: 2) {
                Spacer().frame(width: 64)
                ForEach(cols.indices, id: \.self) { i in
                    Text(i % 3 == 0 ? cols[i] : "").font(.system(size: 8).monospacedDigit()).foregroundStyle(.tertiary)
                        .frame(maxWidth: .infinity)
                        .fixedSize()
                        .frame(maxWidth: .infinity)
                }
            }
            HStack(spacing: 6) {
                Text(L("Ít")).font(.caption2).foregroundStyle(.secondary)
                LinearGradient(colors: [color.opacity(0.15), color], startPoint: .leading, endPoint: .trailing)
                    .frame(width: 80, height: 6).clipShape(Capsule())
                Text(Lf("Nhiều ({0})", Fmt.compact(Int(maxV)))).font(.caption2).foregroundStyle(.secondary)
            }
            .padding(.top, 4)
        }
    }
}

// MARK: - Bản đồ địa lý

struct GeoMapView: View {
    let points: [GeoPoint]
    var color: Color = .neonOrange

    /// Khung bản đồ vừa đủ chứa mọi điểm.
    private var fitRegion: MKCoordinateRegion {
        guard !points.isEmpty else {
            return MKCoordinateRegion(center: CLLocationCoordinate2D(latitude: 20, longitude: 100),
                                      span: MKCoordinateSpan(latitudeDelta: 100, longitudeDelta: 180))
        }
        let lats = points.map(\.lat), lons = points.map(\.lon)
        let (minLa, maxLa, minLo, maxLo) = (lats.min()!, lats.max()!, lons.min()!, lons.max()!)
        return MKCoordinateRegion(
            center: CLLocationCoordinate2D(latitude: (minLa + maxLa) / 2, longitude: (minLo + maxLo) / 2),
            span: MKCoordinateSpan(latitudeDelta: min(170, max(10, (maxLa - minLa) * 1.4)),
                                   longitudeDelta: min(358, max(10, (maxLo - minLo) * 1.3))))
    }

    var body: some View {
        let maxC = max(points.map(\.count).max() ?? 1, 1)
        Map(initialPosition: .region(fitRegion)) {
            ForEach(points) { p in
                Annotation("", coordinate: CLLocationCoordinate2D(latitude: p.lat, longitude: p.lon)) {
                    Circle()
                        .fill(color.opacity(0.55))
                        .overlay(Circle().strokeBorder(color, lineWidth: 1))
                        .frame(width: 8 + 26 * sqrt(p.count / maxC), height: 8 + 26 * sqrt(p.count / maxC))
                }
            }
        }
        .mapStyle(.standard(elevation: .flat, emphasis: .muted))
        .environment(\.colorScheme, .dark)
        .frame(height: 220)
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

extension TimeRange {
    /// Độ rộng cột của biểu đồ theo khoảng thời gian.
    var barUnit: Calendar.Component {
        if span <= 3 * 3600 { return .minute }
        if span <= 3 * 86400 { return .hour }
        return .day
    }
}
