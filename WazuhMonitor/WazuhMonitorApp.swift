import SwiftUI

@main
struct WazuhMonitorApp: App {
    @StateObject private var store = ServerStore()
    @AppStorage(AppLanguage.storageKey) private var lang = AppLanguage.vi.rawValue
    @AppStorage(AppAppearance.storageKey) private var appearance = AppAppearance.system.rawValue

    private var scheme: ColorScheme? {
        switch AppAppearance(rawValue: appearance) ?? .system {
        case .system: return nil
        case .light: return .light
        case .dark: return .dark
        }
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .id(lang)   // dựng lại toàn bộ giao diện khi đổi ngôn ngữ
                .environment(\.locale, (AppLanguage(rawValue: lang) ?? .vi).locale)
                .environmentObject(store)
                .preferredColorScheme(scheme)
                .tint(.neonCyan)
        }
    }
}

struct RootView: View {
    @EnvironmentObject private var store: ServerStore

    var body: some View {
        if let client = store.client {
            MainTabView(client: client)
                .id(store.connectionToken)
        } else {
            NavigationStack {
                ServerListView()
            }
        }
    }
}

struct MainTabView: View {
    let client: WazuhClient
    @State private var tab = UserDefaults.standard.integer(forKey: "ui.tab")

    var body: some View {
        TabView(selection: $tab) {
            Group {
                NavigationStack {
                    #if DEBUG
                    if let id = UserDefaults.standard.string(forKey: "ui.device"), let d = DeviceConfig.catalog.first(where: { $0.id == id }) {
                        DeviceScreen(client: client, device: d)
                    } else {
                        DashboardView(client: client)
                    }
                    #else
                    DashboardView(client: client)
                    #endif
                }
                    .tabItem { Label(L("Tổng quan"), systemImage: "square.grid.2x2.fill") }.tag(0)
                NavigationStack { ModulesView(client: client) }
                    .tabItem { Label(L("Thiết bị"), systemImage: "shield.checkered") }.tag(1)
                NavigationStack { AlertsView(client: client) }
                    .tabItem { Label(L("Cảnh báo"), systemImage: "bell.badge.fill") }.tag(2)
                NavigationStack { CVEView(client: client) }
                    .tabItem { Label("CVE", systemImage: "ladybug.fill") }.tag(3)
                NavigationStack { SystemView(client: client) }
                    .tabItem { Label(L("Hệ thống"), systemImage: "server.rack") }.tag(4)
            }
            .toolbarBackground(Color.barBackground, for: .tabBar)
            .toolbarBackground(.visible, for: .tabBar)
        }
    }
}
