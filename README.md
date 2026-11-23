# Wazuh SOC v1.0 (build 1)

Ứng dụng iPhone xem toàn bộ dashboard Wazuh: SOC Home, màn hình từng thiết bị, săn cảnh báo, lỗ hổng CVE và quản trị hệ thống.

## Tải về

| File | Kích thước | SHA-256 |
|---|---|---|
| `WazuhMonitor.ipa` | 1.5 MB | `a5e14f80724ae3fceed293017776322a3a392de6ade1597df3a3cfcb6544087e` |

- Bundle ID: `vn.home.wazuhmonitor` · Phiên bản 1.0 (1)
- Yêu cầu: **iOS 17.0 trở lên**, iPhone / iPad
- IPA **chưa ký** — cần tự ký khi cài (xem bên dưới)

### Kiểm tra SHA-256

macOS / Linux:

```bash
shasum -a 256 WazuhMonitor.ipa
```

Windows (PowerShell):

```powershell
Get-FileHash .\WazuhMonitor.ipa -Algorithm SHA256
```

Kết quả phải trùng với mã trong bảng trên (hoặc file `SHA256SUMS.txt`).

## Cài đặt

1. Cài **Sideloadly** (Windows / macOS) hoặc **AltStore**.
2. Cắm iPhone, kéo `WazuhMonitor.ipa` vào Sideloadly, đăng nhập Apple ID, bấm **Start**.
3. Trên iPhone: **Cài đặt → Cài đặt chung → VPN & Quản lý thiết bị** → tin cậy Apple ID của bạn.
4. Bật **Chế độ nhà phát triển** nếu iOS yêu cầu (Cài đặt → Quyền riêng tư & Bảo mật).

Apple ID miễn phí: app hết hạn sau 7 ngày, cài lại để gia hạn (cài đè giữ nguyên cấu hình máy chủ).

## Cấu hình lần đầu

Mở app → **Thêm máy chủ**:

| Trường | Ví dụ |
|---|---|
| Wazuh API | `https://wazuh-api.example.com` hoặc `https://10.0.0.5:55000` |
| Tài khoản API | `wazuh-wui` |
| Wazuh Indexer | `https://wazuh-idx.example.com` hoặc `https://10.0.0.5:9200` |
| Tài khoản Indexer | `admin` |
| Cloudflare Service Token | Client ID + Secret, nếu đặt sau Cloudflare Access (policy **Service Auth**) |

Bấm **Kiểm tra kết nối** để thử riêng API và Indexer. Mật khẩu và Client Secret được lưu trong Keychain.

Các thiết bị trên SOC Home (FortiGate, NAS, UniFi, agent Windows / Proxmox / web) được khai báo trong `Core/DeviceCatalog.swift` với địa chỉ và tên agent **mẫu**. Để khớp hệ thống của bạn, sửa file này và build lại từ mã nguồn (`./build_ipa.sh`).

## Có gì trong bản này

- **Tổng quan**: manager & dịch vụ, agent active / disconnected, cảnh báo theo mức, thẻ từng thiết bị kèm sparkline, CVE, biểu đồ cảnh báo theo mức độ.
- **Thiết bị**: màn hình dựng từ cấu hình; KPI, biểu đồ, top rule, phân bố cấp độ, MITRE, sự kiện mới nhất; FortiGate (băng thông theo interface, ứng dụng, chính sách, bản đồ, bản đồ nhiệt, so sánh theo thời gian), NAS, UniFi, agent (CVE, xác thực, FIM, SCA/CIS, inventory, Windows / Proxmox / web).
- **Cảnh báo**: tìm kiếm, lọc agent / nhóm rule / cấp độ / thời gian, cuộn vô hạn (search_after), chi tiết với `data.*`, GeoIP, JSON gốc, lọc nhanh theo IP / rule.
- **CVE**: theo mức độ, agent, gói, CVSS, năm công bố, hệ điều hành; danh sách Critical & High; lịch sử Active / Solved.
- **Hệ thống**: danh sách agent (cảnh báo phiên bản cũ, khởi động lại), nhật ký & khởi động lại manager, tự làm mới, Tiếng Việt / English, giao diện Sáng / Tối.
- Khoảng thời gian: 15 phút, 1 giờ, 24 giờ, 7 ngày, 30 ngày, tuỳ chọn.

## Ghi chú

- Tên trường log của NAS, UniFi, Proxmox và web app phụ thuộc decoder bạn dùng; panel nào báo "Không có dữ liệu" thì chỉnh tên trường trong `DeviceCatalog.swift`.
- Binary đã bỏ ký hiệu debug; build từ mã nguồn trong repo bằng `./build_ipa.sh` sẽ cho file tương đương.
