#!/bin/bash
# Build file WazuhMonitor.ipa (chưa ký) — cần macOS + Xcode 16 trở lên.
# Sau đó ký & cài lên iPhone bằng Sideloadly / AltStore (dùng Apple ID của bạn).
set -euo pipefail
cd "$(dirname "$0")"

if ! xcodebuild -version >/dev/null 2>&1; then
  if [ -d /Applications/Xcode.app ]; then
    echo "❌ Đã có Xcode nhưng chưa được chọn. Chạy lệnh sau (cần mật khẩu máy) rồi chạy lại script:"
    echo "   sudo xcode-select -s /Applications/Xcode.app && sudo xcodebuild -license accept"
  else
    echo "❌ Chưa cài Xcode. Cài 'Xcode' từ App Store (miễn phí, ~15GB), mở Xcode một lần, rồi chạy lại script."
    echo "   Hoặc dùng GitHub Actions (xem README.md) để build mà không cần Xcode."
  fi
  exit 1
fi

# Kiểm tra bảng dịch không có khoá trùng (Swift sẽ crash khi chạy nếu có)
python3 - <<'PY'
import re, collections, sys
s = open("WazuhMonitor/Core/Localization.swift", encoding="utf-8").read()
keys = re.findall(r'^\s*"((?:[^"\\]|\\.)*)": "', s, re.M)
dup = [k for k, c in collections.Counter(keys).items() if c > 1]
if dup:
    sys.exit("❌ Khoá dịch bị trùng: %s" % dup)
PY

rm -rf build WazuhMonitor.ipa
xcodebuild \
  -project WazuhMonitor.xcodeproj \
  -scheme WazuhMonitor \
  -configuration Release \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  -derivedDataPath build \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
  build

mkdir -p build/ipa/Payload
cp -R build/Build/Products/Release-iphoneos/WazuhMonitor.app build/ipa/Payload/
# Bỏ ký hiệu debug (chứa đường dẫn thư mục build trên máy) khỏi file chạy
xcrun strip -S -x build/ipa/Payload/WazuhMonitor.app/WazuhMonitor
(cd build/ipa && zip -qry ../../WazuhMonitor.ipa Payload)
echo "✅ Đã tạo: $(pwd)/WazuhMonitor.ipa"
