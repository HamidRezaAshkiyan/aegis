#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/build-dmg.sh <path-to-aegis-binary> <arch-label> <output-dmg-path>
BIN_PATH="${1:-target/release/aegis}"
ARCH_LABEL="${2:-arm64}"
OUT_DMG="${3:-dist/Aegis-macos-${ARCH_LABEL}.dmg}"
VERSION="${AEGIS_VERSION:-1.0.0}"

if [[ ! -f "$BIN_PATH" ]]; then
  echo "Error: binary not found at $BIN_PATH" >&2
  exit 1
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

APP_DIR="$WORK_DIR/staging/Aegis.app"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

# 1. Copy Rust binary
cp "$BIN_PATH" "$APP_DIR/Contents/MacOS/aegis"
chmod +x "$APP_DIR/Contents/MacOS/aegis"

# 2. Create double-click launcher (starts daemon if not running, opens dashboard)
cat > "$APP_DIR/Contents/MacOS/aegis-launcher" <<'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$HOME/Library/Logs/Aegis"
mkdir -p "$LOG_DIR"

# If Aegis daemon is not already responding, start it in the background
if ! curl -sf http://127.0.0.1:4242/api/status >/dev/null 2>&1; then
  DATA_DIR="$HOME/Library/Application Support/io.aegis.aegis-blocker"
  ARGS=()
  if [[ ! -d "$DATA_DIR/lists" ]]; then
    ARGS+=(--update-lists)
  fi
  nohup "$DIR/aegis" "${ARGS[@]}" >> "$LOG_DIR/aegis.log" 2>&1 &
  # Wait up to 6 seconds for API to come up
  for _ in $(seq 1 30); do
    if curl -sf http://127.0.0.1:4242/api/status >/dev/null 2>&1; then
      break
    fi
    sleep 0.2
  done
fi

open "http://127.0.0.1:4242"
LAUNCHER
chmod +x "$APP_DIR/Contents/MacOS/aegis-launcher"

# 3. Generate Info.plist
cat > "$APP_DIR/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Aegis</string>
    <key>CFBundleDisplayName</key>
    <string>Aegis</string>
    <key>CFBundleIdentifier</key>
    <string>io.aegis.blocker</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleExecutable</key>
    <string>aegis-launcher</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

# 4. Generate a clean shield AppIcon.icns using built-in Python3 + sips + iconutil
ICONSET="$WORK_DIR/AppIcon.iconset"
mkdir -p "$ICONSET"
BASE_PNG="$WORK_DIR/icon_1024.png"

python3 - "$BASE_PNG" <<'PYEOF'
import struct, zlib, sys, math

W, H = 512, 512
rows = []
for y in range(H):
    row = bytearray([0])
    ny = (y - H / 2) / (H / 2)
    for x in range(W):
        nx = (x - W / 2) / (W / 2)
        # Rounded square background (macOS squircle-like)
        r = 0.22
        ax, ay = abs(nx), abs(ny)
        dx = max(ax - (0.86 - r), 0.0)
        dy = max(ay - (0.86 - r), 0.0)
        dist = math.hypot(dx, dy)
        if dist > r:
            row.extend((0, 0, 0, 0))
            continue

        # Smooth blue-cyan gradient background
        t = (nx + ny + 2.0) / 4.0
        bg_r = int(15 + t * 25)
        bg_g = int(42 + t * 88)
        bg_b = int(115 + t * 115)

        # Shield shape in center
        sy = ny + 0.04
        sx = abs(nx)
        in_shield = False
        if -0.52 <= sy <= 0.54:
            if sy < 0.02:
                half_w = 0.44 - 0.04 * ((sy + 0.52) / 0.54)
            else:
                p = (sy - 0.02) / 0.52
                half_w = 0.40 * (1.0 - p * p)
            if sx <= half_w:
                in_shield = True

        if in_shield:
            # Inner dark shield accent for depth
            inner = False
            if -0.38 <= sy <= 0.38:
                if sy < 0.02:
                    ihw = 0.30 - 0.03 * ((sy + 0.38) / 0.40)
                else:
                    ip = (sy - 0.02) / 0.36
                    ihw = 0.27 * (1.0 - ip * ip)
                if sx <= ihw:
                    inner = True
            if inner:
                row.extend((22, 163, 235, 255))
            else:
                row.extend((240, 248, 255, 255))
        else:
            row.extend((bg_r, bg_g, bg_b, 255))
    rows.append(bytes(row))

def chunk(tag, data):
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff)

raw = b"".join(rows)
ihdr = struct.pack(">IIBBBBB", W, H, 8, 6, 0, 0, 0)
png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b"")
with open(sys.argv[1], "wb") as f:
    f.write(png)
PYEOF

for sz in 16 32 128 256 512; do
  sips -z "$sz" "$sz" "$BASE_PNG" --out "$ICONSET/icon_${sz}x${sz}.png" >/dev/null
  dbl=$((sz * 2))
  if [[ "$dbl" -le 512 ]]; then
    sips -z "$dbl" "$dbl" "$BASE_PNG" --out "$ICONSET/icon_${sz}x${sz}@2x.png" >/dev/null
  fi
done
iconutil -c icns "$ICONSET" -o "$APP_DIR/Contents/Resources/AppIcon.icns"

# 5. Ad-hoc sign the app bundle
codesign --force --deep --sign - "$APP_DIR"

# 6. Add Applications symlink for drag-and-drop install
ln -s /Applications "$WORK_DIR/staging/Applications"

# 7. Create compressed .dmg
mkdir -p "$(dirname "$OUT_DMG")"
rm -f "$OUT_DMG"
hdiutil create \
  -volname "Aegis" \
  -srcfolder "$WORK_DIR/staging" \
  -ov \
  -format UDZO \
  "$OUT_DMG"

echo "Created DMG: $OUT_DMG"
ls -lh "$OUT_DMG"
