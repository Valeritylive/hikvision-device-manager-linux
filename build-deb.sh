#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APPDIR="${APPDIR:-$ROOT_DIR/AppDir}"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/dist}"
PACKAGE_ROOT="$OUTPUT_DIR/deb-root"
PACKAGE_NAME="hikvision-device-manager"
VERSION="1.0.0"

if [[ ! -x "$APPDIR/usr/conda/bin/python" ]]; then
  echo "Не найдено встроенное окружение: сначала выполните bash build-appimage.sh" >&2
  exit 1
fi

rm -rf -- "$PACKAGE_ROOT"
mkdir -p \
  "$PACKAGE_ROOT/DEBIAN" \
  "$PACKAGE_ROOT/opt/hikvision-device-manager" \
  "$PACKAGE_ROOT/usr/bin" \
  "$PACKAGE_ROOT/usr/share/applications" \
  "$PACKAGE_ROOT/usr/share/icons/hicolor/scalable/apps"

cp -a "$APPDIR/usr/conda" "$PACKAGE_ROOT/opt/hikvision-device-manager/conda"
# Conda's package download cache is only needed while building, not at runtime.
rm -rf -- "$PACKAGE_ROOT/opt/hikvision-device-manager/conda/pkgs"
install -m 0644 "$APPDIR/usr/share/hikvision-device-manager/app.py" \
  "$APPDIR/usr/share/hikvision-device-manager/hikvision_api.py" \
  "$APPDIR/usr/share/hikvision-device-manager/hikvision_sdk.py" \
  "$PACKAGE_ROOT/opt/hikvision-device-manager/"
install -m 0644 "$APPDIR/usr/share/icons/hicolor/scalable/apps/hikvision-device-manager.svg" \
  "$PACKAGE_ROOT/usr/share/icons/hicolor/scalable/apps/"

cat > "$PACKAGE_ROOT/usr/bin/hikvision-device-manager" <<'LAUNCHER'
#!/usr/bin/env bash
set -e
PREFIX="/opt/hikvision-device-manager/conda"
APP="/opt/hikvision-device-manager/app.py"
export PATH="$PREFIX/bin:$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export GI_TYPELIB_PATH="$PREFIX/lib/girepository-1.0${GI_TYPELIB_PATH:+:$GI_TYPELIB_PATH}"
export GST_PLUGIN_PATH_1_0="$PREFIX/lib/gstreamer-1.0"
export GST_PLUGIN_SYSTEM_PATH_1_0="$PREFIX/lib/gstreamer-1.0"
export GSETTINGS_SCHEMA_DIR="$PREFIX/share/glib-2.0/schemas"
export GST_REGISTRY_1_0="${XDG_CACHE_HOME:-$HOME/.cache}/hikvision-device-manager-gst.bin"
exec "$PREFIX/bin/python" "$APP" "$@"
LAUNCHER
chmod 0755 "$PACKAGE_ROOT/usr/bin/hikvision-device-manager"

cat > "$PACKAGE_ROOT/usr/share/applications/hikvision-device-manager.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Hikvision Device Manager
Comment=Управление устройствами Hikvision в Linux
Exec=hikvision-device-manager
Icon=hikvision-device-manager
Terminal=false
Categories=Utility;Network;
StartupNotify=true
DESKTOP

cat > "$PACKAGE_ROOT/DEBIAN/control" <<CONTROL
Package: $PACKAGE_NAME
Version: $VERSION-1
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Valeritylive
Depends: libc6 (>= 2.35), libstdc++6
Description: Hikvision device discovery and management for Linux
 GTK 4 application for discovering and configuring Hikvision devices on a local network.
CONTROL

OUTPUT_PACKAGE="$OUTPUT_DIR/${PACKAGE_NAME}_${VERSION}-1_amd64.deb"
dpkg-deb --root-owner-group --build -Zxz --uniform-compression \
  "$PACKAGE_ROOT" "$OUTPUT_PACKAGE"
printf 'Готово: %s\n' "$OUTPUT_PACKAGE"
