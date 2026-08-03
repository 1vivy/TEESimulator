# shellcheck disable=SC2034
SKIPUNZIP=1
MIN_SDK=29
CONFIG_DIR=/data/adb/tricky_store

# --- Installation Context Check ---
if [ "$BOOTMODE" != true ]; then
  ui_print "! Please install in Magisk Manager or KernelSU Manager"
  abort "! Install from recovery is NOT supported"
fi

if [ "$KSU" = true ] && [ "$KSU_VER_CODE" -lt 10670 ]; then
  abort "! Please update your KernelSU and KernelSU Manager"
fi

# --- Version Info ---
VERSION=$(grep_prop version "${TMPDIR}/module.prop")
ui_print "- Installing TEESimulator-RS $VERSION"
ui_print ""

# --- Architecture Handling ---
case "$ARCH" in
  arm64) ABI_DIR="arm64-v8a" ;;
  arm)   ABI_DIR="armeabi-v7a" ;;
  x64)   ABI_DIR="x86_64" ;;
  x86)   ABI_DIR="x86" ;;
  *)     abort "! Unsupported architecture: $ARCH" ;;
esac

ui_print "- Device platform: $ARCH"
ui_print "- Using ABI dir: $ABI_DIR"

# --- SDK Check ---
if [ "$API" -lt "$MIN_SDK" ]; then
  abort "! Unsupported SDK: $API. Minimum required is $MIN_SDK"
else
  ui_print "- Device SDK: $API"
fi
ui_print ""

# --- Helpers to install files ---
install_file() {
  if ! unzip -qqjo "$ZIPFILE" "$1" -d "$2"; then
    abort "! Failed to extract $1"
  fi
  ui_print "- Extracted $1"
}

install_module_entry() {
  if ! unzip -qqo "$ZIPFILE" "$1" -d "$MODPATH"; then
    abort "! Failed to extract module entry $1"
  fi
}

# --- Deterministic module installation ---
# Install exactly the files authenticated by the package manifest. This keeps the
# installed tree identical across KernelSU versions that handle META-INF differently.
ARTIFACT_MANIFEST="$TMPDIR/rka-artifacts.sha256"
SOURCE_MANIFEST="$TMPDIR/rka-source.sha256"
unzip -p "$ZIPFILE" META-INF/rka-artifacts.sha256 > "$ARTIFACT_MANIFEST" || \
  abort "! Failed to extract the artifact manifest"
unzip -p "$ZIPFILE" META-INF/rka-source.sha256 > "$SOURCE_MANIFEST" || \
  abort "! Failed to extract the source manifest"
[ -s "$ARTIFACT_MANIFEST" ] || abort "! Empty artifact manifest"
[ -s "$SOURCE_MANIFEST" ] || abort "! Empty source manifest"

ui_print "- Extracting authenticated module files"
artifact_count=0
while IFS= read -r artifact_line || [ -n "$artifact_line" ]; do
  artifact_digest=${artifact_line%%"  "*}
  artifact_path=${artifact_line#*"  "}
  [ "$artifact_digest" != "$artifact_line" ] || abort "! Invalid artifact manifest line"
  case "$artifact_digest" in
    *[!0-9a-f]*|"") abort "! Invalid artifact digest" ;;
  esac
  [ "$(printf %s "$artifact_digest" | wc -c)" -eq 64 ] || \
    abort "! Invalid artifact digest length"
  case "$artifact_path" in
    ""|/*|*/|*//*|*\\*|*[!A-Za-z0-9._/-]*) abort "! Invalid artifact path" ;;
  esac
  artifact_remaining=$artifact_path
  while [ -n "$artifact_remaining" ]; do
    artifact_component=${artifact_remaining%%/*}
    case "$artifact_component" in
      ""|.|..) abort "! Invalid artifact path component" ;;
    esac
    case "$artifact_remaining" in
      */*) artifact_remaining=${artifact_remaining#*/} ;;
      *) artifact_remaining= ;;
    esac
  done
  artifact_count=$((artifact_count + 1))
  [ "$artifact_count" -le 256 ] || abort "! Too many artifact entries"
  install_module_entry "$artifact_path"
done < "$ARTIFACT_MANIFEST"
[ "$artifact_count" -gt 0 ] || abort "! Empty artifact manifest"

if [ -f "$MODPATH/classes.dex" ] && [ ! -e "$MODPATH/service.apk" ]; then
  :
elif [ -f "$MODPATH/service.apk" ] && [ ! -e "$MODPATH/classes.dex" ]; then
  :
else
  abort "! Expected exactly one of service.apk or classes.dex"
fi

(cd "$MODPATH" && sha256sum -c "$ARTIFACT_MANIFEST") >/dev/null || \
  abort "! Installed module manifest verification failed"

mkdir -p "$MODPATH/META-INF" || abort "! Failed to create module metadata"
cp "$ARTIFACT_MANIFEST" "$MODPATH/META-INF/rka-artifacts.sha256" || \
  abort "! Failed to install the artifact manifest"
cp "$SOURCE_MANIFEST" "$MODPATH/META-INF/rka-source.sha256" || \
  abort "! Failed to install the source manifest"
rm -f "$ARTIFACT_MANIFEST" "$SOURCE_MANIFEST"
ui_print ""

# Debug builds carry diag.sh (the diagnostic plane); release builds do not. Extract it when
# present; otherwise sweep any external-storage diagnostics a prior debug install left behind,
# since the release keystore domain has no grant to remove them itself.
# Detect presence by the extracted FILE, not unzip's exit code: the busybox/toybox unzip in
# the install environment exits 0 even when the entry is absent, so the sweep never ran.
unzip -qqjo "$ZIPFILE" "diag.sh" -d "$MODPATH" 2>/dev/null
if [ -f "$MODPATH/diag.sh" ]; then
  chmod 644 "$MODPATH/diag.sh"
  ui_print "- Debug diagnostic plane enabled"
else
  rm -rf /data/media/0/TEESimulator /data/local/tmp/teesim
  ui_print "- Release build: swept stale diagnostics"
fi

# --- Configuration Files ---
if [ ! -d "$CONFIG_DIR" ]; then
  ui_print "- Creating configuration directory"
  mkdir -p "$CONFIG_DIR"
fi

if [ ! -f "$CONFIG_DIR/keybox.xml" ]; then
  ui_print "- Adding AOSP software keybox"
  install_file "keybox.xml" "$CONFIG_DIR"
fi

if [ ! -f "$CONFIG_DIR/target.txt" ]; then
  ui_print "- Adding default target scope"
  install_file "target.txt" "$CONFIG_DIR"
fi

# Some KernelSU releases expand the complete zip before invoking customize.sh.
# Configuration seeds belong in CONFIG_DIR, never in the mounted module tree.
rm -f "$MODPATH/keybox.xml" "$MODPATH/target.txt"

if [ ! -f "$CONFIG_DIR/security_patch.txt" ]; then
  ui_print "- Adding default security patch config (mirror device props)"
  printf '%s\n' \
    '# TEESimulator default: mirror live device props.' \
    '# system=prop reads ro.build.version.security_patch at cert-gen time;' \
    '# boot and vendor are auto-forced to prop too (ConfigurationManager.kt:253-256).' \
    '# Override with explicit YYYY-MM-DD dates if you want active spoofing.' \
    'system=prop' > "$CONFIG_DIR/security_patch.txt"
  chmod 644 "$CONFIG_DIR/security_patch.txt"
fi

rm -f "$CONFIG_DIR/tee_status.txt"

if [ ! -f "$CONFIG_DIR/hbk" ]; then
  ui_print "- Generating device-unique hardware-bound key seed"
  head -c 32 /dev/random > "$CONFIG_DIR/hbk"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644 || abort "! Failed to assign module permissions"

for file in \
    daemon \
    inject \
    rka-agent-pgp-verify \
    rka-control.sh \
    rka-paths.sh \
    rka-sepolicy-probe.sh \
    rka-sidecar \
    rka-supervisor.sh \
    service.sh \
    supervisor \
    uninstall.sh; do
  [ -f "$MODPATH/$file" ] && [ ! -L "$MODPATH/$file" ] || \
    abort "! Invalid module executable"
  set_perm "$MODPATH/$file" 0 0 0755 || abort "! Failed to assign executable permission"
done

set_perm "$MODPATH/META-INF" 0 0 0755 || abort "! Failed to assign metadata permission"
set_perm "$MODPATH/META-INF/rka-artifacts.sha256" 0 0 0644 || \
  abort "! Failed to assign artifact manifest permission"
set_perm "$MODPATH/META-INF/rka-source.sha256" 0 0 0644 || \
  abort "! Failed to assign source manifest permission"
