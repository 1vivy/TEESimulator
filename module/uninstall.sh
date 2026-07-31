#!/system/bin/sh
MODDIR=${0%/*}
CONFIG_DIR=/data/adb/tricky_store

"$MODDIR/rka-supervisor.sh" stop

rm -rf "$CONFIG_DIR/persistent_keys"
rm -f "$CONFIG_DIR/tee_status.txt"
rm -f "$CONFIG_DIR/boot_hash.bin" "$CONFIG_DIR/boot_key.bin"
rm -f "$CONFIG_DIR/security_patch.txt" "$CONFIG_DIR/security_patch.txt.next" "$CONFIG_DIR/last_bulletin_fetch.json"

# Debug diagnostics live on external storage; remove them on uninstall.
rm -rf /data/media/0/TEESimulator
