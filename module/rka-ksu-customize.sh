# shellcheck shell=sh
set_perm_recursive "$MODPATH" 0 0 0755 0644 || abort "! Failed to assign module permissions"

for file in \
    daemon \
    rka-agent-pgp-verify \
    rka-control.sh \
    rka-paths.sh \
    rka-sepolicy-probe.sh \
    rka-sidecar \
    rka-supervisor.sh \
    service.sh \
    uninstall.sh; do
    [ -f "$MODPATH/$file" ] && [ ! -L "$MODPATH/$file" ] || abort "! Invalid module executable"
    set_perm "$MODPATH/$file" 0 0 0755 || abort "! Failed to assign executable permission"
done
