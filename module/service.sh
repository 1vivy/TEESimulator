#!/system/bin/sh
# API36 safety fork: boot is deliberately inert. Injection is never a boot action.
MODDIR=${0%/*}
STATE="$MODDIR/state"

mkdir -p "$STATE"
printf '%s\n' "INERT: no compatibility action started" >"$STATE/last-service-status"
exit 0
