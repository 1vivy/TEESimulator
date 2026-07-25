#!/system/bin/sh
# An action button must never make injection a one-click or persistent operation.
MODDIR=${0%/*}
STATE="$MODDIR/state"
mkdir -p "$STATE"
printf '%s\n' "STOP action-disabled: use the host gate workflow" >"$STATE/last-action-status"
exit 1
