#!/system/bin/sh

set -eu
set -f

readonly state="${RKA_SEPOLICY_PROBE_STATE:-/data/adb/teesimulator-rka}"
readonly socket="${RKA_SEPOLICY_PROBE_SOCKET:-"$state"/run/sockets/broker.sock}"
listener=
scratch=

stop_listener() {
    if [ -n "$listener" ]; then
        kill "$listener" 2>/dev/null || :
        wait "$listener" 2>/dev/null || :
        listener=
    fi
}

cleanup() {
    stop_listener
    if [ -n "$scratch" ]; then
        rm -f "$scratch/sockets/broker.sock" "$scratch/sockets/renamed" "$scratch/sockets/create"
        rmdir "$scratch/sockets" 2>/dev/null || :
        rmdir "$scratch" 2>/dev/null || :
        rmdir "$state/p" 2>/dev/null || :
        scratch=
    fi
}
trap cleanup EXIT HUP INT TERM

unix_broker_probe() {
    toybox nc -U -w 2 "$socket" </dev/null >/dev/null
}

wait_for_socket() {
    attempt=0
    while [ "$attempt" -lt 2 ]; do
        [ -S "$1" ] && return 0
        sleep 1
        attempt=$((attempt + 1))
    done
    [ -S "$1" ]
}

scratch_transition_probe() {
    scratch=$state/p/$2
    scratch_socket=$scratch/sockets/broker.sock
    [ "${#scratch_socket}" -le 107 ] || exit 65
    mkdir -p "$scratch/sockets"
    : > "$scratch/sockets/create"
    toybox nc -l -U -s "$scratch_socket" </dev/null >/dev/null 2>&1 & listener=$!
    wait_for_socket "$scratch_socket"
    toybox nc -U -w 2 "$scratch_socket" </dev/null >/dev/null
    stop_listener
    rm -f "$scratch_socket"
    mv "$scratch/sockets/create" "$scratch/sockets/renamed"
    rm -f "$scratch/sockets/renamed"
    rmdir "$scratch/sockets"
    rmdir "$scratch"
    rmdir "$state/p"
    scratch=
}

case ${1-} in
    4f4a914c656ebaa9170f252850ac3043901d1be7642053c124b07974a3f87eb3) toybox stat -c '%F:%t:%T' "$socket" >/dev/null ;;
    98e6127fb1d87000aadbb1026933eb47aba791e5563dbd65a954c4bacc534a34) toybox stat -c '%F:%t:%T' "$socket" >/dev/null ;;
    37d3b23016f8334d3b99288479025bf22468456df2f4554cf78da73f15f2d7a7) toybox stat -c '%F:%t:%T' "$socket" >/dev/null ;;
    b25eeb0f71d1a9d04fb60cf3b2693bfac938b5916d1ef774973739925bded4ab) scratch_transition_probe "$1" t01 ;;
    861d9f53be100384cab7ee82c939d6357771105123a10ef999232c5f41cb1582) scratch_transition_probe "$1" t02 ;;
    52456abd2e61dd74a98d9ad360b409d9d481a950ca41f0d115de394559176a24) scratch_transition_probe "$1" t03 ;;
    02c6fdc421f86ba69259065a757a1bebe0032036dbf7033687832b5d1df69fa4) scratch_transition_probe "$1" t04 ;;
    7e218072049aca0bc3a6ecc3ab81b754af541e71c2100fa7c3a1e255ea74c619) unix_broker_probe ;;
    790119fc0382f4845b00c6e21562a837828d75295904d758905afa09a1f4639d) scratch_transition_probe "$1" t05 ;;
    ca99c9a626c3af17175bcd6efff7054d26bcb50ca20c69066ad3af8809da0edd) scratch_transition_probe "$1" t06 ;;
    *) exit 64 ;;
esac
