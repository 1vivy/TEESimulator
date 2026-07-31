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

tcp_loopback_probe() {
    port=$((49152 + ($$ % 16384)))
    toybox nc -l -s 127.0.0.1 -p "$port" </dev/null >/dev/null 2>&1 & listener=$!
    toybox nc -w 2 127.0.0.1 "$port" </dev/null >/dev/null
    stop_listener
}

udp_loopback_probe() {
    port=$((49152 + ($$ % 16384)))
    toybox nc -l -u -s 127.0.0.1 -p "$port" </dev/null >/dev/null 2>&1 & listener=$!
    printf x | toybox nc -u -w 2 127.0.0.1 "$port" >/dev/null
    stop_listener
}

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
    toybox nc -l -U "$scratch_socket" </dev/null >/dev/null 2>&1 & listener=$!
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
    3b93b88ace5ab39d7ee01ea44d075b448ab7eafa6792c1bb3cbaa97266da02af) tcp_loopback_probe ;;
    2d9f3cf44030f321ff9dffee5f158fe6941df67cacae77dec54ae8e84d72748e) tcp_loopback_probe ;;
    f48840a8a5154578cc169fd98a64eb121fe94732da6a167bda63648f6c4e7f7a) tcp_loopback_probe ;;
    60ea73d040a2f46b76b204bad2595f899e803f7bc0a8958f74695167f3c98c39) tcp_loopback_probe ;;
    e218a8d598393ca8380c53200e3a54a601073d7174b16751cf32ae8c44254dfd) tcp_loopback_probe ;;
    6aa88691af3c757f9398c6afdbed459fe8bbf9a4791ff415f472b97d79d7af70) tcp_loopback_probe ;;
    43cde2c56cb06e5c7e3d33109d3efdd8349bbd42c02e89956aaf5f0e4627e224) udp_loopback_probe ;;
    5423e3fd80c5b687e0430f8c934700f5672bb5b102beff0b9c2c26257f3af864) udp_loopback_probe ;;
    58bab71fb5f3cb4dd79fa2e40bef9e22e340174c5d70c333f5b422a0cfbf4605) udp_loopback_probe ;;
    3a9281f83546e00271c332deaa60f9e5acde1b48d38d2f872a6d3c93a7b8ba59) udp_loopback_probe ;;
    eb5bb2cc68696f45c152aefaef40c566ac29e58b3d0952c0f2e454c0b6d6d589) udp_loopback_probe ;;
    75bfa7a588b76db9ba5167727ae7c073e1736830f4d9eb419b833f250f21fdbe) udp_loopback_probe ;;
    b25eeb0f71d1a9d04fb60cf3b2693bfac938b5916d1ef774973739925bded4ab) scratch_transition_probe "$1" t01 ;;
    861d9f53be100384cab7ee82c939d6357771105123a10ef999232c5f41cb1582) scratch_transition_probe "$1" t02 ;;
    52456abd2e61dd74a98d9ad360b409d9d481a950ca41f0d115de394559176a24) scratch_transition_probe "$1" t03 ;;
    66a0cb145bebfbb97eb044cf2496d2785d183a975854b6ebca1a299c2475132a) scratch_transition_probe "$1" t04 ;;
    02c6fdc421f86ba69259065a757a1bebe0032036dbf7033687832b5d1df69fa4) scratch_transition_probe "$1" t05 ;;
    e0f3d140c7c052636351dd0c4431e04514a5c6873d981dfe7185aa3959733fea) scratch_transition_probe "$1" t06 ;;
    fd135252e3e0338845d7d55a02821b6eb4e6b541ef9b6da75b08e8ef9f44ea7d) unix_broker_probe ;;
    4c62d4f882a663888dbbc63eafcda776e18c82d226fcf7b9d22573ff3363d379) unix_broker_probe ;;
    790119fc0382f4845b00c6e21562a837828d75295904d758905afa09a1f4639d) scratch_transition_probe "$1" t07 ;;
    ca99c9a626c3af17175bcd6efff7054d26bcb50ca20c69066ad3af8809da0edd) scratch_transition_probe "$1" t08 ;;
    1d6cbc144a30a877de24e6d6af9a9283b09e85e41b5b23a732db01c8cb1b6f0d) scratch_transition_probe "$1" t09 ;;
    beffd260dcd0a2749bd8b7569aca4f745fdaae0a39d070441f16c8a50969f356) scratch_transition_probe "$1" t10 ;;
    *) exit 64 ;;
esac
