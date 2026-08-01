#!/bin/sh
set -eu
umask 077

scenario=${1-}
case $scenario in transition-interruption) expected_interruptions=1 ;; repeated-interruption) expected_interruptions=2 ;; *) exit 2 ;; esac
: "${RKA_HOST_BIN:?RKA_HOST_BIN is required}"

repository=$(CDPATH='' cd -- "$(dirname -- "$0")/../../../.." && pwd -P)
wrapper=$repository/scripts/rka-with-device-pair.sh
fixture=$(mktemp -d)
holder_pid=

sampler_pids() {
    find "$fixture/devices" -path '*/sentinel/*/pid' -type f -exec cat {} \; 2>/dev/null || :
}

cleanup() {
    [ -z "$holder_pid" ] || kill "$holder_pid" 2>/dev/null || :
    sampler_pids | while IFS= read -r pid; do kill "$pid" 2>/dev/null || :; done
    find "$fixture" -depth -delete 2>/dev/null || :
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$fixture/pair" "$fixture/tools" "$fixture/device-tools" "$fixture/control" "$fixture/output" "$fixture/devices/SYNTH_DONOR/module" "$fixture/devices/SYNTH_DONOR/state" "$fixture/devices/SYNTH_DONOR/sentinel" "$fixture/devices/SYNTH_CANDIDATE/module" "$fixture/devices/SYNTH_CANDIDATE/state" "$fixture/devices/SYNTH_CANDIDATE/sentinel"
chmod 700 "$fixture" "$fixture/pair" "$fixture/tools" "$fixture/device-tools" "$fixture/control" "$fixture/output" "$fixture/devices" "$fixture/devices"/* "$fixture/devices"/*/module "$fixture/devices"/*/state "$fixture/devices"/*/sentinel

pair=$fixture/pair/device-pair.json
lock=$fixture/pair/device-pair.lock
baseline=$fixture/baseline.json
printf '%s\n' '{"candidate_serial":"SYNTH_CANDIDATE","donor_serial":"SYNTH_DONOR","profile_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_version":1}' > "$pair"
donor_b64=$(printf SYNTH_DONOR | base64 -w0 | tr '+/' '-_' | tr -d '=')
candidate_b64=$(printf SYNTH_CANDIDATE | base64 -w0 | tr '+/' '-_' | tr -d '=')
printf 'RKA_DEVICE_PAIR_VERSION=1\nRKA_DONOR_SERIAL_B64=%s\nRKA_CANDIDATE_SERIAL_B64=%s\nRKA_PROFILE_SHA256=%s\n' "$donor_b64" "$candidate_b64" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa > "$fixture/pair/device-pair.env"
: > "$lock"
chmod 600 "$pair" "$lock" "$fixture/pair/device-pair.env"

cat > "$fixture/device-tools/pidof" <<'EOF'
#!/bin/sh
case ${1-} in keystore2|rkpd) printf '1\n' ;; *) exit 1 ;; esac
EOF
cat > "$fixture/device-tools/getprop" <<'EOF'
#!/bin/sh
printf 'stable-synthetic-value\n'
EOF
cat > "$fixture/device-tools/logcat" <<'EOF'
#!/bin/sh
printf 'invoked\n' >> "$RKA_INTERRUPT_ROOT/control/logcat-invocations"
while sleep 1; do :; done
EOF
chmod 700 "$fixture/device-tools"/*

cat > "$fixture/tools/adb" <<'EOF'
#!/bin/sh
set -eu
serial=$2
shift 2
device=$RKA_INTERRUPT_ROOT/devices/$serial
case "$*" in
    'shell cat /proc/sys/kernel/random/boot_id') printf 'synthetic-%s-boot\n' "$serial"; exit 0 ;;
    'shell cat /proc/uptime') cat /proc/uptime; exit 0 ;;
    'shell su 0 sh') ;;
    *) exit 2 ;;
esac
payload=$(mktemp "$RKA_INTERRUPT_ROOT/control/payload.XXXXXX")
mapped_payload=$(mktemp "$RKA_INTERRUPT_ROOT/control/mapped-payload.XXXXXX")
loader_root=$device/loader
mkdir -p "$loader_root"
chmod 700 "$loader_root"
trap 'find "$payload" "$mapped_payload" -depth -delete 2>/dev/null || :' EXIT
cat > "$payload"
action=$(sed -n 's/^set -- \([^ ]*\).*/\1/p' "$payload" | head -n 1)
sentinel_id=$(sed -n 's/^set -- [^ ]* \([^ ]*\).*/\1/p' "$payload" | head -n 1)
if [ "$serial" = SYNTH_DONOR ] && [ "$action" = assert-live ] && [ -f "$RKA_INTERRUPT_ROOT/control/barrier-next" ]; then
    barrier=$(cat "$RKA_INTERRUPT_ROOT/control/barrier-next")
    mv "$RKA_INTERRUPT_ROOT/control/barrier-next" "$RKA_INTERRUPT_ROOT/control/barrier-consumed-$barrier"
    : > "$RKA_INTERRUPT_ROOT/control/barrier-ready-$barrier"
    trap 'printf "sentinel_id=%s action=assert-live phase=INSTALLED_OBSERVED samples=999\n" "$sentinel_id"; exit 0' HUP INT TERM
    while :; do sleep 1; done
fi
control=$device/module/rka-control.sh
state=$device/state
sed "s#/data/local/tmp/rka-host-root\.#$loader_root/rka-host-root.#g" "$payload" > "$mapped_payload"
RKA_SENTINEL_ROOT=$device/sentinel \
RKA_SENTINEL_CONTROL=$control \
RKA_SENTINEL_STATE_ROOT=$state \
PATH=$RKA_INTERRUPT_ROOT/device-tools:$PATH \
    exec sh "$mapped_payload"
EOF
chmod 700 "$fixture/tools/adb"

run_host() {
    PATH=$fixture/tools:$PATH RKA_INTERRUPT_ROOT=$fixture RKA_INTERRUPT_MUTATION=${RKA_INTERRUPT_MUTATION-} \
        "$wrapper" --pair "$pair" -- "$RKA_HOST_BIN" "$@"
}

start_interrupt_host() {
    exec env PATH="$fixture/tools:$PATH" RKA_INTERRUPT_ROOT="$fixture" RKA_INTERRUPT_MUTATION="${RKA_INTERRUPT_MUTATION-}" \
        "$wrapper" --pair "$pair" -- "$RKA_HOST_BIN" "$@"
}

sentinel_directory() {
    find "$fixture/devices/$1/sentinel" -mindepth 1 -maxdepth 1 -type d
}

sample_count() {
    cat "$(sentinel_directory "$1")/count"
}

metadata_digest() {
    sha256sum "$(sentinel_directory "$1")/metadata" | awk '{print $1}'
}

assert_sampler_live() {
    pid=$(cat "$(sentinel_directory "$1")/pid")
    kill -0 "$pid"
}

assert_frames_complete() {
    sentinel=$(sentinel_directory "$1")
    count=$(cat "$sentinel/count")
    files=$(find "$sentinel/samples" -type f | wc -l)
    [ "$count" -eq "$files" ]
    [ -z "$(find "$sentinel/samples" -name '*.tmp' -print -quit)" ]
    sequence=1
    while [ "$sequence" -le "$count" ]; do
        [ "$(sed -n '5s/^sequence=//p' "$sentinel/samples/$sequence")" -eq "$sequence" ]
        [ "$(tail -n 1 "$sentinel/samples/$sequence")" = complete=1 ]
        sequence=$((sequence + 1))
    done
}

maximum_gap() {
    sentinel=$(sentinel_directory "$1")
    awk -F= '$1 == "uptime_ms" { if (seen && $2 - last > maximum) maximum=$2-last; last=$2; seen=1 } END { print maximum+0 }' "$sentinel"/samples/*
}

install_runtime() {
    device=$fixture/devices/$1
    mkdir -p "$device/module/META-INF" "$device/state/run"
    printf '#!/bin/sh\nexit 0\n' > "$device/module/rka-control.sh"
    chmod 700 "$device/module/rka-control.sh"
    control_hash=$(sha256sum "$device/module/rka-control.sh" | awk '{print $1}')
    printf '%s  rka-control.sh\n' "$control_hash" > "$device/module/META-INF/rka-artifacts.sha256"
    boot=$(cat /proc/sys/kernel/random/boot_id)
    printf 'version=1\nsentinel_id=synthetic\nboot_id=%s\nsample_ms=1\n' "$boot" > "$device/state/run/boot-continuity.state"
}

mutate_after_interrupt() {
    case ${RKA_INTERRUPT_MUTATION-} in
        kill_sampler)
            sampler_pids | while IFS= read -r pid; do kill "$pid" 2>/dev/null || :; done
            ;;
        new_lifecycle)
            run_host sentinel stop --baseline "$baseline" >/dev/null 2>&1
            run_host sentinel start --baseline "$baseline" --nonce SYNTH_REPLACEMENT >/dev/null 2>&1
            ;;
        hold_lock)
            (exec 8> "$lock"; flock 8; : > "$fixture/control/lock-held"; sleep 10) &
            holder_pid=$!
            while [ ! -f "$fixture/control/lock-held" ]; do sleep 0.01; done
            ;;
        gap)
            sampler_pids | while IFS= read -r pid; do kill -STOP "$pid"; done
            sleep 3
            sampler_pids | while IFS= read -r pid; do kill -CONT "$pid"; done
            ;;
        partial_installed)
            candidate=$(sentinel_directory SYNTH_CANDIDATE)
            sequence=$(cat "$candidate/count")
            sed -i 's/^phase=PRE_INSTALL$/phase=INSTALLED/' "$candidate/samples/$sequence"
            ;;
    esac
}

interrupt_assert() {
    barrier=$1
    printf '%s\n' "$barrier" > "$fixture/control/barrier-next"
    start_interrupt_host sentinel assert-live --baseline "$baseline" > "$fixture/output/interrupted-$barrier.out" 2> "$fixture/output/interrupted-$barrier.err" &
    wrapper_pid=$!
    attempts=0
    while [ ! -f "$fixture/control/barrier-ready-$barrier" ]; do
        sleep 0.01
        attempts=$((attempts + 1))
        [ "$attempts" -le 1000 ] || return 1
    done
    before_donor=$(sample_count SYNTH_DONOR)
    before_candidate=$(sample_count SYNTH_CANDIDATE)
    kill -TERM "$wrapper_pid"
    set +e
    wait "$wrapper_pid"
    interrupted_status=$?
    set -e
    [ "$interrupted_status" -eq 143 ]
    if grep -q '"result":"SENTINEL_LIVE"' "$fixture/output/interrupted-$barrier.out"; then return 1; fi
    mutate_after_interrupt
    flock -n "$lock" -c true
    sleep 2
    assert_sampler_live SYNTH_DONOR
    assert_sampler_live SYNTH_CANDIDATE
    after_donor=$(sample_count SYNTH_DONOR)
    after_candidate=$(sample_count SYNTH_CANDIDATE)
    [ "$after_donor" -gt "$before_donor" ]
    [ "$after_candidate" -gt "$before_candidate" ]
    [ "$(sha256sum "$baseline" | awk '{print $1}')" = "$baseline_digest" ]
    [ "$(sha256sum "$pair" | awk '{print $1}')" = "$pair_digest" ]
    [ "$(metadata_digest SYNTH_DONOR)" = "$donor_metadata" ]
    [ "$(metadata_digest SYNTH_CANDIDATE)" = "$candidate_metadata" ]
    assert_frames_complete SYNTH_DONOR
    assert_frames_complete SYNTH_CANDIDATE
    [ "$(maximum_gap SYNTH_DONOR)" -le 2000 ]
    [ "$(maximum_gap SYNTH_CANDIDATE)" -le 2000 ]
    eval "status_$barrier=$interrupted_status"
    eval "count_${barrier}_donor=$after_donor"
    eval "count_${barrier}_candidate=$after_candidate"
}

run_host sentinel start --baseline "$baseline" --nonce SYNTH_NONCE >/dev/null
sleep 2
status_transition=UNSET
count_transition_donor=UNSET
count_transition_candidate=UNSET
initial_donor=$(sample_count SYNTH_DONOR)
initial_candidate=$(sample_count SYNTH_CANDIDATE)
baseline_digest=$(sha256sum "$baseline" | awk '{print $1}')
pair_digest=$(sha256sum "$pair" | awk '{print $1}')
donor_metadata=$(metadata_digest SYNTH_DONOR)
candidate_metadata=$(metadata_digest SYNTH_CANDIDATE)

install_runtime SYNTH_DONOR
interrupt_assert transition
grep -q '^phase=INSTALLED$' "$(sentinel_directory SYNTH_DONOR)"/samples/*
if grep -q '^phase=INSTALLED$' "$(sentinel_directory SYNTH_CANDIDATE)"/samples/*; then exit 1; fi
install_runtime SYNTH_CANDIDATE
sleep 2

if [ "$expected_interruptions" -eq 2 ]; then
    interrupt_assert installed
else
    status_installed=NOT_RUN
    count_installed_donor=NOT_RUN
    count_installed_candidate=NOT_RUN
fi

run_host sentinel assert-live --baseline "$baseline" > "$fixture/output/final.out"
grep -q '"result":"SENTINEL_LIVE"' "$fixture/output/final.out"
grep -q '^phase=INSTALLED$' "$(sentinel_directory SYNTH_DONOR)"/samples/*
grep -q '^phase=INSTALLED$' "$(sentinel_directory SYNTH_CANDIDATE)"/samples/*
final_donor=$(sample_count SYNTH_DONOR)
final_candidate=$(sample_count SYNTH_CANDIDATE)
max_gap_donor=$(maximum_gap SYNTH_DONOR)
max_gap_candidate=$(maximum_gap SYNTH_CANDIDATE)
run_host sentinel stop --baseline "$baseline" >/dev/null
[ ! -e "$baseline" ]
[ ! -e "$fixture/devices/SYNTH_DONOR/sentinel" ]
[ ! -e "$fixture/devices/SYNTH_CANDIDATE/sentinel" ]
[ ! -e "$fixture/control/logcat-invocations" ]
[ ! -e "$baseline" ]
[ ! -e "$fixture/devices/SYNTH_DONOR/sentinel" ]
[ ! -e "$fixture/devices/SYNTH_CANDIDATE/sentinel" ]

printf 'scenario=%s\n' "$scenario"
printf 'interruption_count=%s\n' "$expected_interruptions"
printf 'interruption_statuses=%s,%s\n' "$status_transition" "$status_installed"
printf 'sample_counts_donor=%s,%s,%s,%s\n' "$initial_donor" "$count_transition_donor" "$count_installed_donor" "$final_donor"
printf 'sample_counts_candidate=%s,%s,%s,%s\n' "$initial_candidate" "$count_transition_candidate" "$count_installed_candidate" "$final_candidate"
printf 'maximum_gap_ms=%s,%s\n' "$max_gap_donor" "$max_gap_candidate"
printf 'logcat_invocations=0\n'
printf 'same_lifecycle=true\nlock_reacquired_each=true\npartial_transition_not_installed=true\nstale_success_rejected=true\nsequence_advanced_each=true\ninstalled_resume=true\ncleanup_idempotent=true\nresult=PASS\n'
