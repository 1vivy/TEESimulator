#!/usr/bin/env bash
set -euo pipefail

RKA_PAIR_WRAPPER_DIR=$(cd -- "$(dirname -- "$0")" && pwd -P)
export RKA_PAIR_WRAPPER_DIR
exec python3 - "$@" <<'PY'
import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys

class WrapperFailure(Exception):
    pass

PAIR_ENVIRONMENT_NAMES = {
    "RKA_DEVICE_PAIR_VERSION",
    "RKA_DONOR_SERIAL_B64",
    "RKA_CANDIDATE_SERIAL_B64",
    "RKA_PROFILE_SHA256",
}
SURFACE_FILES = (
    "scripts/rka-deploy.sh",
    "scripts/rka-adb-root.sh",
    "scripts/rka-traced-adb.sh",
)

def fail(code):
    raise WrapperFailure(code)

def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail("PAIR_SNAPSHOT_INVALID")
        value[key] = item
    return value

def decode_serial(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        fail("PAIR_SNAPSHOT_INVALID")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        ).decode("ascii")
    except (binascii.Error, UnicodeError, ValueError):
        fail("PAIR_SNAPSHOT_INVALID")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", decoded):
        fail("PAIR_SNAPSHOT_INVALID")
    return decoded

def attest_deploy_surface(wrapper_directory):
    project_root = os.path.realpath(os.path.join(wrapper_directory, ".."))
    manifest_path = os.path.join(wrapper_directory, "rka-command-surface.sha256")
    manifest_facts = os.lstat(manifest_path)
    if (
        not stat.S_ISREG(manifest_facts.st_mode)
        or manifest_facts.st_uid != os.getuid()
        or stat.S_IMODE(manifest_facts.st_mode) & 0o022
    ):
        fail("DEPLOY_SOURCE_UNSAFE")
    with open(manifest_path, "rb") as source:
        manifest = source.read()
    if len(manifest) > 4096 or not manifest.endswith(b"\n"):
        fail("DEPLOY_SOURCE_MANIFEST_INVALID")
    records = {}
    for raw_line in manifest.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", raw_line)
        if match is None or match.group(2) in records:
            fail("DEPLOY_SOURCE_MANIFEST_INVALID")
        records[match.group(2)] = match.group(1)
    if tuple(records) != SURFACE_FILES:
        fail("DEPLOY_SOURCE_MANIFEST_INVALID")
    expected_modes = {
        "scripts/rka-deploy.sh": 0o755,
        "scripts/rka-adb-root.sh": 0o644,
        "scripts/rka-traced-adb.sh": 0o755,
    }
    for relative, expected in records.items():
        source_path = os.path.join(project_root, relative)
        facts = os.lstat(source_path)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.getuid()
            or stat.S_IMODE(facts.st_mode) != expected_modes[relative]
            or os.path.islink(source_path)
        ):
            fail("DEPLOY_SOURCE_UNSAFE")
        with open(source_path, "rb") as source:
            observed = hashlib.sha256(source.read()).hexdigest()
        if observed != expected:
            fail("DEPLOY_SOURCE_MISMATCH")
    deploy = os.path.realpath(os.path.join(project_root, "scripts/rka-deploy.sh"))
    return {
        "deploy": deploy,
        "deploy_sha": records["scripts/rka-deploy.sh"],
        "deploy_path_sha": hashlib.sha256(deploy.encode("utf-8")).hexdigest(),
        "surface_sha": hashlib.sha256(manifest).hexdigest(),
    }

def main():
    args = sys.argv[1:]
    if len(args) < 4 or args[0] != "--pair" or args[2] != "--" or args[1] == "":
        fail("USAGE")
    pair_path = os.path.abspath(args[1])
    if os.path.basename(pair_path) != "device-pair.json":
        fail("PAIR_PATH_INVALID")
    command = args[3:]
    if not command or any(value == "--pair" or value.startswith("--pair=") for value in command):
        fail("CHILD_PAIR_PATH_FORBIDDEN")

    runtime = os.path.dirname(pair_path)
    directory_fd = os.open(
        runtime, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    directory = os.fstat(directory_fd)
    if directory.st_uid != os.getuid() or stat.S_IMODE(directory.st_mode) != 0o700:
        fail("RUNTIME_DIRECTORY_UNSAFE")

    def secure_open(name, flags):
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
        value = os.fstat(fd)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            value.st_uid != os.getuid()
            or stat.S_IMODE(value.st_mode) != 0o600
            or not stat.S_ISREG(value.st_mode)
            or value.st_ino != current.st_ino
            or value.st_dev != current.st_dev
        ):
            fail("PAIR_FILE_UNSAFE")
        return fd

    lock_fd = secure_open("device-pair.lock", os.O_RDWR)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fail("PAIR_LOCK_BUSY")
    json_fd = secure_open("device-pair.json", os.O_RDONLY)
    env_fd = secure_open("device-pair.env", os.O_RDONLY)

    raw_json = os.read(json_fd, 65537)
    raw_env = os.read(env_fd, 8193)
    if len(raw_json) > 65536 or len(raw_env) > 8192:
        fail("PAIR_SNAPSHOT_OVERSIZED")
    try:
        pair = json.loads(raw_json, object_pairs_hook=unique_object)
        if not isinstance(pair, dict):
            fail("PAIR_SNAPSHOT_INVALID")
        lines = raw_env.decode("ascii").splitlines()
        env = unique_object(line.split("=", 1) for line in lines)
        donor = decode_serial(env["RKA_DONOR_SERIAL_B64"])
        candidate = decode_serial(env["RKA_CANDIDATE_SERIAL_B64"])
    except (ValueError, KeyError, UnicodeError, json.JSONDecodeError, TypeError):
        fail("PAIR_SNAPSHOT_INVALID")
    if set(env) != PAIR_ENVIRONMENT_NAMES:
        fail("PAIR_ENV_INVALID")
    if (
        env["RKA_DEVICE_PAIR_VERSION"] != "1"
        or type(pair.get("schema_version")) is not int
        or pair.get("schema_version") != 1
        or donor != pair.get("donor_serial")
        or candidate != pair.get("candidate_serial")
        or env["RKA_PROFILE_SHA256"] != pair.get("profile_sha256")
    ):
        fail("PAIR_SNAPSHOT_MISMATCH")
    legacy_keys = {
        "candidate_serial",
        "donor_serial",
        "profile_sha256",
        "schema_version",
    }
    canonical_keys = legacy_keys | {
        "candidate_serial_sha256",
        "donor_serial_sha256",
    }
    if set(pair) not in (legacy_keys, canonical_keys):
        fail("PAIR_SNAPSHOT_INVALID")
    if donor == candidate:
        fail("PAIR_SNAPSHOT_INVALID")
    if not isinstance(pair["profile_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", pair["profile_sha256"]
    ):
        fail("PAIR_SNAPSHOT_INVALID")
    donor_hash = hashlib.sha256(donor.encode("ascii")).hexdigest()
    candidate_hash = hashlib.sha256(candidate.encode("ascii")).hexdigest()
    if set(pair) == canonical_keys and (
        pair["donor_serial_sha256"] != donor_hash
        or pair["candidate_serial_sha256"] != candidate_hash
    ):
        fail("PAIR_SNAPSHOT_MISMATCH")
    canonical = json.dumps(
        {
            "candidate_serial": candidate,
            "candidate_serial_sha256": candidate_hash,
            "donor_serial": donor,
            "donor_serial_sha256": donor_hash,
            "profile_sha256": pair["profile_sha256"],
            "schema_version": 1,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"
    host_cli_child = (
        os.path.basename(command[0]) == "rka-host"
        or "org.matrix.teesimulator.rkahost.cli.HostCli" in command
    )
    child_snapshot = canonical

    memfd = os.memfd_create("rka-device-pair", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.write(memfd, child_snapshot)
    os.lseek(memfd, 0, os.SEEK_SET)
    seals = (
        fcntl.F_SEAL_SEAL
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_WRITE
    )
    fcntl.fcntl(memfd, fcntl.F_ADD_SEALS, seals)
    readonly_fd = os.open(f"/proc/self/fd/{memfd}", os.O_RDONLY | os.O_CLOEXEC)
    os.dup2(readonly_fd, 3, inheritable=True)
    for fd in (json_fd, env_fd, directory_fd, memfd, readonly_fd):
        if fd not in (3, lock_fd):
            os.close(fd)
    environment = os.environ.copy()
    configured_adb = environment.get("RKA_DEPLOY_ADB", "adb")
    for name in tuple(environment):
        if (
            name.startswith("RKA_DEVICE_PAIR_")
            or name.startswith("RKA_TRACE_")
            or name in PAIR_ENVIRONMENT_NAMES
        ):
            del environment[name]
    environment["RKA_DEVICE_PAIR_FD"] = "3"
    environment["RKA_RUNTIME_DIR"] = runtime
    surface = attest_deploy_surface(environment["RKA_PAIR_WRAPPER_DIR"])
    environment["RKA_TRACE_DEPLOY_SHA256"] = surface["deploy_sha"]
    environment["RKA_TRACE_DEPLOY_PATH_SHA256"] = surface["deploy_path_sha"]
    environment["RKA_TRACE_SURFACE_SHA256"] = surface["surface_sha"]
    active_trace = os.path.exists(os.path.join(runtime, "active-adb-trace-v1"))
    resolved_command = (
        os.path.realpath(command[0])
        if os.path.sep in command[0]
        else shutil.which(command[0], path=environment.get("PATH"))
    )
    deploy_named = os.path.basename(command[0]) == "rka-deploy.sh"
    if deploy_named and resolved_command != surface["deploy"]:
        fail("DEPLOY_SOURCE_MISMATCH")
    if active_trace and not host_cli_child and resolved_command != surface["deploy"]:
        fail("TRACE_CHILD_UNAUTHORIZED")
    if active_trace and resolved_command == surface["deploy"]:
        host_cli = shutil.which("rka-host", path=environment.get("PATH"))
        if host_cli is None:
            fail("TRACE_HOST_UNAVAILABLE")
        environment["RKA_TRACE_HOST_CLI"] = host_cli
        environment["RKA_TRACE_REAL_ADB"] = configured_adb
        environment["RKA_TRACE_REQUIRED"] = "1"
        environment["RKA_TRACE_DEPLOY_REALPATH"] = surface["deploy"]
        environment["RKA_DEPLOY_ADB"] = os.path.join(
            environment["RKA_PAIR_WRAPPER_DIR"], "rka-traced-adb.sh"
        )
    child = subprocess.Popen(
        command,
        env=environment,
        pass_fds=(3,),
        close_fds=True,
        start_new_session=True,
    )

    def forward(signal_number, _frame):
        try:
            os.killpg(child.pid, signal_number)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGINT, forward)
    signal.signal(signal.SIGTERM, forward)
    return_code = child.wait()
    return 128 + -return_code if return_code < 0 else return_code

try:
    raise SystemExit(main())
except WrapperFailure as failure:
    print(f"RESULT={failure}", file=sys.stderr)
    raise SystemExit(2)
except (OSError, ValueError, KeyError, UnicodeError, json.JSONDecodeError):
    print("RESULT=PAIR_WRAPPER_FAILED", file=sys.stderr)
    raise SystemExit(2)
PY
