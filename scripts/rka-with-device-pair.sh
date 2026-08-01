#!/usr/bin/env bash
set -euo pipefail

exec python3 - "$@" <<'PY'
import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys

class WrapperFailure(Exception):
    pass

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
    if set(env) != {
        "RKA_DEVICE_PAIR_VERSION",
        "RKA_DONOR_SERIAL_B64",
        "RKA_CANDIDATE_SERIAL_B64",
        "RKA_PROFILE_SHA256",
    }:
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
    child_snapshot = canonical if host_cli_child else raw_json

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
    for name in tuple(environment):
        if name.startswith("RKA_DEVICE_PAIR_"):
            del environment[name]
    environment["RKA_DEVICE_PAIR_FD"] = "3"
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
