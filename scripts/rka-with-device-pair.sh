#!/usr/bin/env bash
set -euo pipefail

exec python3 - "$@" <<'PY'
import base64
import fcntl
import json
import os
import signal
import stat
import subprocess
import sys

class WrapperFailure(Exception):
    pass

def fail(code):
    raise WrapperFailure(code)

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
        pair = json.loads(raw_json)
        lines = raw_env.decode("ascii").splitlines()
        env = dict(line.split("=", 1) for line in lines)
        donor = base64.urlsafe_b64decode(
            env["RKA_DONOR_SERIAL_B64"] + "==="
        ).decode()
        candidate = base64.urlsafe_b64decode(
            env["RKA_CANDIDATE_SERIAL_B64"] + "==="
        ).decode()
    except (ValueError, KeyError, UnicodeError, json.JSONDecodeError):
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
        or pair.get("schema_version") != 1
        or donor != pair.get("donor_serial")
        or candidate != pair.get("candidate_serial")
        or env["RKA_PROFILE_SHA256"] != pair.get("profile_sha256")
    ):
        fail("PAIR_SNAPSHOT_MISMATCH")

    memfd = os.memfd_create("rka-device-pair", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.write(memfd, raw_json)
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
