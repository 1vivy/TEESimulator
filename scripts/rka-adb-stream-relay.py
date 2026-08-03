#!/usr/bin/env python3
"""Relay end-to-end RKA TLS records between an ADB donor and a routed candidate."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import subprocess
import sys
import time
from typing import Final, Sequence


PORT: Final = 37_373
BUFFER_BYTES: Final = 65_536
PAIR_MAX_BYTES: Final = 65_536
SERIAL_PATTERN: Final = re.compile(r"[A-Za-z0-9._:-]{1,128}")


class RelayFailure(Exception):
    """A redacted, user-actionable relay failure."""


@dataclass(frozen=True)
class DevicePair:
    donor_serial: str
    candidate_serial: str


@dataclass
class BridgeStats:
    donor_bytes: int = 0
    candidate_bytes: int = 0
    donor_tls_record: bool = False

    def render(self, duration_ms: int) -> str:
        return (
            "ADB_STREAM_RELAY=CLOSED "
            f"DONOR_BYTES={'YES' if self.donor_bytes else 'NO'} "
            f"CANDIDATE_BYTES={'YES' if self.candidate_bytes else 'NO'} "
            f"DONOR_TLS_RECORD={'YES' if self.donor_tls_record else 'NO'} "
            f"DURATION_MS={duration_ms} "
            f"DONOR_TOTAL={self.donor_bytes} "
            f"CANDIDATE_TOTAL={self.candidate_bytes}"
        )


def read_device_pair(path: Path) -> DevicePair:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise RelayFailure("PAIR_FILE_UNSAFE") from error
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.getuid()
            or stat.S_IMODE(facts.st_mode) != 0o600
            or facts.st_size > PAIR_MAX_BYTES
        ):
            raise RelayFailure("PAIR_FILE_UNSAFE")
        payload = os.read(descriptor, PAIR_MAX_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(payload) > PAIR_MAX_BYTES:
        raise RelayFailure("PAIR_FILE_OVERSIZED")
    try:
        value = json.loads(payload)
        donor = value["donor_serial"]
        candidate = value["candidate_serial"]
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RelayFailure("PAIR_FILE_INVALID") from error
    if (
        not isinstance(donor, str)
        or not isinstance(candidate, str)
        or SERIAL_PATTERN.fullmatch(donor) is None
        or SERIAL_PATTERN.fullmatch(candidate) is None
        or donor == candidate
    ):
        raise RelayFailure("PAIR_FILE_INVALID")
    return DevicePair(donor_serial=donor, candidate_serial=candidate)


def candidate_address(adb: str, serial: str) -> str:
    command = (
        "set -eu\n"
        "sed -n 's/^listen_interface=//p' "
        "/data/adb/teesimulator-rka/profiles/direct.conf\n"
    ).encode("ascii")
    try:
        completed = subprocess.run(
            [adb, "-s", serial, "shell", "su", "0", "sh"],
            input=command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=10,
        )
        address = completed.stdout.decode("ascii").strip()
        parsed = ipaddress.ip_address(address)
    except (OSError, UnicodeDecodeError, ValueError, subprocess.SubprocessError) as error:
        raise RelayFailure("CANDIDATE_ROUTE_UNAVAILABLE") from error
    if parsed.version != 4:
        raise RelayFailure("CANDIDATE_ROUTE_UNAVAILABLE")
    return address


def donor_listener(adb: str, serial: str) -> subprocess.Popen[bytes]:
    try:
        return subprocess.Popen(
            [
                adb,
                "-s",
                serial,
                "shell",
                "-T",
                "toybox",
                "nc",
                "-l",
                "-p",
                str(PORT),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
    except OSError as error:
        raise RelayFailure("DONOR_ADB_UNAVAILABLE") from error


def close_listener(process: subprocess.Popen[bytes]) -> None:
    try:
        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()
    except OSError:
        pass
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def bridge_once(adb: str, pair: DevicePair, address: str) -> BridgeStats:
    remote = donor_listener(adb, pair.donor_serial)
    if remote.stdin is None or remote.stdout is None:
        close_listener(remote)
        raise RelayFailure("DONOR_ADB_UNAVAILABLE")
    network: socket.socket | None = None
    stats = BridgeStats()
    donor_header = bytearray()
    started = time.monotonic()
    try:
        time.sleep(0.2)
        try:
            network = socket.create_connection((address, PORT), timeout=5)
        except OSError as error:
            raise RelayFailure("CANDIDATE_ROUTE_UNAVAILABLE") from error
        network.settimeout(None)
        print("ADB_STREAM_RELAY=CONNECTED", flush=True)
        remote_fd = remote.stdout.fileno()
        while True:
            readable, _, _ = select.select([network, remote_fd], [], [], 1.0)
            if remote_fd in readable:
                payload = os.read(remote_fd, BUFFER_BYTES)
                if not payload:
                    break
                stats.donor_bytes += len(payload)
                if len(donor_header) < 5:
                    donor_header.extend(payload[: 5 - len(donor_header)])
                    stats.donor_tls_record = (
                        len(donor_header) == 5
                        and donor_header[0] in (0x15, 0x16, 0x17)
                        and donor_header[1] == 0x03
                    )
                network.sendall(payload)
            if network in readable:
                payload = network.recv(BUFFER_BYTES)
                if not payload:
                    break
                stats.candidate_bytes += len(payload)
                remote.stdin.write(payload)
                remote.stdin.flush()
        return stats
    except (OSError, subprocess.SubprocessError) as error:
        raise RelayFailure("RELAY_IO_FAILED") from error
    finally:
        print(
            stats.render(int((time.monotonic() - started) * 1000)),
            flush=True,
        )
        if network is not None:
            network.close()
        close_listener(remote)


def parse_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Relay opaque RKA TLS records from an ADB donor to a routed candidate."
    )
    parser.add_argument("--pair", required=True, type=Path)
    parser.add_argument("--adb", default=os.environ.get("RKA_DEPLOY_ADB", "adb"))
    parser.add_argument("--once", action="store_true")
    return parser.parse_args(arguments)


def run(arguments: Sequence[str]) -> int:
    options = parse_arguments(arguments)
    pair = read_device_pair(options.pair)
    print("ADB_STREAM_RELAY=STARTING", flush=True)
    while True:
        try:
            address = candidate_address(options.adb, pair.candidate_serial)
            stats = bridge_once(options.adb, pair, address)
            if not (
                stats.donor_bytes
                and stats.candidate_bytes
                and stats.donor_tls_record
            ):
                raise RelayFailure("RELAY_SESSION_INCOMPLETE")
            if options.once:
                return 0
        except RelayFailure as error:
            print(f"ADB_STREAM_RELAY=RETRY REASON={error}", flush=True)
            if options.once:
                return 1
        time.sleep(0.25)


def main() -> int:
    try:
        return run(sys.argv[1:])
    except RelayFailure as error:
        print(f"ADB_STREAM_RELAY=FAILED REASON={error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("ADB_STREAM_RELAY=STOPPED", flush=True)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
