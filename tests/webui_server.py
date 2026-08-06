from __future__ import annotations

import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
from typing import Final

from webui_server_state import RuntimeStateStore


REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
CONTROL: Final = REPOSITORY_ROOT / "module" / "rka-control.sh"
WEBROOT: Final = Path(os.environ.get("RKA_WEBROOT", REPOSITORY_ROOT / "module" / "webroot"))
PUBLIC_CONTROL: Final = "/data/adb/modules/tricky_store/rka-control.sh"


class Handler(SimpleHTTPRequestHandler):
    server: "WebUiServer"

    def __init__(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
        server: "WebUiServer",
    ) -> None:
        super().__init__(request, client_address, server, directory=str(WEBROOT))

    def do_POST(self) -> None:
        if self.path == "/api/test-state":
            self.set_test_state()
            return
        if self.path != "/api/exec":
            self.send_error(404)
            return
        length = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(length))
        command = request.get("command", "")
        arguments = shlex.split(command)
        if not arguments or arguments[0] != PUBLIC_CONTROL:
            self.send_json({"errno": 64, "stdout": ""})
            return
        session_id = self.headers.get("x-rka-test-session", "default")
        try:
            runtime = self.server.runtime_states.get(session_id)
        except ValueError:
            self.send_json({"errno": 64, "stdout": ""})
            return
        result = subprocess.run(
            [
                "bash",
                str(CONTROL),
                "--root",
                str(runtime.module_root),
                "--state-root",
                str(runtime.state_root),
                *arguments[1:],
            ],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, **runtime.environment},
        )
        self.send_json({
            "errno": result.returncode,
            "stderr": result.stderr,
            "stdout": result.stdout,
        })

    def set_test_state(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        if length <= 0 or length > 128:
            self.send_json({"errno": 64, "stdout": ""})
            return
        request = json.loads(self.rfile.read(length))
        if request != {"runtime": "RUNNING"}:
            self.send_json({"errno": 64, "stdout": ""})
            return
        session_id = self.headers.get("x-rka-test-session", "default")
        try:
            runtime = self.server.runtime_states.get(session_id)
        except ValueError:
            self.send_json({"errno": 64, "stdout": ""})
            return
        private(runtime.state_root / "run" / "supervisor.state", "RUNNING\n")
        self.send_json({"errno": 0, "stdout": ""})

    def send_json(self, value: dict[str, int | str]) -> None:
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            return


class WebUiServer(ThreadingHTTPServer):
    runtime_states: RuntimeStateStore


def private(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o600)


def initialize(root: Path) -> tuple[Path, Path, dict[str, str]]:
    module_root = root / "module"
    state_root = root / "state"
    subprocess.run(
        ["bash", str(CONTROL), "--root", str(module_root), "--state-root", str(state_root), "set-role", "DONOR"],
        check=True,
    )
    subprocess.run(
        ["bash", str(CONTROL), "--root", str(module_root), "--state-root", str(state_root), "initialize"],
        check=True,
    )
    private(state_root / "secrets" / "transport.key", "browser-transport-material\n")
    private(
        state_root / "trust" / "transport-trust.pem",
        "-----BEGIN CERTIFICATE-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n-----END CERTIFICATE-----\n",
    )
    private(
        state_root / "trust" / "transport-identity.commit",
        f"version=1\nspki_sha256={'cd' * 32}\n",
    )
    private(state_root / "trust" / "transport.pin", f"{'cd' * 32}\n")
    private(
        state_root / "profiles" / "direct.conf",
        "version=2\n"
        "role=DONOR\n"
        "profile_epoch=0\n"
        "dial_mode=DONOR_DIALS\n"
        "dial_endpoint=100.64.0.2\n"
        "listen_interface=192.168.1.2\n"
        f"peer_spki_sha256={'ab' * 32}\n"
        "transport=DIRECT\n",
    )
    daemon = root / "fake-daemon.sh"
    daemon.write_text("#!/bin/sh\nwhile :; do sleep 60; done\n", encoding="utf-8")
    daemon.chmod(0o700)
    supervisor = root / "fake-supervisor.sh"
    supervisor.write_text(
        "#!/bin/sh\n"
        '[ "$1" = --detach ] || exit 64\n'
        "shift\n"
        "RKA_INTERNAL_CHILD_LOOP=1 sh \"$@\" </dev/null >/dev/null 2>&1 &\n",
        encoding="utf-8",
    )
    supervisor.chmod(0o700)
    sidecar = root / "fake-sidecar.sh"
    sidecar.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = provision ]; then\n"
        "  printf '%s\\n' 'role=donor status=READY' 'RESULT=PROVISIONED'\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$1\" = synthetic-lease-renew ]; then\n"
        "  mkdir -p \"$RKA_STATE_ROOT/synthetic-leases\"\n"
        "  chmod 700 \"$RKA_STATE_ROOT/synthetic-leases\"\n"
        "  printf synthetic-lease-test > \"$RKA_STATE_ROOT/synthetic-leases/state.bin\"\n"
        "  chmod 600 \"$RKA_STATE_ROOT/synthetic-leases/state.bin\"\n"
        "  printf '%s\\n' 'synthetic_lease_issue_status=READY slot=CURRENT epoch=0 lease_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa record_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb certificate_count=5 valid_until_millis=1800000000000'\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$1\" = synthetic-lease-status ]; then\n"
        "  printf '%s\\n' 'synthetic_lease_status=ACTIVE' 'lease_epoch=0' 'lease_next=EMPTY' 'lease_valid_until_millis=1800000000000' 'lease_certificate_count=5'\n"
        "  exit 0\n"
        "fi\n"
        "[ \"$1\" = --role ] || exit 2\n"
        "profile_sha=$(sha256sum \"$RKA_PROFILE_PATH\" | awk '{print $1}') || exit 1\n"
        "pin=$(sed -n '7s/^peer_spki_sha256=//p' \"$RKA_PROFILE_PATH\") || exit 1\n"
        "pin_sha=$(printf %s \"$pin\" | xxd -r -p | sha256sum | awk '{print $1}') || exit 1\n"
        "printf 'version=1\\nprofile_sha256=%s\\nprofile_epoch=%s\\npeer_pin_sha256=%s\\ndial_mode=DONOR_DIALS\\ntransport=DIRECT\\n' \"$profile_sha\" \"$RKA_EXPECTED_PROFILE_EPOCH\" \"$pin_sha\" > \"$RKA_PROFILE_RECEIPT_PATH\"\n"
        "chmod 600 \"$RKA_PROFILE_RECEIPT_PATH\"\n"
        "exec python3 -c 'import os, socket, sys, time; s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); os.chmod(sys.argv[1], 0o600); s.listen(); time.sleep(3600)' \"$RKA_DONOR_SOCKET\"\n",
        encoding="utf-8",
    )
    sidecar.chmod(0o700)
    getprop = root / "fake-getprop.sh"
    getprop.write_text(
        "#!/bin/sh\n"
        "case $1 in\n"
        "remote_provisioning.enable_rkpd) printf '%s\\n' true ;;\n"
        "remote_provisioning.hostname) printf '%s\\n' remoteprovisioning.googleapis.com ;;\n"
        "ro.build.fingerprint) printf '%s\\n' brand/product/device:16/id/build:user/release-keys ;;\n"
        "*) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    getprop.chmod(0o700)
    rkpd_preferences = root / "com.android.rkpdapp.utils.preferences.xml"
    rkpd_preferences.write_text(
        '<?xml version="1.0" encoding="utf-8" standalone="yes" ?>\n'
        "<map>\n"
        '    <int name="settings_id" value="4242" />\n'
        "</map>\n",
        encoding="ascii",
    )
    pm = root / "fake-pm.sh"
    pm.write_text(
        "#!/bin/sh\n"
        '[ "$*" = "list packages --show-versioncode com.android.rkpdapp" ] || exit 2\n'
        "printf '%s\\n' 'package:com.android.rkpdapp versionCode:42'\n",
        encoding="ascii",
    )
    pm.chmod(0o700)
    return module_root, state_root, {
        "RKA_DAEMON": str(daemon),
        "RKA_GETPROP": str(getprop),
        "RKA_NATIVE_SUPERVISOR": str(supervisor),
        "RKA_PM": str(pm),
        "RKA_RKPD_PREFERENCES": str(rkpd_preferences),
        "RKA_SIDECAR": str(sidecar),
        "RKA_SOCKET_DIRECTORY_CONTEXT": "?",
        "RKA_SOCKET_CONTEXT": "?",
        "RKA_STABLE_SECONDS": "60",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--nonce-file", type=Path, required=True)
    arguments = parser.parse_args()
    root = arguments.root.resolve() / f"run-{os.getpid()}"
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    root.chmod(0o700)
    server = WebUiServer(("127.0.0.1", arguments.port), Handler)
    server.runtime_states = RuntimeStateStore(root, initialize)
    arguments.nonce_file.parent.mkdir(parents=True, exist_ok=True)
    arguments.nonce_file.write_text(str(os.getpid()), encoding="utf-8")
    try:
        server.serve_forever()
    finally:
        server.runtime_states.close()
        server.server_close()


if __name__ == "__main__":
    main()
