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


REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
CONTROL: Final = REPOSITORY_ROOT / "module" / "rka-control.sh"
WEBROOT: Final = Path(os.environ.get("RKA_WEBROOT", REPOSITORY_ROOT / "module" / "webroot"))
PUBLIC_CONTROL: Final = "/data/adb/modules/tricky_store/rka-control.sh"


class Handler(SimpleHTTPRequestHandler):
    server: "WebUiServer"

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, directory=str(WEBROOT), **kwargs)

    def do_POST(self) -> None:
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
        result = subprocess.run(
            [
                "bash",
                str(CONTROL),
                "--root",
                str(self.server.module_root),
                "--state-root",
                str(self.server.state_root),
                *arguments[1:],
            ],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, **self.server.runtime_environment},
        )
        self.send_json({"errno": result.returncode, "stdout": result.stdout})

    def send_json(self, value: dict[str, int | str]) -> None:
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class WebUiServer(ThreadingHTTPServer):
    module_root: Path
    state_root: Path
    runtime_environment: dict[str, str]
    broker_socket: socket.socket


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
    sidecar = root / "fake-sidecar.sh"
    sidecar.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = provision ]; then\n"
        "  printf '%s\\n' 'role=donor status=READY' 'RESULT=PROVISIONED'\n"
        "  exit 0\n"
        "fi\n"
        "[ \"$1\" = --role ] || exit 2\n"
        "profile_sha=$(sha256sum \"$RKA_PROFILE_PATH\" | awk '{print $1}') || exit 1\n"
        "pin=$(sed -n '7s/^peer_spki_sha256=//p' \"$RKA_PROFILE_PATH\") || exit 1\n"
        "pin_sha=$(printf %s \"$pin\" | xxd -r -p | sha256sum | awk '{print $1}') || exit 1\n"
        "printf 'version=1\\nprofile_sha256=%s\\nprofile_epoch=%s\\npeer_pin_sha256=%s\\ndial_mode=DONOR_DIALS\\ntransport=DIRECT\\n' \"$profile_sha\" \"$RKA_EXPECTED_PROFILE_EPOCH\" \"$pin_sha\" > \"$RKA_PROFILE_RECEIPT_PATH\"\n"
        "chmod 600 \"$RKA_PROFILE_RECEIPT_PATH\"\n"
        "while :; do sleep 60; done\n",
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
    return module_root, state_root, {
        "RKA_DAEMON": str(daemon),
        "RKA_GETPROP": str(getprop),
        "RKA_SIDECAR": str(sidecar),
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
    module_root, state_root, environment = initialize(root)
    server = WebUiServer(("127.0.0.1", arguments.port), Handler)
    server.module_root = module_root
    server.state_root = state_root
    server.runtime_environment = environment
    server.broker_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    broker_path = state_root / "run" / "sockets" / "broker.sock"
    server.broker_socket.bind(str(broker_path))
    broker_path.chmod(0o600)
    arguments.nonce_file.parent.mkdir(parents=True, exist_ok=True)
    arguments.nonce_file.write_text(str(os.getpid()), encoding="utf-8")
    server.serve_forever()


if __name__ == "__main__":
    main()
