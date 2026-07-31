from __future__ import annotations

import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shlex
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
    runtime = root / "fake-runtime.sh"
    runtime.write_text("#!/bin/sh\nwhile :; do sleep 60; done\n", encoding="utf-8")
    runtime.chmod(0o700)
    return module_root, state_root, {
        "RKA_DAEMON": str(runtime),
        "RKA_SIDECAR": str(runtime),
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
    arguments.nonce_file.parent.mkdir(parents=True, exist_ok=True)
    arguments.nonce_file.write_text(str(os.getpid()), encoding="utf-8")
    server.serve_forever()


if __name__ == "__main__":
    main()
