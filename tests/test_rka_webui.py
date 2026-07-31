from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
import os
from pathlib import Path
from subprocess import CompletedProcess, run
from tempfile import TemporaryDirectory
import threading
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTROL_SCRIPT = REPOSITORY_ROOT / "module" / "rka-control.sh"
WEBROOT = REPOSITORY_ROOT / "module" / "webroot"
FIXED_ACTIONS = (
    "status",
    "role-donor",
    "role-candidate",
    "pair-direct",
    "rotate-pairing",
    "start",
    "stop",
    "recover-keystore2",
    "export-audit",
    "export-evidence",
    "quarantine",
    "cleanup",
)


class ActionParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.actions: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "button":
            return
        action = dict(attrs).get("data-action")
        if action is not None:
            self.actions.append(action)


class RkaWebUiTest(unittest.TestCase):
    def run_control(
        self, config_root: Path, state_root: Path, *arguments: str
    ) -> CompletedProcess[str]:
        return run(
            [
                "bash",
                str(CONTROL_SCRIPT),
                "--root",
                str(config_root),
                "--state-root",
                str(state_root),
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def initialize(self, config_root: Path, state_root: Path, role: str = "DONOR") -> None:
        self.assertEqual(self.run_control(config_root, state_root, "set-role", role).returncode, 0)
        self.assertEqual(self.run_control(config_root, state_root, "initialize").returncode, 0)

    def open_webui(self, config_root: Path, state_root: Path) -> str:
        opened = self.run_control(config_root, state_root, "webui-open")
        self.assertEqual(opened.returncode, 0, opened.stderr)
        return self.field(opened.stdout, "nonce")

    def field(self, output: str, name: str) -> str:
        return next(
            line.removeprefix(f"{name}=")
            for line in output.splitlines()
            if line.startswith(f"{name}=")
        )

    def mutate(
        self, config_root: Path, state_root: Path, action: str, nonce: str
    ) -> tuple[CompletedProcess[str], str]:
        result = self.run_control(config_root, state_root, "webui", action, nonce)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result, self.field(result.stdout, "next_nonce")

    def write_private(self, path: Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")
        os.chmod(path, 0o600)

    def write_ready_pairing(self, state_root: Path) -> None:
        self.write_private(
            state_root / "profiles" / "webui-status.conf",
            "version=1\n"
            "pairing=PAIRED\n"
            "direct_profile=DIRECT_NETWORK\n"
            "direct_readiness=READY\n"
            "diagnostic=DIAGNOSTIC_ONLY\n",
        )

    def test_status_renders_validated_ready_pairing_without_secret_or_path(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.initialize(config_root, state_root)
            self.write_ready_pairing(state_root)
            self.write_private(
                state_root / "secrets" / "transport.key", "sensitive-material-must-not-render\n"
            )
            nonce = self.open_webui(config_root, state_root)
            result = self.run_control(config_root, state_root, "webui", "status", nonce)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("role=DONOR", result.stdout)
        self.assertIn("phone_role=PHONE_A_DONOR", result.stdout)
        self.assertIn("direct_profile=DIRECT_NETWORK", result.stdout)
        self.assertIn("direct_readiness=READY", result.stdout)
        self.assertIn("pairing=PAIRED", result.stdout)
        self.assertIn("diagnostic=DIAGNOSTIC_ONLY", result.stdout)
        self.assertNotIn("sensitive-material-must-not-render", result.stdout)
        self.assertNotIn(str(state_root), result.stdout)

    def test_status_rejects_malformed_or_cross_role_state(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.initialize(config_root, state_root)
            self.write_private(
                state_root / "profiles" / "webui-status.conf",
                "version=1\npairing=PAIRED\ndirect_profile=DIRECT_NETWORK\n"
                "direct_readiness=NOT_READY\ndiagnostic=DIAGNOSTIC_ONLY\n",
            )
            malformed = self.run_control(
                config_root, state_root, "webui", "status", self.open_webui(config_root, state_root)
            )
            self.write_ready_pairing(state_root)
            self.write_private(
                state_root / "profiles" / "active.conf",
                "version=1\nrole=CANDIDATE\nprofile_epoch=0\n",
            )
            cross_role = self.run_control(
                config_root, state_root, "webui", "status", self.open_webui(config_root, state_root)
            )

        self.assertEqual(malformed.stdout, "WEBUI_INVALID_REQUEST\n")
        self.assertNotEqual(malformed.returncode, 0)
        self.assertEqual(cross_role.stdout, "WEBUI_INVALID_REQUEST\n")
        self.assertNotEqual(cross_role.returncode, 0)

    def test_nonce_is_single_use_under_twenty_way_concurrency(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.initialize(config_root, state_root)
            nonce = self.open_webui(config_root, state_root)
            barrier = threading.Barrier(20)

            def request() -> CompletedProcess[str]:
                barrier.wait()
                return self.run_control(config_root, state_root, "webui", "pair-direct", nonce)

            with ThreadPoolExecutor(max_workers=20) as executor:
                results = list(executor.map(lambda _: request(), range(20)))

        successes = [result for result in results if result.returncode == 0]
        self.assertEqual(len(successes), 1)
        self.assertIn("next_nonce=", successes[0].stdout)
        self.assertIn("pairing=PENDING", successes[0].stdout)
        self.assertIn("direct_profile=DIRECT_NETWORK", successes[0].stdout)
        self.assertIn("direct_readiness=NOT_READY", successes[0].stdout)
        for result in results:
            if result.returncode != 0:
                self.assertEqual(result.stdout, "WEBUI_INVALID_REQUEST\n")

    def test_role_change_updates_root_role_and_active_profile_before_start_contract(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.initialize(config_root, state_root)
            changed, nonce = self.mutate(
                config_root, state_root, "role-candidate", self.open_webui(config_root, state_root)
            )
            active_profile = (state_root / "profiles" / "active.conf").read_text(encoding="utf-8")
            root_role = (config_root / "rka" / "role.conf").read_text(encoding="utf-8")
            started = self.run_control(config_root, state_root, "webui", "start", nonce)

        self.assertIn("role=CANDIDATE", changed.stdout)
        self.assertIn("role=CANDIDATE", active_profile)
        self.assertIn("role=CANDIDATE", root_role)
        self.assertNotEqual(started.returncode, 0)
        self.assertEqual(started.stdout, "WEBUI_INVALID_REQUEST\n")

    def test_fixed_dom_actions_execute_their_command_contracts(self) -> None:
        parser = ActionParser()
        parser.feed((WEBROOT / "index.html").read_text(encoding="utf-8"))
        self.assertEqual(tuple(parser.actions), FIXED_ACTIONS)
        app = (WEBROOT / "app.js").read_text(encoding="utf-8")
        self.assertIn("textContent", app)
        self.assertNotIn("innerHTML", app)

        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.initialize(config_root, state_root)
            self.write_ready_pairing(state_root)
            nonce = self.open_webui(config_root, state_root)
            status = self.run_control(config_root, state_root, "webui", "status", nonce)
            _, nonce = self.mutate(config_root, state_root, "role-donor", nonce)
            _, nonce = self.mutate(config_root, state_root, "role-candidate", nonce)
            _, nonce = self.mutate(config_root, state_root, "pair-direct", nonce)
            _, nonce = self.mutate(config_root, state_root, "rotate-pairing", nonce)
            start = self.run_control(config_root, state_root, "webui", "start", nonce)
            self.assertNotEqual(start.returncode, 0)
            nonce = self.open_webui(config_root, state_root)
            _, nonce = self.mutate(config_root, state_root, "stop", nonce)
            recovery, nonce = self.mutate(config_root, state_root, "recover-keystore2", nonce)
            audit, nonce = self.mutate(config_root, state_root, "export-audit", nonce)
            evidence, nonce = self.mutate(config_root, state_root, "export-evidence", nonce)
            quarantine = self.run_control(config_root, state_root, "webui", "quarantine", nonce)
            _, _ = self.mutate(config_root, state_root, "cleanup", nonce)
            audit_export = (state_root / "sidecar" / "audit" / "audit-export.txt").read_text(
                encoding="utf-8"
            )
            evidence_export = (state_root / "sidecar" / "audit" / "evidence-export.txt").read_text(
                encoding="utf-8"
            )

        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("recovery_target=KEYSTORE2", recovery.stdout)
        self.assertIn("audit_export=REDACTED_READY", audit.stdout)
        self.assertIn("evidence_export=REDACTED_READY", evidence.stdout)
        self.assertEqual(quarantine.returncode, 0, quarantine.stderr)
        for export in (audit_export, evidence_export):
            self.assertLessEqual(len(export.encode("utf-8")), 512)
            self.assertNotIn("transport.key", export)
            self.assertNotIn(str(state_root), export)
            self.assertIn("pairing=PAIRED", export)

    def test_rejects_arbitrary_action_and_bad_nonce_without_command_evaluation(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.initialize(config_root, state_root)
            nonce = self.open_webui(config_root, state_root)
            arbitrary = self.run_control(config_root, state_root, "webui", "$(id)", nonce)
            invalid_nonce = self.run_control(config_root, state_root, "webui", "status", "bad")

        self.assertEqual(arbitrary.stdout, "WEBUI_INVALID_REQUEST\n")
        self.assertNotEqual(arbitrary.returncode, 0)
        self.assertEqual(invalid_nonce.stdout, "WEBUI_INVALID_REQUEST\n")
        self.assertNotEqual(invalid_nonce.returncode, 0)

    def test_packaged_surface_has_no_reboot_shell_escape_or_sensitive_literals(self) -> None:
        product_text = "\n".join(
            path.read_text(encoding="utf-8") for path in WEBROOT.rglob("*") if path.is_file()
        ).lower()
        for forbidden in ("reboot", "killall", "private key", "device serial"):
            self.assertNotIn(forbidden, product_text)
        self.assertNotIn("eval(", product_text)


if __name__ == "__main__":
    unittest.main()
