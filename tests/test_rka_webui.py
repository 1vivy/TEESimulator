from __future__ import annotations

import os
from pathlib import Path
from subprocess import CompletedProcess, run
from tempfile import TemporaryDirectory
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTROL_SCRIPT = REPOSITORY_ROOT / "module" / "rka-control.sh"
WEBROOT = REPOSITORY_ROOT / "module" / "webroot"


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

    def open_webui(self, config_root: Path, state_root: Path) -> str:
        opened = self.run_control(config_root, state_root, "webui-open")
        self.assertEqual(opened.returncode, 0, opened.stderr)
        nonce_line = next(line for line in opened.stdout.splitlines() if line.startswith("nonce="))
        return nonce_line.removeprefix("nonce=")

    def test_paired_donor_status(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.assertEqual(
                self.run_control(config_root, state_root, "set-role", "DONOR").returncode, 0
            )
            self.assertEqual(
                self.run_control(config_root, state_root, "initialize").returncode, 0
            )
            (state_root / "secrets" / "transport.key").write_text(
                "sensitive-material-must-not-render", encoding="utf-8"
            )
            os.chmod(state_root / "secrets" / "transport.key", 0o600)
            nonce = self.open_webui(config_root, state_root)
            result = self.run_control(config_root, state_root, "webui", "status", nonce)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("role=DONOR", result.stdout)
        self.assertIn("phone_role=PHONE_A_DONOR", result.stdout)
        self.assertIn("profile_epoch=0", result.stdout)
        self.assertIn("direct_profile=DIRECT_NETWORK", result.stdout)
        self.assertIn("direct_readiness=NOT_READY", result.stdout)
        self.assertIn("sentinel=NOT_READY", result.stdout)
        self.assertIn("quarantine_count=0", result.stdout)
        self.assertIn("diagnostic=DIAGNOSTIC_ONLY", result.stdout)
        self.assertNotIn("sensitive-material-must-not-render", result.stdout)
        self.assertNotIn(str(state_root), result.stdout)

    def test_every_action_has_a_fixed_dom_contract(self) -> None:
        document = "\n".join(
            (WEBROOT / name).read_text(encoding="utf-8") for name in ("index.html", "app.js")
        )
        for action in (
            "status",
            "role-donor",
            "role-candidate",
            "pair-direct",
            "rotate-pairing",
            "start",
            "stop",
            "recover-keystore2",
            "export-audit",
            "cleanup",
            "quarantine",
        ):
            self.assertIn(f'data-action="{action}"', document)
        self.assertIn("textContent", document)
        self.assertNotIn("innerHTML", document)

    def test_rejects_arbitrary_command(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.assertEqual(
                self.run_control(config_root, state_root, "set-role", "DONOR").returncode, 0
            )
            self.assertEqual(
                self.run_control(config_root, state_root, "initialize").returncode, 0
            )
            nonce = self.open_webui(config_root, state_root)
            result = self.run_control(config_root, state_root, "webui", "$(id)", nonce)
            invalid_nonce = self.run_control(config_root, state_root, "webui", "status", "bad")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "WEBUI_INVALID_REQUEST\n")
        self.assertNotEqual(invalid_nonce.returncode, 0)
        self.assertEqual(invalid_nonce.stdout, "WEBUI_INVALID_REQUEST\n")

    def test_has_no_reboot_action(self) -> None:
        product_text = "\n".join(
            path.read_text(encoding="utf-8") for path in WEBROOT.rglob("*") if path.is_file()
        )
        self.assertNotIn("reboot", product_text.lower())

    def test_request_schema_rotates_nonce_and_keeps_diagnostics_nonproduction(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.assertEqual(
                self.run_control(config_root, state_root, "set-role", "DONOR").returncode, 0
            )
            self.assertEqual(
                self.run_control(config_root, state_root, "initialize").returncode, 0
            )
            nonce = self.open_webui(config_root, state_root)
            recovery = self.run_control(
                config_root, state_root, "webui", "recover-keystore2", nonce
            )
            replay = self.run_control(
                config_root, state_root, "webui", "recover-keystore2", nonce
            )

        self.assertEqual(recovery.returncode, 0, recovery.stderr)
        self.assertIn("recovery_target=KEYSTORE2", recovery.stdout)
        self.assertIn("next_nonce=", recovery.stdout)
        self.assertNotEqual(replay.returncode, 0)
        self.assertEqual(replay.stdout, "WEBUI_INVALID_REQUEST\n")

    def test_fixed_role_and_pairing_requests_accept_only_the_issued_nonce(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.assertEqual(
                self.run_control(config_root, state_root, "set-role", "DONOR").returncode, 0
            )
            self.assertEqual(
                self.run_control(config_root, state_root, "initialize").returncode, 0
            )
            nonce = self.open_webui(config_root, state_root)
            role = self.run_control(config_root, state_root, "webui", "role-candidate", nonce)
            next_nonce = next(
                line.removeprefix("next_nonce=")
                for line in role.stdout.splitlines()
                if line.startswith("next_nonce=")
            )
            pairing = self.run_control(
                config_root, state_root, "webui", "pair-direct", next_nonce
            )

        self.assertEqual(role.returncode, 0, role.stderr)
        self.assertIn("role=CANDIDATE", role.stdout)
        self.assertEqual(pairing.returncode, 0, pairing.stderr)
        self.assertIn("pairing=UNPAIRED", pairing.stdout)

    def test_packaged_surface_has_no_shell_escape_or_sensitive_literals(self) -> None:
        product_text = "\n".join(
            path.read_text(encoding="utf-8") for path in WEBROOT.rglob("*") if path.is_file()
        ).lower()
        for forbidden in ("killall", "private key", "device serial"):
            self.assertNotIn(forbidden, product_text)
        self.assertNotIn("eval(", product_text)


if __name__ == "__main__":
    unittest.main()
