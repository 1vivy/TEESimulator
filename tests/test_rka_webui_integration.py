from __future__ import annotations

import os
from pathlib import Path
from subprocess import CompletedProcess, run
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONTROL = Path(os.environ.get("RKA_CONTROL_SCRIPT", ROOT / "module" / "rka-control.sh"))


class LiveWebUiIntegrationTest(unittest.TestCase):
    def control(
        self,
        root: Path,
        state: Path,
        *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> CompletedProcess[str]:
        return run(
            ["bash", str(CONTROL), "--root", str(root), "--state-root", str(state), *arguments],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, **(environment or {})},
        )

    def test_missing_sentinel_and_arbitrary_recovery_are_blocked(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            root, state = base / "module", base / "state"
            self.assertEqual(self.control(root, state, "set-role", "DONOR").returncode, 0)
            self.assertEqual(self.control(root, state, "initialize").returncode, 0)
            nonce = self.control(root, state, "webui-open").stdout.split("=", 1)[1].strip()
            (state / "run" / "boot-continuity.state").unlink()
            missing = self.control(root, state, "webui", "recover-rkpd", nonce)
            (state / "profiles" / "recovery.conf").write_text(
                "version=1\nkeystore2_name=keystore2\n"
                "keystore2_executable=/system/bin/keystore2\nkeystore2_restart=keystore2\n"
                "rkpd_name=rkpd\nrkpd_executable=/system/bin/rkpd\nrkpd_restart=rkpd\n"
                "rkpd_property_one=persist.rkpd.a\nrkpd_property_two=persist.rkpd.b\n",
                encoding="utf-8",
            )
            (state / "profiles" / "recovery.conf").chmod(0o600)
            proc = base / "proc" / "42"
            proc.mkdir(parents=True)
            (proc / "stat").write_text(
                "42 (keystore2) S 1 42 42 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 777 0\n",
                encoding="utf-8",
            )
            (proc / "exe").symlink_to("/system/bin/keystore2")
            pidof = base / "pidof"
            pidof.write_text("#!/bin/sh\nprintf '42\\n'\n", encoding="utf-8")
            pidof.chmod(0o700)
            boot = base / "boot"
            uptime = base / "uptime"
            boot.write_text("test-boot\n", encoding="utf-8")
            uptime.write_text("10.00 1.00\n", encoding="utf-8")
            (state / "run" / "boot-continuity.state").write_text(
                "version=1\nsentinel_id=00000000000000000000000000000000\n"
                "boot_id=test-boot\nsample_ms=1\n",
                encoding="utf-8",
            )
            (state / "run" / "boot-continuity.state").chmod(0o600)
            (state / "quarantine" / "entry").write_text("q\n", encoding="utf-8")
            (state / "quarantine" / "entry").chmod(0o600)
            environment = {
                "RKA_RECOVERY_PIDOF": str(pidof),
                "RKA_RECOVERY_PROC_ROOT": str(base / "proc"),
                "RKA_RECOVERY_BOOT_ID_PATH": str(boot),
                "RKA_RECOVERY_UPTIME_PATH": str(uptime),
            }
            arbitrary = self.control(
                root, state, "recover-exact", "snapshot", "system_server",
                environment=environment,
            )
        self.assertNotEqual(missing.returncode, 0)
        self.assertNotEqual(arbitrary.returncode, 0)

    def test_confirmation_nonce_is_single_use(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            root, state = base / "module", base / "state"
            self.control(root, state, "set-role", "DONOR")
            self.control(root, state, "initialize")
            nonce = self.control(root, state, "webui-open").stdout.split("=", 1)[1].strip()
            prepared = self.control(root, state, "webui", "cleanup", nonce)
            values = dict(line.split("=", 1) for line in prepared.stdout.splitlines() if "=" in line)
            first = self.control(root, state, "webui", "cleanup", values["next_nonce"], values["confirmation_token"])
            replay = self.control(root, state, "webui", "cleanup", values["next_nonce"], values["confirmation_token"])
        self.assertEqual(first.returncode, 0)
        self.assertNotEqual(replay.returncode, 0)

    def test_mutation_nonce_cannot_be_replayed_sequentially(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            root, state = base / "module", base / "state"
            self.control(root, state, "set-role", "DONOR")
            self.control(root, state, "initialize")
            nonce = self.control(root, state, "webui-open").stdout.split("=", 1)[1].strip()
            first = self.control(root, state, "webui", "pair-direct", nonce)
            replay = self.control(root, state, "webui", "pair-direct", nonce)
        self.assertEqual(first.returncode, 0)
        self.assertNotEqual(replay.returncode, 0)

    def test_root_rotation_overlap_and_signed_no_overlap(self) -> None:
        cases = (
            ("overlap", "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc", False),
            ("unsigned-no-overlap", "3" * 64, False),
            ("signed-no-overlap", "3" * 64, True),
        )
        for name, pin, signed in cases:
            with self.subTest(name=name), TemporaryDirectory() as directory:
                base = Path(directory)
                root, state = base / "module", base / "state"
                self.control(root, state, "set-role", "DONOR")
                self.control(root, state, "initialize")
                fetch = base / "fetch"
                fetch.write_text(
                    f"#!/bin/sh\nprintf 'version=1\\nepoch=1\\npin={pin}\\n'\n",
                    encoding="utf-8",
                )
                fetch.chmod(0o700)
                sidecar = base / "sidecar"
                sidecar.write_text(
                    "#!/bin/sh\n"
                    'if [ "$1" = rotate-roots ]; then cp "$RKA_STATE_ROOT/trust/root-bundle.next" '
                    '"$RKA_STATE_ROOT/trust/root-bundle.active"; else printf "1\\n"; fi\n',
                    encoding="utf-8",
                )
                sidecar.chmod(0o700)
                if signed:
                    signed_bundle = root / "rka-root-bundle.signed"
                    signed_bundle.write_text(
                        f"version=1\nepoch=1\npin={pin}\nauthorization={'0' * 64}\n",
                        encoding="utf-8",
                    )
                    signed_bundle.chmod(0o600)
                    (root / "rka-root-bundle.signed.sig").write_text("signed\n", encoding="utf-8")
                    (root / "rka-root-bundle.signed.sig").chmod(0o600)
                    verifier = root / "rka-agent-pgp-verify.sh"
                    verifier.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                    verifier.chmod(0o700)
                nonce = self.control(root, state, "webui-open").stdout.split("=", 1)[1].strip()
                environment = {"RKA_ROOT_FETCH": str(fetch), "RKA_SIDECAR": str(sidecar)}
                prepared = self.control(
                    root, state, "webui", "rotate-attestation-roots", nonce,
                    environment=environment,
                )
                values = dict(
                    line.split("=", 1) for line in prepared.stdout.splitlines() if "=" in line
                )
                if name == "unsigned-no-overlap":
                    self.assertNotEqual(prepared.returncode, 0)
                    self.assertFalse((state / "trust" / "root-bundle.next").exists())
                    continue
                self.assertEqual(prepared.returncode, 0, prepared.stdout)
                expected_overlap = "NO_OVERLAP" if signed else "OVERLAP"
                self.assertEqual(values["root_overlap"], expected_overlap)
                applied = self.control(
                    root,
                    state,
                    "webui",
                    "rotate-attestation-roots",
                    values["next_nonce"],
                    values["confirmation_token"],
                    environment=environment,
                )
                self.assertEqual(applied.returncode, 0, applied.stdout)
                self.assertIn("profile_epoch=1", applied.stdout)


if __name__ == "__main__":
    unittest.main()
