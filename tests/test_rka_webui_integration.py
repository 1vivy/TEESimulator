from __future__ import annotations

import os
from pathlib import Path
import socket
from subprocess import CompletedProcess, run
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONTROL = Path(os.environ.get("RKA_CONTROL_SCRIPT", ROOT / "module" / "rka-control.sh"))
AGENT_PGP_TOOL = ROOT / "module" / "rka-agent-pgp-verify"
AGENT_PGP_ANCHOR = ROOT / "module" / "rka-agent-pgp-public.gpg"


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

    def test_no_overlap_verifier_is_package_owned(self) -> None:
        control_source = CONTROL.read_text(encoding="utf-8")

        self.assertTrue(AGENT_PGP_TOOL.is_file())
        self.assertTrue(AGENT_PGP_ANCHOR.is_file())
        self.assertIn("webui_verifier=$script_directory/rka-agent-pgp-verify", control_source)
        self.assertIn("webui_agent_anchor=$script_directory/rka-agent-pgp-public.gpg", control_source)
        self.assertNotIn("$root/rka-agent-pgp-verify.sh", control_source)

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

    def test_donor_rkp_provisioning_requires_confirmation_and_updates_status(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            root, state = base / "module", base / "state"
            self.assertEqual(self.control(root, state, "set-role", "DONOR").returncode, 0)
            self.assertEqual(self.control(root, state, "initialize").returncode, 0)
            (state / "profiles" / "direct.conf").write_text(
                "version=2\n"
                "role=DONOR\n"
                "profile_epoch=0\n"
                "dial_mode=DONOR_DIALS\n"
                "dial_endpoint=100.64.0.2\n"
                "listen_interface=192.168.1.2\n"
                f"peer_spki_sha256={'ab' * 32}\n"
                "transport=DIRECT\n",
                encoding="ascii",
            )
            (state / "profiles" / "direct.conf").chmod(0o600)
            commands = base / "commands"
            commands.mkdir()
            getprop = commands / "getprop"
            getprop.write_text(
                "#!/bin/sh\n"
                "case $1 in\n"
                "remote_provisioning.enable_rkpd) printf '%s\\n' true ;;\n"
                "remote_provisioning.hostname) printf '%s\\n' remoteprovisioning.googleapis.com ;;\n"
                "ro.build.fingerprint) printf '%s\\n' brand/product/device:16/id/build:user/release-keys ;;\n"
                "*) exit 1 ;;\n"
                "esac\n",
                encoding="ascii",
            )
            rkpd_preferences = base / "com.android.rkpdapp.utils.preferences.xml"
            rkpd_preferences.write_text(
                '<?xml version="1.0" encoding="utf-8" standalone="yes" ?>\n'
                "<map>\n"
                '    <int name="settings_id" value="4242" />\n'
                "</map>\n",
                encoding="ascii",
            )
            pm = commands / "pm"
            pm.write_text(
                "#!/bin/sh\n"
                '[ "$*" = "list packages --show-versioncode com.android.rkpdapp" ] || exit 2\n'
                "printf '%s\\n' 'package:com.android.rkpdapp versionCode:42'\n",
                encoding="ascii",
            )
            sidecar = commands / "rka-sidecar"
            sidecar.write_text(
                "#!/bin/sh\n"
                "[ \"$1\" = provision ] || exit 2\n"
                "printf '%s\\n' 'role=donor status=READY' 'RESULT=PROVISIONED'\n",
                encoding="ascii",
            )
            getprop.chmod(0o700)
            pm.chmod(0o700)
            sidecar.chmod(0o700)
            environment = {
                "RKA_GETPROP": str(getprop),
                "RKA_PM": str(pm),
                "RKA_RKPD_PREFERENCES": str(rkpd_preferences),
                "RKA_SIDECAR": str(sidecar),
            }
            broker_socket = state / "run" / "sockets" / "broker.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(broker_socket))
                broker_socket.chmod(0o600)
                nonce = self.control(
                    root, state, "webui-open", environment=environment,
                ).stdout.split("=", 1)[1].strip()
                prepared = self.control(
                    root, state, "webui", "provision-rkp", nonce, environment=environment,
                )
                values = dict(
                    line.split("=", 1) for line in prepared.stdout.splitlines() if "=" in line
                )
                applied = self.control(
                    root,
                    state,
                    "webui",
                    "provision-rkp",
                    values["next_nonce"],
                    values["confirmation_token"],
                    environment=environment,
                )

        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        self.assertEqual(values["confirmation_action"], "provision-rkp")
        self.assertEqual(applied.returncode, 0, applied.stdout)
        self.assertIn("rkp_provisioning=PROVISIONED", applied.stdout)

    def test_candidate_lease_renewal_is_confirmed_persisted_and_redacted(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            root, state = base / "module", base / "state"
            self.assertEqual(self.control(root, state, "set-role", "CANDIDATE").returncode, 0)
            self.assertEqual(self.control(root, state, "initialize").returncode, 0)

            def private(path: Path, contents: str) -> None:
                path.write_text(contents, encoding="ascii")
                path.chmod(0o600)

            private(
                state / "profiles" / "direct.conf",
                "version=2\n"
                "role=CANDIDATE\n"
                "profile_epoch=0\n"
                "dial_mode=CANDIDATE_DIALS\n"
                "dial_endpoint=100.64.0.2\n"
                "listen_interface=192.168.1.2\n"
                f"peer_spki_sha256={'ab' * 32}\n"
                "transport=DIRECT\n",
            )
            private(state / "profiles" / "pair.request", "version=1\naction=PAIR_DIRECT\n")
            private(state / "secrets" / "transport.key", "candidate-transport-key\n")
            private(
                state / "trust" / "transport-trust.pem",
                "-----BEGIN CERTIFICATE-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n"
                "-----END CERTIFICATE-----\n",
            )
            private(state / "run" / "supervisor.state", "RUNNING\n")
            boot_id = base / "boot-id"
            boot_id.write_text("test-boot\n", encoding="ascii")
            private(
                state / "run" / "boot-continuity.state",
                "version=1\nsentinel_id=00000000000000000000000000000000\n"
                "boot_id=test-boot\nsample_ms=1\n",
            )
            sidecar = base / "rka-sidecar"
            sidecar.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = synthetic-lease-renew ]; then\n"
                "  mkdir -p \"$RKA_STATE_ROOT/synthetic-leases\"\n"
                "  chmod 700 \"$RKA_STATE_ROOT/synthetic-leases\"\n"
                "  printf lease > \"$RKA_STATE_ROOT/synthetic-leases/state.bin\"\n"
                "  chmod 600 \"$RKA_STATE_ROOT/synthetic-leases/state.bin\"\n"
                "  printf '%s\\n' 'synthetic_lease_issue_status=READY slot=CURRENT epoch=4 lease_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa record_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb certificate_count=5 valid_until_millis=1800000000000'\n"
                "elif [ \"$1\" = synthetic-lease-status ]; then\n"
                "  printf '%s\\n' 'synthetic_lease_status=ACTIVE' 'lease_epoch=4' 'lease_next=EMPTY' 'lease_valid_until_millis=1800000000000' 'lease_certificate_count=5'\n"
                "else\n"
                "  exit 2\n"
                "fi\n",
                encoding="ascii",
            )
            sidecar.chmod(0o700)
            environment = {
                "RKA_RECOVERY_BOOT_ID_PATH": str(boot_id),
                "RKA_SIDECAR": str(sidecar),
            }
            broker_socket = state / "run" / "sockets" / "broker.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(broker_socket))
                broker_socket.chmod(0o600)
                nonce = self.control(
                    root, state, "webui-open", environment=environment,
                ).stdout.split("=", 1)[1].strip()
                prepared = self.control(
                    root,
                    state,
                    "webui",
                    "renew-synthetic-lease",
                    nonce,
                    environment=environment,
                )
                values = dict(
                    line.split("=", 1) for line in prepared.stdout.splitlines() if "=" in line
                )
                applied = self.control(
                    root,
                    state,
                    "webui",
                    "renew-synthetic-lease",
                    values["next_nonce"],
                    values["confirmation_token"],
                    environment=environment,
                )

        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        self.assertEqual(values["confirmation_action"], "renew-synthetic-lease")
        self.assertIn("synthetic_lease=NOT_READY", prepared.stdout)
        self.assertEqual(applied.returncode, 0, applied.stdout)
        self.assertIn("synthetic_lease_renewal=READY", applied.stdout)
        self.assertIn("synthetic_lease=ACTIVE", applied.stdout)
        self.assertIn("lease_epoch=4", applied.stdout)
        self.assertIn("lease_next=EMPTY", applied.stdout)
        self.assertNotIn("lease_id=", applied.stdout)
        self.assertNotIn("record_sha256=", applied.stdout)

    def test_root_rotation_overlap_and_signed_no_overlap(self) -> None:
        cases = (
            ("overlap", "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc"),
            ("unsigned-no-overlap", "3" * 64),
        )
        for name, pin in cases:
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
                self.assertEqual(values["root_overlap"], "OVERLAP")
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
