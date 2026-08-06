from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
from subprocess import CompletedProcess, run
from tempfile import TemporaryDirectory
import threading
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTROL_SCRIPT = REPOSITORY_ROOT / "module" / "rka-control.sh"
WEBROOT = REPOSITORY_ROOT / "module" / "webroot"
BROWSER_HARNESS = REPOSITORY_ROOT / "tests" / "webui_browser_harness.mjs"
FIXED_ACTIONS = (
    "status",
    "role-donor",
    "provision-rkp",
    "role-candidate",
    "pair-direct",
    "rotate-pairing",
    "start",
    "stop",
    "rotate-attestation-roots",
    "recover-keystore2",
    "recover-rkpd",
    "export-audit",
    "export-evidence",
    "quarantine",
    "cleanup",
)


class RkaWebUiTest(unittest.TestCase):
    def run_control(
        self,
        config_root: Path,
        state_root: Path,
        *arguments: str,
        environment: dict[str, str] | None = None,
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
            env={**os.environ, **(environment or {})},
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
        self,
        config_root: Path,
        state_root: Path,
        action: str,
        nonce: str,
        environment: dict[str, str] | None = None,
    ) -> tuple[CompletedProcess[str], str]:
        result = self.run_control(
            config_root, state_root, "webui", action, nonce, environment=environment
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result, self.field(result.stdout, "next_nonce")

    def write_private(self, path: Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")
        os.chmod(path, 0o600)

    def write_live_transport_sources(self, state_root: Path) -> None:
        role = next(
            line.removeprefix("role=")
            for line in (state_root / "profiles" / "active.conf").read_text(encoding="utf-8").splitlines()
            if line.startswith("role=")
        )
        self.write_private(
            state_root / "secrets" / "transport.key", "test-transport-key-material\n"
        )
        self.write_private(
            state_root / "trust" / "transport-trust.pem",
            "-----BEGIN CERTIFICATE-----\n"
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n"
            "-----END CERTIFICATE-----\n",
        )
        self.write_private(
            state_root / "trust" / "transport-identity.commit",
            f"version=1\nspki_sha256={'cd' * 32}\n",
        )
        self.write_private(state_root / "trust" / "transport.pin", f"{'cd' * 32}\n")
        self.write_private(
            state_root / "profiles" / "direct.conf",
            "version=2\n"
            f"role={role}\n"
            "profile_epoch=0\n"
            "dial_mode=DONOR_DIALS\n"
            "dial_endpoint=100.64.0.2\n"
            "listen_interface=192.168.1.2\n"
            f"peer_spki_sha256={'ab' * 32}\n"
            "transport=DIRECT\n",
        )

    def write_fake_runtime(self, temporary_root: Path) -> Path:
        runtime = temporary_root / "fake-runtime.sh"
        runtime.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = --role ]; then\n"
            "  profile_sha=$(sha256sum \"$RKA_PROFILE_PATH\" | awk '{print $1}') || exit 1\n"
            "  pin=$(sed -n '7s/^peer_spki_sha256=//p' \"$RKA_PROFILE_PATH\") || exit 1\n"
            "  pin_sha=$(printf %s \"$pin\" | xxd -r -p | sha256sum | awk '{print $1}') || exit 1\n"
            "  printf 'version=1\\nprofile_sha256=%s\\nprofile_epoch=%s\\npeer_pin_sha256=%s\\ndial_mode=DONOR_DIALS\\ntransport=DIRECT\\n' \"$profile_sha\" \"$RKA_EXPECTED_PROFILE_EPOCH\" \"$pin_sha\" > \"$RKA_PROFILE_RECEIPT_PATH\"\n"
            "  chmod 600 \"$RKA_PROFILE_RECEIPT_PATH\"\n"
            "  exec python3 -c 'import os, socket, sys, time; s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); os.chmod(sys.argv[1], 0o600); s.listen(); time.sleep(3600)' \"$RKA_DONOR_SOCKET\"\n"
            "fi\n"
            "while :; do sleep 60; done\n",
            encoding="utf-8",
        )
        os.chmod(runtime, 0o700)
        supervisor = temporary_root / "fake-supervisor.sh"
        supervisor.write_text(
            "#!/bin/sh\n"
            '[ "$1" = --detach ] || exit 64\n'
            "shift\n"
            "RKA_INTERNAL_CHILD_LOOP=1 sh \"$@\" </dev/null >/dev/null 2>&1 &\n",
            encoding="utf-8",
        )
        os.chmod(supervisor, 0o700)
        return runtime

    def test_status_derives_ready_pairing_from_production_sources_without_secret_or_path(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.initialize(config_root, state_root)
            pending, nonce = self.mutate(
                config_root, state_root, "pair-direct", self.open_webui(config_root, state_root)
            )
            self.write_live_transport_sources(state_root)
            fake_runtime = self.write_fake_runtime(temporary_root)
            runtime_environment = {
                "RKA_DAEMON": str(fake_runtime),
                "RKA_NATIVE_SUPERVISOR": str(fake_runtime.with_name("fake-supervisor.sh")),
                "RKA_SIDECAR": str(fake_runtime),
                "RKA_SOCKET_DIRECTORY_CONTEXT": "?",
                "RKA_SOCKET_CONTEXT": "?",
                "RKA_STABLE_SECONDS": "60",
            }
            result, nonce = self.mutate(
                config_root, state_root, "start", nonce, environment=runtime_environment
            )
            stopped, _ = self.mutate(
                config_root, state_root, "stop", nonce, environment=runtime_environment
            )

        self.assertIn("pairing=PENDING", pending.stdout)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("role=DONOR", result.stdout)
        self.assertIn("phone_role=PHONE_A_DONOR", result.stdout)
        self.assertIn("direct_profile=DIRECT_NETWORK", result.stdout)
        self.assertIn("direct_readiness=READY", result.stdout)
        self.assertIn("pairing=PAIRED", result.stdout)
        self.assertIn("runtime=RUNNING", result.stdout)
        self.assertIn("diagnostic=DIAGNOSTIC_ONLY", result.stdout)
        self.assertNotIn("test-transport-key-material", result.stdout)
        self.assertNotIn(str(state_root), result.stdout)
        self.assertIn("runtime=STOPPED", stopped.stdout)

    def test_network_settings_update_the_existing_profile_without_replacing_pairing_identity(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.initialize(config_root, state_root)
            self.write_live_transport_sources(state_root)
            profile_path = state_root / "profiles" / "direct.conf"

            result = self.run_control(
                config_root,
                state_root,
                "webui",
                "network-save",
                self.open_webui(config_root, state_root),
                "100.70.0.2,100.70.0.1,37373",
            )
            profile = profile_path.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("network_peer_ip=100.70.0.2", result.stdout)
        self.assertIn("network_local_ip=100.70.0.1", result.stdout)
        self.assertIn("network_port=37373", result.stdout)
        self.assertIn("dial_endpoint=100.70.0.2\n", profile)
        self.assertIn("listen_interface=100.70.0.1\n", profile)
        self.assertIn(f"peer_spki_sha256={'ab' * 32}\n", profile)

    def test_network_settings_reject_malformed_ipv4_without_changing_the_profile(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.initialize(config_root, state_root)
            self.write_live_transport_sources(state_root)
            profile_path = state_root / "profiles" / "direct.conf"
            original = profile_path.read_text(encoding="utf-8")

            result = self.run_control(
                config_root,
                state_root,
                "webui",
                "network-save",
                self.open_webui(config_root, state_root),
                "100.70.0.999,100.70.0.1,37373",
            )
            after = profile_path.read_text(encoding="utf-8")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "WEBUI_INVALID_REQUEST\n")
        self.assertEqual(after, original)

    def test_multi_candidate_status_is_scoped_and_network_edit_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.initialize(config_root, state_root)
            self.write_live_transport_sources(state_root)
            profile = (state_root / "profiles" / "direct.conf").read_text(encoding="utf-8")
            direct_directory = state_root / "profiles" / "direct.d"
            candidates = ("candidate-a", "candidate-b")
            for candidate in candidates:
                self.write_private(direct_directory / f"{candidate}.conf", profile)
                self.write_private(
                    direct_directory / f"{candidate}.pair.request",
                    "version=1\naction=PAIR_DIRECT\n",
                )
            self.write_private(state_root / "run" / "supervisor-candidate-a.state", "RUNNING\n")
            self.write_private(state_root / "run" / "supervisor-candidate-b.state", "STOPPED\n")

            status = self.run_control(
                config_root, state_root, "webui", "status", self.open_webui(config_root, state_root)
            )
            before = {
                candidate: (direct_directory / f"{candidate}.conf").read_text(encoding="utf-8")
                for candidate in candidates
            }
            network = self.run_control(
                config_root,
                state_root,
                "webui",
                "network-save",
                self.open_webui(config_root, state_root),
                "100.70.0.2,100.70.0.1,37373",
            )
            after = {
                candidate: (direct_directory / f"{candidate}.conf").read_text(encoding="utf-8")
                for candidate in candidates
            }

        blocks = status.stdout.split("candidate_begin=")[1:]
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(len(blocks), 2)
        self.assertIn("runtime=NOT_READY", blocks[0])
        self.assertIn("direct_readiness=NOT_READY", blocks[0])
        self.assertIn("runtime=STOPPED", blocks[1])
        self.assertIn("direct_readiness=NOT_READY", blocks[1])
        self.assertNotEqual(network.returncode, 0)
        for candidate in candidates:
            self.assertEqual(after[candidate], before[candidate])

    def test_status_ignores_test_seeded_snapshot_and_rejects_cross_role_state(self) -> None:
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
            seeded = self.run_control(
                config_root, state_root, "webui", "status", self.open_webui(config_root, state_root)
            )
            self.write_private(
                state_root / "profiles" / "active.conf",
                "version=1\nrole=CANDIDATE\nprofile_epoch=0\n",
            )
            cross_role = self.run_control(
                config_root, state_root, "webui", "status", self.open_webui(config_root, state_root)
            )

        self.assertEqual(seeded.returncode, 0, seeded.stderr)
        self.assertIn("pairing=UNPAIRED", seeded.stdout)
        self.assertIn("direct_profile=UNAVAILABLE", seeded.stdout)
        self.assertNotIn("pairing=PAIRED", seeded.stdout)
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
        self.assertIn("direct_profile=UNAVAILABLE", successes[0].stdout)
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
            self.write_live_transport_sources(state_root)
            self.write_private(state_root / "run" / "supervisor.state", "RUNNING\n")
            blocked = self.run_control(
                config_root,
                state_root,
                "webui",
                "role-candidate",
                self.open_webui(config_root, state_root),
            )
            self.write_private(state_root / "run" / "supervisor.state", "STOPPED\n")
            changed, nonce = self.mutate(
                config_root, state_root, "role-candidate", self.open_webui(config_root, state_root)
            )
            active_profile = (state_root / "profiles" / "active.conf").read_text(encoding="utf-8")
            root_role = (config_root / "rka" / "role.conf").read_text(encoding="utf-8")
            direct_profile = (state_root / "profiles" / "direct.conf").read_text(encoding="utf-8")
            started = self.run_control(config_root, state_root, "webui", "start", nonce)

        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("role=CANDIDATE", changed.stdout)
        self.assertIn("role=CANDIDATE", active_profile)
        self.assertIn("role=CANDIDATE", root_role)
        self.assertIn("role=CANDIDATE", direct_profile)
        self.assertNotEqual(started.returncode, 0)
        self.assertEqual(started.stdout, "WEBUI_INVALID_REQUEST\n")

    def test_role_change_rejects_running_indexed_candidate_when_global_state_is_stopped(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.initialize(config_root, state_root)
            self.write_live_transport_sources(state_root)
            profile = (state_root / "profiles" / "direct.conf").read_text(encoding="utf-8")
            self.write_private(
                state_root / "profiles" / "direct.d" / "candidate-a.conf",
                profile,
            )
            self.write_private(state_root / "run" / "supervisor.state", "STOPPED\n")
            self.write_private(
                state_root / "run" / "supervisor-candidate-a.state",
                "RUNNING\n",
            )

            changed = self.run_control(
                config_root,
                state_root,
                "webui",
                "role-candidate",
                self.open_webui(config_root, state_root),
            )
            active_profile = (state_root / "profiles" / "active.conf").read_text(
                encoding="utf-8"
            )
            root_role = (config_root / "rka" / "role.conf").read_text(encoding="utf-8")

        self.assertNotEqual(changed.returncode, 0)
        self.assertIn("role=DONOR", active_profile)
        self.assertIn("role=DONOR", root_role)

    def test_webui_open_recovers_interrupted_role_transaction_by_rolling_forward(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.initialize(config_root, state_root)
            self.write_live_transport_sources(state_root)
            self.write_private(
                state_root / "journal" / "webui-role.state",
                "version=1\nrequested_role=CANDIDATE\nprofile_epoch=0\ndirect_present=true\n",
            )
            self.write_private(
                state_root / "profiles" / "active.conf",
                "version=1\nrole=CANDIDATE\nprofile_epoch=0\n",
            )

            opened = self.run_control(config_root, state_root, "webui-open")
            active_profile = (state_root / "profiles" / "active.conf").read_text(
                encoding="utf-8"
            )
            root_role = (config_root / "rka" / "role.conf").read_text(encoding="utf-8")
            direct_profile = (state_root / "profiles" / "direct.conf").read_text(
                encoding="utf-8"
            )

        self.assertEqual(opened.returncode, 0, opened.stderr)
        self.assertIn("role=CANDIDATE", active_profile)
        self.assertIn("role=CANDIDATE", root_role)
        self.assertIn("role=CANDIDATE", direct_profile)

    def test_provisioning_status_rejects_state_without_live_broker_generation(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.initialize(config_root, state_root)
            self.write_private(
                state_root / "journal" / "provisioning.state",
                "version=1\nstatus=PROVISIONED\nprofile_epoch=0\nkey_count=1\n",
            )

            status = self.run_control(
                config_root,
                state_root,
                "webui",
                "status",
                self.open_webui(config_root, state_root),
            )

        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("rkp_provisioning=NOT_READY", status.stdout)

    def test_fixed_dom_actions_execute_their_command_contracts(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "rka-state"
            self.initialize(config_root, state_root)
            nonce = self.open_webui(config_root, state_root)
            status = self.run_control(config_root, state_root, "webui", "status", nonce)
            _, nonce = self.mutate(config_root, state_root, "role-donor", nonce)
            _, nonce = self.mutate(config_root, state_root, "role-candidate", nonce)
            _, nonce = self.mutate(config_root, state_root, "pair-direct", nonce)
            _, nonce = self.mutate(config_root, state_root, "rotate-pairing", nonce)
            self.write_live_transport_sources(state_root)
            fake_runtime = self.write_fake_runtime(temporary_root)
            runtime_environment = {
                "RKA_DAEMON": str(fake_runtime),
                "RKA_NATIVE_SUPERVISOR": str(fake_runtime.with_name("fake-supervisor.sh")),
                "RKA_SIDECAR": str(fake_runtime),
                "RKA_SOCKET_DIRECTORY_CONTEXT": "?",
                "RKA_SOCKET_CONTEXT": "?",
                "RKA_STABLE_SECONDS": "60",
            }
            start, nonce = self.mutate(
                config_root, state_root, "start", nonce, environment=runtime_environment
            )
            _, nonce = self.mutate(
                config_root, state_root, "stop", nonce, environment=runtime_environment
            )
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
        self.assertIn("runtime=RUNNING", start.stdout)
        self.assertIn("recovery_target=KEYSTORE2", recovery.stdout)
        self.assertIn("audit_export=REDACTED_READY", audit.stdout)
        self.assertIn("evidence_export=REDACTED_READY", evidence.stdout)
        self.assertEqual(quarantine.returncode, 0, quarantine.stderr)
        for export in (audit_export, evidence_export):
            self.assertLessEqual(len(export.encode("utf-8")), 512)
            self.assertNotIn("transport.key", export)
            self.assertNotIn(str(state_root), export)
        self.assertIn("pairing=PENDING", export)

    def test_browser_clicks_every_fixed_action_and_renders_bridge_failures_safely(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            browser_evidence = Path(temporary_directory) / "browser"
            result = run(
                ["node", str(BROWSER_HARNESS), str(browser_evidence)],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            action_log = json.loads(
                (browser_evidence / "browser-action-log.json").read_text(encoding="utf-8")
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([entry["action"] for entry in action_log["observed"]], list(FIXED_ACTIONS))
        self.assertEqual(
            [entry["commandState"] for entry in action_log["observed"]],
            [
                "Status refreshed" if action == "status"
                else "Request failed · session restored" if action == "quarantine"
                else "Request accepted"
                for action in FIXED_ACTIONS
            ],
        )
        self.assertFalse(action_log["escaping"]["hostileExecuted"])
        self.assertFalse(action_log["escaping"]["hostileText"])
        self.assertFalse(action_log["escaping"]["imageChildren"])
        self.assertEqual(action_log["failure"]["commandState"], "Request failed · session restored")
        self.assertEqual(action_log["malformedState"], "WebUI unavailable")
        self.assertTrue(action_log["busy"]["disabled"])
        self.assertFalse(action_log["settled"]["disabled"])
        self.assertEqual(action_log["settled"]["commandState"], "Status refreshed")

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
