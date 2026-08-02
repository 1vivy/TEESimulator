from __future__ import annotations

import os
from pathlib import Path
import select
import signal
import socket
from subprocess import CompletedProcess, run
from tempfile import TemporaryDirectory
from time import monotonic, sleep
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SUPERVISOR = REPOSITORY_ROOT / "module" / "rka-supervisor.sh"
CUSTOMIZE = REPOSITORY_ROOT / "module" / "customize.sh"
DAEMON = REPOSITORY_ROOT / "module" / "daemon"
NATIVE_SUPERVISOR = REPOSITORY_ROOT / "app" / "src" / "main" / "cpp" / "supervisor.cpp"


class RkaSupervisorTest(unittest.TestCase):
    def test_native_exec_closed_drops_every_inherited_descriptor(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            runner = temporary / "supervisor"
            compiled = run(
                ["c++", "-std=c++17", str(NATIVE_SUPERVISOR), "-o", str(runner)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            child_pid_path = temporary / "child.pid"
            fake_ksud = temporary / "ksud"
            fake_ksud.write_text(
                "#!/usr/bin/env python3\n"
                "import os, time\n"
                "from pathlib import Path\n"
                "pid = os.fork()\n"
                "if pid == 0:\n"
                "    time.sleep(30)\n"
                "    os._exit(0)\n"
                "Path(os.environ['RKA_FAKE_CHILD_PID']).write_text(str(pid), encoding='ascii')\n"
                "print('install complete')\n",
                encoding="utf-8",
            )
            fake_ksud.chmod(0o755)
            install_stdout = temporary / "install.stdout"
            install_stderr = temporary / "install.stderr"
            read_fd, write_fd = os.pipe()
            child_pid: int | None = None
            try:
                result = run(
                    [
                        str(runner),
                        "--exec-closed",
                        str(install_stdout),
                        str(install_stderr),
                        str(fake_ksud),
                        "module",
                        "install",
                    ],
                    check=False,
                    capture_output=True,
                    env=os.environ | {"RKA_FAKE_CHILD_PID": str(child_pid_path)},
                    pass_fds=(write_fd,),
                    text=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(install_stdout.read_text(encoding="utf-8"), "install complete\n")
                child_pid = int(child_pid_path.read_text(encoding="ascii"))
                os.close(write_fd)
                write_fd = -1
                readable, _, _ = select.select([read_fd], [], [], 1)
                self.assertEqual(readable, [read_fd])
                self.assertEqual(os.read(read_fd, 1), b"")
            finally:
                if write_fd >= 0:
                    os.close(write_fd)
                os.close(read_fd)
                if child_pid is not None:
                    try:
                        os.kill(child_pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass

    def command(
        self, root: Path, state: Path, *arguments: str, environment: dict[str, str] | None = None
    ) -> CompletedProcess[str]:
        child_environment = os.environ | {
            "RKA_CONTROL": str(REPOSITORY_ROOT / "module" / "rka-control.sh"),
            "RKA_DAEMON": str(root / "fake-child.sh"),
            "RKA_SIDECAR": str(root / "fake-child.sh"),
            "RKA_NATIVE_SUPERVISOR": str(root / "fake-supervisor.sh"),
            "RKA_CHILD_LOG": str(root / "children.log"),
            "RKA_BACKOFF_BASE": "0",
        }
        if environment is not None:
            child_environment = child_environment | environment
        return run(
            ["sh", str(SUPERVISOR), "--root", str(root), "--state-root", str(state), *arguments],
            check=False,
            capture_output=True,
            env=child_environment,
            text=True,
        )

    def write_role(self, root: Path, role: str) -> None:
        path = root / "rka" / "role.conf"
        path.parent.mkdir(parents=True)
        path.write_text(f"version=1\nrole={role}\n", encoding="utf-8")
        os.chmod(path, 0o600)

    def write_profile(self, state: Path, role: str) -> None:
        path = state / "profiles" / "active.conf"
        path.parent.mkdir(parents=True)
        path.write_text(f"version=1\nrole={role}\nprofile_epoch=0\n", encoding="utf-8")
        os.chmod(path, 0o600)

    def write_direct_profile(self, state: Path, role: str, epoch: int = 0) -> None:
        path = state / "profiles" / "direct.conf"
        path.write_text(
            "version=2\n"
            f"role={role}\n"
            f"profile_epoch={epoch}\n"
            "dial_mode=DONOR_DIALS\n"
            "dial_endpoint=100.88.0.2\n"
            "listen_interface=100.88.0.2\n"
            f"peer_spki_sha256={'ab' * 32}\n"
            "transport=DIRECT\n",
            encoding="utf-8",
        )
        os.chmod(path, 0o600)

    def write_direct_identity(self, state: Path, committed: bool) -> None:
        secrets = state / "secrets"
        trust = state / "trust"
        profiles = state / "profiles"
        secrets.mkdir(parents=True, exist_ok=True)
        trust.mkdir(parents=True, exist_ok=True)
        profiles.mkdir(parents=True, exist_ok=True)
        key = secrets / "transport.key"
        certificate = trust / "transport-trust.pem"
        request = profiles / "pair.request"
        key.write_text("transport-private-material\n", encoding="ascii")
        certificate.write_text(
            "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n",
            encoding="ascii",
        )
        request.write_text("version=1\naction=PAIR_DIRECT\n", encoding="ascii")
        for path in (key, certificate, request):
            os.chmod(path, 0o600)
        if committed:
            marker = trust / "transport-identity.commit"
            marker.write_text(f"version=1\nspki_sha256={'ab' * 32}\n", encoding="ascii")
            os.chmod(marker, 0o600)

    def fixture(self, role: str | None) -> tuple[TemporaryDirectory[str], Path, Path]:
        temporary = TemporaryDirectory()
        root = Path(temporary.name) / "root"
        state = Path(temporary.name) / "state"
        root.mkdir()
        child = root / "fake-child.sh"
        child.write_text(
            "#!/bin/sh\nprintf '%s %s RKA_PROFILE_PATH=%s RKA_EXPECTED_PROFILE_EPOCH=%s RKA_PROFILE_RECEIPT_PATH=%s\\n' \"$0\" \"$*\" \"${RKA_PROFILE_PATH-}\" \"${RKA_EXPECTED_PROFILE_EPOCH-}\" \"${RKA_PROFILE_RECEIPT_PATH-}\" >> \"$RKA_CHILD_LOG\"\nif [ -n \"${RKA_PROFILE_RECEIPT_PATH-}\" ]; then profile_hash=$(sha256sum \"$RKA_PROFILE_PATH\" | awk '{print $1}'); printf 'version=1\\nprofile_sha256=%s\\nprofile_epoch=%s\\npeer_pin_sha256=%064d\\ndial_mode=DONOR_DIALS\\ntransport=DIRECT\\n' \"$profile_hash\" \"$RKA_EXPECTED_PROFILE_EPOCH\" 0 > \"$RKA_PROFILE_RECEIPT_PATH\"; chmod 600 \"$RKA_PROFILE_RECEIPT_PATH\"; fi\n[ \"${RKA_CHILD_MODE:-hold}\" = crash ] && exit 7\nif [ \"${RKA_CHILD_MODE:-hold}\" = crash-once ] && [ ! -e \"$RKA_CRASH_ONCE_FILE\" ]; then : > \"$RKA_CRASH_ONCE_FILE\"; sleep 1; exit 7; fi\nif [ \"${RKA_CHILD_MODE:-hold}\" = ignore-term ]; then trap '' TERM INT; else trap 'printf term\\n >> \"$RKA_CHILD_LOG\"; exit 0' TERM INT; fi\nwhile :; do sleep 1; done\n",
            encoding="utf-8",
        )
        child.chmod(0o755)
        detacher = root / "fake-supervisor.sh"
        detacher.write_text(
            "#!/bin/sh\n"
            '[ "$1" = --detach ] || exit 64\n'
            "shift\n"
            "RKA_INTERNAL_CHILD_LOOP=1 sh \"$@\" </dev/null >/dev/null 2>&1 &\n",
            encoding="utf-8",
        )
        detacher.chmod(0o755)
        if role is not None:
            self.write_role(root, role)
            if role not in {"LOCAL", "DISABLED"}:
                self.write_profile(state, role)
                self.write_direct_profile(state, role)
        return temporary, root, state

    def clean(self, root: Path, state: Path) -> None:
        self.command(root, state, "stop")

    def test_local_starts_only_legacy_process(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            result = self.command(root, state, "start")
            status = self.command(root, state, "status")
            self.assertEqual(result.returncode, 0)
            self.assertIn("legacy=RUNNING", status.stdout)
            self.assertNotIn("broker=RUNNING", status.stdout)
            self.assertNotIn("sidecar=RUNNING", status.stdout)
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_donor_process_graph(self) -> None:
        temporary, root, state = self.fixture("DONOR")
        try:
            self.assertEqual(self.command(root, state, "start").returncode, 0)
            status = self.command(root, state, "status")
            child_log = (root / "children.log").read_text(encoding="utf-8")
            self.assertIn("broker=RUNNING", status.stdout)
            self.assertIn("sidecar=RUNNING", status.stdout)
            self.assertIn(f"{state / 'bin' / 'rka-sidecar'} --role donor", child_log)
            self.assertEqual(
                os.stat(state / "bin" / "rka-sidecar").st_mode & 0o777,
                0o700,
            )
            self.assertNotIn("--rka-candidate", child_log)
            self.assertNotIn("legacy=RUNNING", status.stdout)
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_broker_launches_daemon_with_module_directory(self) -> None:
        temporary, root, state = self.fixture("DONOR")
        broker = root / "daemon-contract.sh"
        ready = root / "broker-ready"
        broker.write_text(
            "#!/bin/sh\n"
            '[ "$#" -eq 3 ] || exit 64\n'
            '[ "$1" = "$RKA_EXPECTED_MODULE_DIRECTORY" ] || exit 64\n'
            '[ "$2" = --rka-role ] || exit 64\n'
            '[ "$3" = donor ] || exit 64\n'
            'printf "%s\\n%s\\n%s\\n" "$1" "$2" "$3" > "$RKA_BROKER_READY"\n'
            'exec "$RKA_CHILD_EXECUTABLE" "$@"\n',
            encoding="utf-8",
        )
        broker.chmod(0o755)
        try:
            result = self.command(
                root,
                state,
                "start",
                environment={
                    "RKA_DAEMON": str(broker),
                    "RKA_CHILD_EXECUTABLE": str(root / "fake-child.sh"),
                    "RKA_EXPECTED_MODULE_DIRECTORY": str(SUPERVISOR.parent),
                    "RKA_BROKER_READY": str(ready),
                },
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(
                ready.read_text(encoding="utf-8"),
                f"{SUPERVISOR.parent}\n--rka-role\ndonor\n",
            )
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_candidate_process_graph(self) -> None:
        temporary, root, state = self.fixture("CANDIDATE")
        try:
            self.assertEqual(self.command(root, state, "start").returncode, 0)
            child_log = (root / "children.log").read_text(encoding="utf-8")
            self.assertIn("--rka-role candidate", child_log)
            self.assertIn("candidate", child_log)
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_internal_child_loop_is_not_a_public_command(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            result = self.command(root, state, "__child-loop", "legacy", "", "/bin/true")
            mismatched = self.command(
                root,
                state,
                "__child-loop",
                "sidecar",
                "",
                "/bin/true",
                environment={"RKA_INTERNAL_CHILD_LOOP": "1"},
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertNotEqual(mismatched.returncode, 0)
            self.assertFalse((state / "run" / "pids" / "legacy.pid").exists())
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_direct_runtime_requires_committed_identity_set(self) -> None:
        temporary, root, state = self.fixture("CANDIDATE")
        environment = {"RKA_REQUIRE_DIRECT_READY": "true"}
        try:
            self.write_direct_identity(state, committed=False)
            self.assertNotEqual(
                self.command(root, state, "start", environment=environment).returncode,
                0,
            )
            self.write_direct_identity(state, committed=True)
            self.assertEqual(
                self.command(root, state, "start", environment=environment).returncode,
                0,
            )
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_invalid_or_disabled_starts_nothing(self) -> None:
        temporary, root, state = self.fixture("DISABLED")
        try:
            result = self.command(root, state, "start")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "children.log").exists())
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_invalid_role_configuration_starts_nothing(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            os.chmod(root / "rka" / "role.conf", 0o644)
            result = self.command(root, state, "start")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "children.log").exists())
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_duplicate_start_is_idempotent(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            self.assertEqual(self.command(root, state, "start").returncode, 0)
            self.assertEqual(self.command(root, state, "start").returncode, 0)
            self.assertEqual(len(list((state / "run" / "pids").glob("*.pid"))), 1)
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_duplicate_role_start_preserves_fixed_sidecar_inode(self) -> None:
        temporary, root, state = self.fixture("DONOR")
        try:
            self.assertEqual(self.command(root, state, "start").returncode, 0)
            runtime_sidecar = state / "bin" / "rka-sidecar"
            before = os.stat(runtime_sidecar).st_ino
            self.assertEqual(self.command(root, state, "start").returncode, 0)
            self.assertEqual(os.stat(runtime_sidecar).st_ino, before)
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_stale_or_reused_pid_record_is_removed_without_signal(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            record = state / "run" / "pids" / "legacy.pid"
            record.parent.mkdir(parents=True)
            record.write_text("1 1 1\n", encoding="utf-8")
            self.assertEqual(self.command(root, state, "stop").returncode, 0)
            self.assertFalse(record.exists())
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_stop_removes_identity_record_without_pid_record(self) -> None:
        temporary, root, state = self.fixture("DONOR")
        try:
            identity = state / "run" / "pids" / "broker.identity"
            identity.parent.mkdir(parents=True)
            identity.write_text("stale\n", encoding="utf-8")
            os.chmod(identity, 0o600)
            self.assertEqual(self.command(root, state, "stop").returncode, 0)
            self.assertFalse(identity.exists())
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_stop_removes_only_the_owned_runtime_socket(self) -> None:
        temporary, root, state = self.fixture("CANDIDATE")
        socket_directory = state / "run" / "sockets"
        socket_directory.mkdir(parents=True)
        os.chmod(socket_directory, 0o700)
        socket_path = socket_directory / "broker.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(socket_path))
            os.chmod(socket_path, 0o600)
            self.assertEqual(self.command(root, state, "stop").returncode, 0)
            self.assertFalse(socket_path.exists())
        finally:
            listener.close()
            self.clean(root, state)
            temporary.cleanup()

    def test_stop_removes_owned_half_bound_runtime_socket(self) -> None:
        temporary, root, state = self.fixture("DONOR")
        socket_directory = state / "run" / "sockets"
        socket_directory.mkdir(parents=True)
        os.chmod(socket_directory, 0o700)
        socket_path = socket_directory / "broker.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(socket_path))
            os.chmod(socket_path, 0o700)
            self.assertEqual(self.command(root, state, "stop").returncode, 0)
            self.assertFalse(socket_path.exists())
        finally:
            listener.close()
            self.clean(root, state)
            temporary.cleanup()

    def test_stop_rejects_an_unexpected_runtime_socket_entry(self) -> None:
        temporary, root, state = self.fixture("CANDIDATE")
        socket_directory = state / "run" / "sockets"
        socket_directory.mkdir(parents=True)
        os.chmod(socket_directory, 0o700)
        socket_path = socket_directory / "broker.sock"
        socket_path.write_text("not a socket\n", encoding="ascii")
        os.chmod(socket_path, 0o600)
        try:
            self.assertNotEqual(self.command(root, state, "stop").returncode, 0)
            self.assertTrue(socket_path.is_file())
        finally:
            socket_path.unlink()
            self.clean(root, state)
            temporary.cleanup()

    def test_child_death_restarts_and_stop_forwards_term(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            self.assertEqual(self.command(root, state, "start").returncode, 0)
            record = next((state / "run" / "pids").glob("legacy.pid"))
            prior_record = record.read_text(encoding="utf-8")
            run(["kill", "-TERM", "--", f"-{prior_record.split()[1]}"], check=True)
            deadline = monotonic() + 2
            while record.read_text(encoding="utf-8") == prior_record and monotonic() < deadline:
                sleep(0.02)
            self.assertNotEqual(record.read_text(encoding="utf-8"), prior_record)
            self.assertEqual(self.command(root, state, "stop").returncode, 0)
            self.assertIn("legacy=STOPPED", self.command(root, state, "status").stdout)
            self.assertIn("term", (root / "children.log").read_text(encoding="utf-8"))
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_stop_waits_for_sigkill_quiescence_before_removing_record(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            self.assertEqual(
                self.command(
                    root,
                    state,
                    "start",
                    environment={"RKA_CHILD_MODE": "ignore-term"},
                ).returncode,
                0,
            )
            record = state / "run" / "pids" / "legacy.pid"
            child_pid = int(record.read_text(encoding="utf-8").split()[0])

            result = self.command(root, state, "stop")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(record.exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
            source = SUPERVISOR.read_text(encoding="utf-8")
            sigkill = source.index('kill -KILL "$pid"')
            self.assertIn('while record_live "$record"', source[sigkill:])
            self.assertIn('record_live "$record" && return 1', source[sigkill:])
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_rapid_crashes_reach_failed_cap(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            result = self.command(root, state, "start", environment={"RKA_CHILD_MODE": "crash"})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("state=FAILED_CRASH_CAP", self.command(root, state, "status").stdout)
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_no_restart_during_generating(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            marker = state / "journal" / "mutation.state"
            marker.parent.mkdir(parents=True)
            marker.write_text("RKP_KEY_GENERATING\n", encoding="utf-8")
            result = self.command(root, state, "start", environment={"RKA_CHILD_MODE": "crash"})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "state=QUARANTINED_AMBIGUOUS_MUTATION",
                self.command(root, state, "status").stdout,
            )
            self.assertEqual((root / "children.log").read_text(encoding="utf-8").count("legacy"), 1)
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_marker_matrix_quarantines_ambiguous_and_restarts_normal(self) -> None:
        quarantined = ("POST_AMBIGUOUS", "RKP_KEY_GENERATING", "APP_KEY_GENERATING", "malformed", "unreadable")
        normal = (None, "IDLE", "COMPLETED")
        for marker_value in quarantined + normal:
            temporary, root, state = self.fixture("LOCAL")
            try:
                if marker_value is not None:
                    marker = state / "journal" / "mutation.state"
                    marker.parent.mkdir(parents=True)
                    marker.write_text(f"{marker_value}\n", encoding="utf-8")
                    if marker_value == "unreadable":
                        os.chmod(marker, 0o000)
                crash_file = root / "crashed-once"
                self.assertEqual(
                    self.command(
                        root,
                        state,
                        "start",
                        environment={"RKA_CHILD_MODE": "crash-once", "RKA_CRASH_ONCE_FILE": str(crash_file)},
                    ).returncode,
                    0,
                )
                deadline = monotonic() + 3
                while "state=RUNNING" in self.command(root, state, "status").stdout and monotonic() < deadline:
                    sleep(0.02)
                status = self.command(root, state, "status").stdout
                launches = (root / "children.log").read_text(encoding="utf-8").count("legacy")
                if marker_value in quarantined:
                    self.assertIn("state=QUARANTINED_AMBIGUOUS_MUTATION", status)
                    self.assertEqual(launches, 1)
                else:
                    self.assertIn("legacy=RUNNING", status)
                    self.assertEqual(launches, 2)
            finally:
                self.clean(root, state)
                temporary.cleanup()

    def test_forbidden_process_control_tokens_are_absent(self) -> None:
        source = SUPERVISOR.read_text(encoding="utf-8")
        for forbidden in ("killall", "pkill", "reboot", "keystore2", "rkpd", "classpath"):
            self.assertNotIn(forbidden, source.lower())

    def test_rka_daemon_uses_fixed_broker_process_contract(self) -> None:
        source = DAEMON.read_text(encoding="utf-8")
        self.assertIn('CLASSPATH="$CLASSPATH" exec /system/bin/app_process64 /system/bin', source)
        self.assertIn('org.matrix.TEESimulator.App --rka-role "$2"', source)
        self.assertIn('donor|candidate', source)
        self.assertNotIn('--nice-name=TEESimulator org.matrix.TEESimulator.App --rka-role', source)

    def test_daemon_changes_to_module_directory_before_app_process(self) -> None:
        source = DAEMON.read_text(encoding="utf-8")
        module_directory_change = source.index('cd "$MODDIR"')
        rka_launch = source.index('if [ "$1" = --rka-role ]; then')
        legacy_launch = source.rindex('exec /system/bin/app_process')
        self.assertLess(module_directory_change, rka_launch)
        self.assertLess(module_directory_change, legacy_launch)

    def test_role_start_publishes_sidecar_before_broker_identity(self) -> None:
        source = SUPERVISOR.read_text(encoding="utf-8")
        self.assertIn('"$runtime_sidecar" --role "$selected_role"', source)
        self.assertIn('"$pids/$name.identity"', source)
        self.assertIn('rm -f "$record" "$pids/$name.identity"', source)
        self.assertIn('while ! process_identity_matches', source)
        donor_sidecar = source.index('start_sidecar donor "$active_epoch"')
        donor_broker = source.index('start_one broker donor')
        candidate_sidecar = source.index('start_sidecar candidate "$active_epoch"')
        candidate_broker = source.index('start_one broker candidate')
        self.assertLess(donor_sidecar, donor_broker)
        self.assertLess(candidate_sidecar, candidate_broker)

    def test_module_installer_ships_supervisor(self) -> None:
        source = CUSTOMIZE.read_text(encoding="utf-8")
        self.assertIn("rka-supervisor.sh", source)
        self.assertIn('chmod 755 "$MODPATH/rka-supervisor.sh"', source)
        self.assertIn("rka-sidecar", source)
