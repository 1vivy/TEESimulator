from __future__ import annotations

import os
from pathlib import Path
import socket
from subprocess import CompletedProcess, run
from tempfile import TemporaryDirectory
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTROL_SCRIPT = REPOSITORY_ROOT / "module" / "rka-control.sh"
ACTIVE_CONFIG_DIRECTORY = "rka"
ACTIVE_CONFIG_NAME = "role.conf"


class RkaControlTest(unittest.TestCase):
    def run_control(
        self,
        config_root: Path,
        *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> CompletedProcess[str]:
        return run(
            ["bash", str(CONTROL_SCRIPT), "--root", str(config_root), *arguments],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )

    def write_config(self, config_root: Path, content: str, mode: int = 0o600) -> None:
        config_path = config_root / ACTIVE_CONFIG_DIRECTORY / ACTIVE_CONFIG_NAME
        config_path.parent.mkdir()
        config_path.write_text(content, encoding="utf-8")
        os.chmod(config_path, mode)

    def test_future_version_fails_inert(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            config_root = Path(temporary_directory) / "tricky_store"
            config_root.mkdir()
            self.write_config(config_root, "version=2\nrole=LOCAL\n")
            result = self.run_control(config_root, "boot-decision")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("INERT_INVALID_CONFIG", result.stdout)
        self.assertNotIn("LOCAL", result.stdout)

    def test_missing_config_defaults_to_local(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            config_root = Path(temporary_directory) / "tricky_store"
            result = self.run_control(config_root, "boot-decision")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "LOCAL\n")

    def test_shipped_seed_does_not_become_active_config(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            config_root = Path(temporary_directory) / "tricky_store"
            config_root.mkdir()
            shipped_seed = config_root / "rka-role.conf"
            shipped_seed.write_text("version=1\nrole=LOCAL\n", encoding="utf-8")
            os.chmod(shipped_seed, 0o644)
            result = self.run_control(config_root, "boot-decision")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "LOCAL\n")

    def test_duplicate_key_fails_inert(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            config_root = Path(temporary_directory) / "tricky_store"
            config_root.mkdir()
            self.write_config(config_root, "version=1\nrole=LOCAL\nrole=DONOR\n")
            result = self.run_control(config_root, "boot-decision")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "INERT_INVALID_CONFIG\n")

    def test_unknown_key_fails_inert(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            config_root = Path(temporary_directory) / "tricky_store"
            config_root.mkdir()
            self.write_config(config_root, "version=1\nrole=LOCAL\nextra=value\n")
            result = self.run_control(config_root, "boot-decision")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "INERT_INVALID_CONFIG\n")

    def test_wrong_mode_fails_inert(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            config_root = Path(temporary_directory) / "tricky_store"
            config_root.mkdir()
            self.write_config(config_root, "version=1\nrole=LOCAL\n", 0o644)
            result = self.run_control(config_root, "boot-decision")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "INERT_INVALID_CONFIG\n")

    def test_symlink_fails_inert(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            config_root = Path(temporary_directory) / "tricky_store"
            config_root.mkdir()
            target_path = config_root / "role-target"
            target_path.write_text("version=1\nrole=LOCAL\n", encoding="utf-8")
            os.chmod(target_path, 0o600)
            active_path = config_root / ACTIVE_CONFIG_DIRECTORY / ACTIVE_CONFIG_NAME
            active_path.parent.mkdir()
            active_path.symlink_to(target_path)
            result = self.run_control(config_root, "boot-decision")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "INERT_INVALID_CONFIG\n")

    def test_symlinked_root_fails_inert(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            target_root = temporary_root / "target-root"
            target_root.mkdir()
            self.write_config(target_root, "version=1\nrole=LOCAL\n")
            linked_root = temporary_root / "linked-root"
            linked_root.symlink_to(target_root, target_is_directory=True)
            result = self.run_control(linked_root, "boot-decision")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "INERT_INVALID_CONFIG\n")

    def test_symlinked_config_directory_fails_inert(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            config_root.mkdir()
            target_directory = temporary_root / "role-target"
            target_directory.mkdir()
            target_config = target_directory / ACTIVE_CONFIG_NAME
            target_config.write_text("version=1\nrole=LOCAL\n", encoding="utf-8")
            os.chmod(target_config, 0o600)
            (config_root / ACTIVE_CONFIG_DIRECTORY).symlink_to(target_directory, target_is_directory=True)
            result = self.run_control(config_root, "boot-decision")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "INERT_INVALID_CONFIG\n")

    def test_set_role_rejects_symlinked_root(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            target_root = temporary_root / "target-root"
            target_root.mkdir()
            self.write_config(target_root, "version=1\nrole=LOCAL\n")
            linked_root = temporary_root / "linked-root"
            linked_root.symlink_to(target_root, target_is_directory=True)
            result = self.run_control(linked_root, "set-role", "DONOR")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "INERT_INVALID_CONFIG\n")

    def test_set_role_rejects_symlinked_config_directory(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            config_root.mkdir()
            target_directory = temporary_root / "role-target"
            target_directory.mkdir()
            (config_root / ACTIVE_CONFIG_DIRECTORY).symlink_to(target_directory, target_is_directory=True)
            result = self.run_control(config_root, "set-role", "DONOR")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "INERT_INVALID_CONFIG\n")

    def test_oversized_config_fails_inert(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            config_root = Path(temporary_directory) / "tricky_store"
            config_root.mkdir()
            self.write_config(config_root, "version=1\nrole=LOCAL\n" + ("x" * 4096))
            result = self.run_control(config_root, "boot-decision")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "INERT_INVALID_CONFIG\n")

    def test_invalid_write_preserves_last_valid_file(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            config_root = Path(temporary_directory) / "tricky_store"
            first_write = self.run_control(config_root, "set-role", "CANDIDATE")
            config_path = config_root / ACTIVE_CONFIG_DIRECTORY / ACTIVE_CONFIG_NAME
            valid_content = config_path.read_text(encoding="utf-8")
            invalid_write = self.run_control(config_root, "set-role", "UNKNOWN")
            final_content = config_path.read_text(encoding="utf-8")

        self.assertEqual(first_write.returncode, 0)
        self.assertNotEqual(invalid_write.returncode, 0)
        self.assertEqual(final_content, valid_content)

    def test_donor_provision_command_binds_device_properties_and_fixed_paths(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "teesimulator-rka"
            self.assertEqual(
                self.run_control(
                    config_root,
                    "--state-root",
                    str(state_root),
                    "set-role",
                    "DONOR",
                ).returncode,
                0,
            )
            self.assertEqual(
                self.run_control(
                    config_root,
                    "--state-root",
                    str(state_root),
                    "initialize",
                ).returncode,
                0,
            )
            direct_profile = state_root / "profiles" / "direct.conf"
            direct_profile.write_text(
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
            os.chmod(direct_profile, 0o600)
            commands = temporary_root / "commands"
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
            sidecar = commands / "rka-sidecar"
            observed = temporary_root / "provision.env"
            sidecar.write_text(
                "#!/bin/sh\n"
                "[ \"$1\" = provision ] || exit 2\n"
                "printf '%s\\n' \"$RKA_PROVISIONING_BASE\" \"$RKA_DONOR_SOCKET\" \"$RKA_VALIDATOR_PKCS8\" \"$RKA_KEY_COUNT\" > \"$RKA_TEST_ENV\"\n"
                "printf '%s\\n' 'role=donor status=READY' 'RESULT=PROVISIONED'\n",
                encoding="ascii",
            )
            for executable in (getprop, sidecar):
                os.chmod(executable, 0o700)
            broker_socket = state_root / "run" / "sockets" / "broker.sock"
            environment = os.environ | {
                "RKA_GETPROP": str(getprop),
                "RKA_SIDECAR": str(sidecar),
                "RKA_TEST_ENV": str(observed),
            }
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(broker_socket))
                os.chmod(broker_socket, 0o600)
                result = self.run_control(
                    config_root,
                    "--state-root",
                    str(state_root),
                    "provision-rkp",
                    environment=environment,
                )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "role=donor status=READY\nRESULT=PROVISIONED\n")
            self.assertEqual(
                observed.read_text(encoding="ascii"),
                "https://remoteprovisioning.googleapis.com/v1\n"
                f"{broker_socket}\n"
                f"{state_root / 'secrets' / 'validator.pk8'}\n"
                "1\n",
            )
            self.assertEqual(
                (state_root / "journal" / "provisioning.state").read_text(encoding="ascii"),
                "version=1\nstatus=PROVISIONED\nprofile_epoch=0\nkey_count=1\n",
            )

    def test_set_role_fsync_failure_preserves_last_valid_file(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            self.assertEqual(self.run_control(config_root, "set-role", "DONOR").returncode, 0)
            config_path = config_root / ACTIVE_CONFIG_DIRECTORY / ACTIVE_CONFIG_NAME
            valid_content = config_path.read_text(encoding="utf-8")
            command_directory = temporary_root / "commands"
            command_directory.mkdir()
            sync_command = command_directory / "sync"
            sync_command.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            os.chmod(sync_command, 0o700)
            environment = os.environ | {"PATH": f"{command_directory}:{os.environ['PATH']}"}

            failed_write = self.run_control(
                config_root, "set-role", "CANDIDATE", environment=environment
            )
            final_content = config_path.read_text(encoding="utf-8")

        self.assertNotEqual(failed_write.returncode, 0)
        self.assertEqual(final_content, valid_content)
