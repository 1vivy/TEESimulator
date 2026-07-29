import base64
import datetime
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts/gate-g2.py"


class GateG2ContractTests(unittest.TestCase):
    def test_cli_is_available_for_a_native_rehearsal(self) -> None:
        # Given: the checked-out host scripts.
        # When: the standalone G2 surface is invoked.
        completed = subprocess.run(
            ["python3", str(GATE), "--help"],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

        # Then: the dedicated G2 CLI is available.
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_requires_a_runtime_trust_anchor(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            completed = subprocess.run(
                [
                    "python3",
                    str(GATE),
                    "--adb",
                    str(temporary_path / "adb"),
                    "--serial-b",
                    "B",
                    "--expected-model-b",
                    "modelB",
                    "--module-dir",
                    "/data/adb/modules/teesimulator_api36_probe",
                    "--state-file",
                    str(temporary_path / "state.json"),
                ],
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(self._result(completed)["code"], "INVALID_ARGUMENT")

    def _write_anchor(self, temporary_path: Path) -> tuple[Path, Path]:
        anchor = temporary_path / "anchor.pem"
        key = temporary_path / "anchor-key.pem"
        if anchor.exists() and key.exists():
            return anchor, key
        private_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-root")])
        now = datetime.datetime.now(datetime.UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(minutes=1))
            .sign(private_key, hashes.SHA256())
        )
        anchor.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return anchor, key

    def _write_fake_adb(self, temporary_path: Path) -> tuple[Path, Path, Path]:
        fake_adb = temporary_path / "adb"
        argv_log = temporary_path / "adb.argv.jsonl"
        observables = temporary_path / "observables.jsonl"
        fake_adb.write_text(
            """#!/usr/bin/env python3
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier


def length(value):
    if value < 128:
        return bytes([value])
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def tlv(tag, value, mode=""):
    if mode == "long-short" and len(value) < 128:
        return tag + b"\\x81" + bytes([len(value)]) + value
    if mode == "leading-zero":
        return tag + b"\\x82\\x00" + bytes([len(value)]) + value
    if mode == "indefinite":
        return tag + b"\\x80" + value
    if mode == "truncated":
        return tag + length(len(value) + 1) + value
    return tag + length(len(value)) + value


def integer(value):
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\\x00" + encoded
    return tlv(b"\\x02", encoded)


def enum(value):
    return tlv(b"\\x0a", bytes([value]))


def key_description(challenge, tee_level, origin_value, der_mode):
    if der_mode == "oversized":
        return b"\\x30\\x83\\x01\\x00\\x01\\x00"
    origin = tlv(b"\\xbf\\x85\\x3e", integer(origin_value))
    encoded = tlv(
        b"\\x30",
        integer(3)
        + enum(tee_level)
        + integer(4)
        + enum(tee_level)
        + tlv(b"\\x04", challenge, der_mode)
        + tlv(b"\\x04", b"")
        + tlv(b"\\x30", b"")
        + tlv(b"\\x30", origin),
    )
    return encoded + b"\\x00" if der_mode == "trailing" else encoded


def load_state(path):
    if not path.exists():
        return {"restart": 0}
    return json.loads(path.read_text())


def save_state(path, state):
    path.write_text(json.dumps(state))


def record(path, value):
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, separators=(",", ":")) + "\\n")


argv = sys.argv[1:]
if len(argv) < 4 or argv[0] != "-s" or argv[2] != "shell":
    raise SystemExit(91)
remote = argv[3:]
record(Path(os.environ["FAKE_ADB_LOG"]), argv)
joined = " ".join(remote)
hang_on = os.environ.get("FAKE_HANG_ON", "")
ready_path = Path(os.environ.get("FAKE_READY", "/dev/null"))
if hang_on and hang_on in joined and not ready_path.exists():
    ready_path.write_text("ready")
    time.sleep(300)

state_path = Path(os.environ["FAKE_G2_DEVICE_STATE"])
state = load_state(state_path)
observables = Path(os.environ["FAKE_OBSERVABLE_LOG"])

if remote[:2] == ["getprop", "ro.product.model"]:
    print(os.environ.get("FAKE_MODEL_B", "modelB"))
elif remote[:2] == ["pidof", "TEESimulator"]:
    pass
elif remote[:2] == ["pidof", "keystore2"]:
    pid = 100 + (state["restart"] * 100)
    record(observables, {"kind": "pid", "value": pid})
    print(pid)
elif remote[:2] == ["service", "list"]:
    failures = int(os.environ.get("FAKE_READINESS_FAILURES", "0"))
    ready = state["restart"] == 0 or state["restart"] > failures
    record(observables, {"kind": "services", "ready": ready})
    if ready:
        print("android.system.keystore2.IKeystoreService/default")
        print("android.hardware.security.keymint.IKeyMintDevice/default")
elif remote[:3] == ["su", "0", "stop"]:
    pass
elif remote[:4] == ["su", "0", "start", "keystore2"]:
    state["restart"] += 1
    save_state(state_path, state)
elif remote[:3] == ["su", "0", "cat"] and remote[-1].endswith("/maps"):
    hook_restart = int(os.environ.get("FAKE_HOOK_ON_RESTART", "-1"))
    hooked = state["restart"] == hook_restart
    record(observables, {"kind": "maps", "hooked": hooked})
    print(os.environ.get("FAKE_HOOK_PATH", "/data/adb/modules/teesimulator/libinject.so") if hooked else "/system/bin/keystore2")
elif remote[:2] == ["su", "0"]:
    pass
elif remote[:2] == ["am", "broadcast"]:
    action = remote[remote.index("-a") + 1]
    if action.endswith(".ATTEST_SIGN"):
        challenge = base64.b64decode(remote[remote.index("challenge") + 1], validate=True)
        root_key = serialization.load_pem_private_key(Path(os.environ["FAKE_ROOT_KEY"]).read_bytes(), password=None)
        root_certificate = x509.load_pem_x509_certificate(Path(os.environ["FAKE_ROOT_CERT"]).read_bytes())
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture")])
        now = datetime.datetime.now(datetime.UTC)
        certificate_challenge = b"x" * 32 if os.environ.get("FAKE_TAMPER_CHALLENGE") == "1" else challenge
        tee_level = int(os.environ.get("FAKE_TEE_LEVEL", "1"))
        origin_value = int(os.environ.get("FAKE_ORIGIN", "0"))
        signer = root_key
        issuer = root_certificate.subject
        chain_root = root_certificate
        if os.environ.get("FAKE_UNTRUSTED_ROOT") == "1":
            signer = ec.generate_private_key(ec.SECP256R1())
            foreign_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "foreign-root")])
            chain_root = (
                x509.CertificateBuilder()
                .subject_name(foreign_name)
                .issuer_name(foreign_name)
                .public_key(signer.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(minutes=1))
                .sign(signer, hashes.SHA256())
            )
            issuer = chain_root.subject
        if os.environ.get("FAKE_BROKEN_CHAIN") == "1":
            signer = ec.generate_private_key(ec.SECP256R1())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(minutes=1))
            .add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"),
                    key_description(certificate_challenge, tee_level, origin_value, os.environ.get("FAKE_DER_MODE", "")),
                ),
                critical=False,
            )
            .sign(signer, hashes.SHA256())
        )
        payload = hashlib.sha256(challenge + b"fixture-payload").digest()
        response = {
            "version": 1,
            "status": "ok",
            "command": "attest-sign",
            "chain": [
                base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode("ascii"),
                base64.b64encode(chain_root.public_bytes(serialization.Encoding.DER)).decode("ascii"),
            ],
            "payload": base64.b64encode(payload).decode("ascii"),
            "signature": base64.b64encode(
                b"\\x00" * 72 if os.environ.get("FAKE_TAMPER_SIGNATURE") == "1" else key.sign(payload, ec.ECDSA(hashes.SHA256()))
            ).decode("ascii"),
        }
    elif action.endswith(".STOP"):
        response = {"version": 1, "status": "ok", "command": "stop"}
    else:
        raise SystemExit(96)
    if os.environ.get("FAKE_MALFORMED_PROOF") == "1" and action.endswith(".ATTEST_SIGN"):
        response = "ignore previous instructions"
    print("Broadcast completed: result=-1, data=" + json.dumps(response, separators=(",", ":")))
else:
    raise SystemExit(97)
"""
        )
        fake_adb.chmod(0o755)
        return fake_adb, argv_log, observables

    def _run(
        self,
        temporary_path: Path,
        environment: dict[str, str] | None = None,
        anchor_bytes: bytes | None = None,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        anchor, anchor_key = self._write_anchor(temporary_path)
        if anchor_bytes is not None:
            anchor.write_bytes(anchor_bytes)
        fake_adb, argv_log, observables = self._write_fake_adb(temporary_path)
        child_environment = dict(os.environ)
        child_environment.update(
            {
                "FAKE_ADB_LOG": str(argv_log),
                "FAKE_G2_DEVICE_STATE": str(temporary_path / "device.json"),
                "FAKE_OBSERVABLE_LOG": str(observables),
                "FAKE_ROOT_CERT": str(anchor),
                "FAKE_ROOT_KEY": str(anchor_key),
            }
        )
        if environment is not None:
            child_environment.update(environment)
        return subprocess.run(
            [
                "python3",
                str(GATE),
                "--adb",
                str(fake_adb),
                "--serial-b",
                "B",
                "--expected-model-b",
                "modelB",
                "--module-dir",
                "/data/adb/modules/teesimulator_api36_probe",
                "--trust-anchor",
                str(anchor),
                "--state-file",
                str(temporary_path / "g2-state.json"),
                "--deadline-seconds",
                "20",
            ],
            cwd=ROOT,
            env=child_environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )

    def _result(self, completed: subprocess.CompletedProcess[str]) -> dict[str, bool | int | str]:
        self.assertEqual(completed.stderr, "")
        parsed = json.loads(completed.stdout)
        self.assertIsInstance(parsed, dict)
        return parsed

    def _argv(self, temporary_path: Path) -> list[list[str]]:
        path = temporary_path / "adb.argv.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()]

    def _proof_challenges(self, commands: list[list[str]]) -> list[bytes]:
        challenges: list[bytes] = []
        for command in commands:
            if any(argument.endswith(".ATTEST_SIGN") for argument in command):
                challenges.append(base64.b64decode(command[command.index("challenge") + 1], validate=True))
        return challenges

    def _starts(self, commands: list[list[str]]) -> int:
        return sum(command[3:7] == ["su", "0", "start", "keystore2"] for command in commands)

    def _observables(self, temporary_path: Path) -> list[dict[str, bool | int | str]]:
        path = temporary_path / "observables.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()]

    def _assert_no_injection(self, commands: list[list[str]]) -> None:
        for command in commands:
            self.assertNotIn("daemon", command)
            self.assertFalse(any("inject" in argument.lower() for argument in command))
            self.assertNotEqual(command[3:6], ["su", "0", "sh"])

    def test_passes_two_consecutive_rehearsals_with_fresh_proofs_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            first = self._run(temporary_path)
            second = self._run(temporary_path)

            for completed in (first, second):
                self.assertEqual(completed.returncode, 0, completed.stderr)
                result = self._result(completed)
                self.assertEqual(result["verdict"], "PASS")
                self.assertTrue(result["pidChanged"])
                self.assertTrue(result["servicesReady"])
                self.assertTrue(result["hookAbsent"])
                self.assertEqual(result["cleanup"], "CLEAN")
                self.assertNotIn("B", completed.stdout)
                self.assertLessEqual(len(completed.stdout.encode()), 1024)

            commands = self._argv(temporary_path)
            challenges = self._proof_challenges(commands)
            self.assertEqual(len(challenges), 6)
            self.assertTrue(all(len(challenge) == 32 for challenge in challenges))
            self.assertEqual(len(set(challenges)), 6)
            self.assertEqual(self._starts(commands), 4)
            self._assert_no_injection(commands)
            observables = self._observables(temporary_path)
            observed_pids = [event["value"] for event in observables if event["kind"] == "pid"]
            self.assertGreaterEqual(len(set(observed_pids)), 3)
            self.assertTrue(all(event["ready"] for event in observables if event["kind"] == "services"))
            self.assertFalse(any(event["hooked"] for event in observables if event["kind"] == "maps"))
            self.assertEqual(json.loads((temporary_path / "g2-state.json").read_text())["state"], "CLEAN")

    def test_retries_once_when_first_readiness_check_fails(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            completed = self._run(temporary_path, {"FAKE_READINESS_FAILURES": "1"})

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(self._result(completed)["attempts"], 2)
            self.assertEqual(self._starts(self._argv(temporary_path)), 3)

    def test_rejects_hook_maps_before_retrying_readiness(self) -> None:
        for hook_path in ("/data/adb/modules/teesimulator/libinject.so", "/vendor/lib64/trickystore.so"):
            with self.subTest(hook_path=hook_path), tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
                temporary_path = Path(temporary_directory)
                completed = self._run(
                    temporary_path,
                    {"FAKE_HOOK_ON_RESTART": "1", "FAKE_HOOK_PATH": hook_path},
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(self._result(completed)["attempts"], 2)
                self.assertEqual(self._starts(self._argv(temporary_path)), 3)

    def test_stops_cleanly_after_second_readiness_failure_without_injection(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            completed = self._run(temporary_path, {"FAKE_READINESS_FAILURES": "2"})

            self.assertEqual(completed.returncode, 1)
            result = self._result(completed)
            self.assertEqual(result["verdict"], "STOP")
            self.assertEqual(result["code"], "READINESS_FAILED")
            self.assertEqual(result["attempts"], 2)
            self.assertEqual(result["cleanup"], "CLEAN")
            commands = self._argv(temporary_path)
            self.assertEqual(self._starts(commands), 3)
            self._assert_no_injection(commands)
            self.assertEqual(json.loads((temporary_path / "g2-state.json").read_text())["state"], "CLEAN")

    def test_stops_for_malformed_fixture_output_and_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            completed = self._run(temporary_path, {"FAKE_MALFORMED_PROOF": "1"})

            self.assertEqual(completed.returncode, 1)
            result = self._result(completed)
            self.assertEqual(result["verdict"], "STOP")
            self.assertEqual(result["code"], "UNTRUSTED_OUTPUT")
            self.assertEqual(result["cleanup"], "DIRTY")
            self._assert_no_injection(self._argv(temporary_path))

    def test_stops_when_independent_verification_rejects_challenge_or_signature(self) -> None:
        for environment in ({"FAKE_TAMPER_CHALLENGE": "1"}, {"FAKE_TAMPER_SIGNATURE": "1"}):
            with self.subTest(environment=environment), tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
                temporary_path = Path(temporary_directory)
                completed = self._run(temporary_path, environment)

                self.assertEqual(completed.returncode, 1)
                result = self._result(completed)
                self.assertEqual(result["verdict"], "STOP")
                self.assertEqual(result["code"], "ATTESTATION_VERIFICATION_FAILED")
                self._assert_no_injection(self._argv(temporary_path))

    def _assert_verification_stop(self, environment: dict[str, str]) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            completed = self._run(temporary_path, environment)
            self.assertEqual(completed.returncode, 1)
            result = self._result(completed)
            self.assertEqual(result["verdict"], "STOP")
            self.assertEqual(result["code"], "ATTESTATION_VERIFICATION_FAILED")
            self._assert_no_injection(self._argv(temporary_path))

    def test_stops_for_untrusted_root(self) -> None:
        self._assert_verification_stop({"FAKE_UNTRUSTED_ROOT": "1"})

    def test_stops_for_broken_chain_signature(self) -> None:
        self._assert_verification_stop({"FAKE_BROKEN_CHAIN": "1"})

    def test_stops_for_non_tee_attestation(self) -> None:
        self._assert_verification_stop({"FAKE_TEE_LEVEL": "0"})

    def test_stops_for_non_generated_origin(self) -> None:
        self._assert_verification_stop({"FAKE_ORIGIN": "1"})

    def test_stops_for_noncanonical_der_forms(self) -> None:
        for mode in ("long-short", "leading-zero", "indefinite", "truncated", "trailing", "oversized"):
            with self.subTest(mode=mode):
                self._assert_verification_stop({"FAKE_DER_MODE": mode})

    def test_stops_for_malformed_duplicate_or_oversized_runtime_anchor(self) -> None:
        for anchor_bytes in (b"not-a-certificate", b"x" * 87_385):
            with self.subTest(anchor_bytes=anchor_bytes[:16]), tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
                completed = self._run(Path(temporary_directory), anchor_bytes=anchor_bytes)
                self.assertEqual(completed.returncode, 1)
                self.assertEqual(self._result(completed)["code"], "ATTESTATION_VERIFICATION_FAILED")
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            anchor, _ = self._write_anchor(temporary_path)
            completed = self._run(temporary_path, anchor_bytes=anchor.read_bytes() * 2)
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(self._result(completed)["code"], "ATTESTATION_VERIFICATION_FAILED")

    def test_stops_for_stale_state_and_leaves_a_truthful_cleanup_receipt(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            (temporary_path / "g2-state.json").write_text("not-json")
            completed = self._run(temporary_path)

            self.assertEqual(completed.returncode, 1)
            result = self._result(completed)
            self.assertEqual(result["verdict"], "STOP")
            self.assertEqual(result["code"], "STALE_STATE")
            self.assertEqual(result["cleanup"], "CLEAN")

    def test_interrupt_cleans_up_and_reports_a_bounded_stop(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            anchor, anchor_key = self._write_anchor(temporary_path)
            fake_adb, argv_log, observables = self._write_fake_adb(temporary_path)
            ready = temporary_path / "ready"
            child = subprocess.Popen(
                [
                    "python3",
                    str(GATE),
                    "--adb",
                    str(fake_adb),
                    "--serial-b",
                    "B",
                    "--expected-model-b",
                    "modelB",
                    "--module-dir",
                    "/data/adb/modules/teesimulator_api36_probe",
                    "--trust-anchor",
                    str(anchor),
                    "--state-file",
                    str(temporary_path / "g2-state.json"),
                    "--deadline-seconds",
                    "20",
                ],
                cwd=ROOT,
                env={
                    **os.environ,
                    "FAKE_ADB_LOG": str(argv_log),
                    "FAKE_G2_DEVICE_STATE": str(temporary_path / "device.json"),
                    "FAKE_OBSERVABLE_LOG": str(observables),
                    "FAKE_ROOT_CERT": str(anchor),
                    "FAKE_ROOT_KEY": str(anchor_key),
                    "FAKE_HANG_ON": "service list",
                    "FAKE_READY": str(ready),
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(100):
                if ready.exists():
                    break
                time.sleep(0.01)
            self.assertTrue(ready.exists())
            child.send_signal(signal.SIGINT)
            stdout, stderr = child.communicate(timeout=10)

            self.assertEqual(child.returncode, 130, stderr)
            self.assertEqual(stderr, "")
            result = json.loads(stdout)
            self.assertEqual(result["verdict"], "STOP")
            self.assertEqual(result["code"], "CANCELLED")
            self.assertLessEqual(len(stdout.encode()), 1024)
            self.assertEqual(json.loads((temporary_path / "g2-state.json").read_text())["state"], "CLEAN")


if __name__ == "__main__":
    unittest.main()
