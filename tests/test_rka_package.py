from __future__ import annotations

import hashlib
import base64
import os
import socket
import threading
from pathlib import Path
from shutil import copy2
from subprocess import CompletedProcess, run
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_MANIFEST = REPOSITORY_ROOT / "module" / "rka-runtime.manifest"
SEPOLICY_RULE = REPOSITORY_ROOT / "module" / "sepolicy.rule"
SEPOLICY_PROBES = REPOSITORY_ROOT / "module" / "sepolicy.probes"
SEPOLICY_LIVE_PROBE = REPOSITORY_ROOT / "module" / "rka-sepolicy-probe.sh"
FIXED_EPOCH = "1785486225"


class RkaPackageTest(unittest.TestCase):
    def test_ksu_next_policy_applies_without_rejected_legacy_targets(self) -> None:
        rules = [
            line
            for line in SEPOLICY_RULE.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]

        rejects = self.fake_ksu_next_apply(rules)

        self.assertEqual(rejects, [])
        self.assertEqual(len(rules), 10)
        self.assertFalse(any("magisk" in rule for rule in rules))
        self.assertFalse(any("tcp_socket" in rule or "udp_socket" in rule for rule in rules))
        self.assertIn(
            "allow ksu ksu unix_stream_socket { create bind connect listen accept read write getattr getopt setopt shutdown }",
            rules,
        )

    def test_clean_release_build_writes_root_receipt_for_release_archive(self) -> None:
        result = run(
            ["./gradlew", "clean", "zipRelease", "--rerun-tasks"],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            env=os.environ | {"SOURCE_DATE_EPOCH": FIXED_EPOCH},
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        archive = self.current_archives()["Release"]
        receipt = REPOSITORY_ROOT / "build" / "rka-release.sha256"
        self.assertEqual(
            receipt.read_text(encoding="ascii"),
            f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  out/{archive.name}\n",
        )

    def test_sepolicy_probe_manifest_is_complete_bounded_and_live(self) -> None:
        rules = [
            line
            for line in SEPOLICY_RULE.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        probes = [line.split("|", 1) for line in SEPOLICY_PROBES.read_text(encoding="ascii").splitlines()]
        self.assert_probe_manifest_contract(rules, probes)
        with self.assertRaises(AssertionError):
            self.assert_probe_manifest_contract(rules, probes[:-1])
        with self.assertRaises(AssertionError):
            self.assert_probe_manifest_contract(rules, probes + [probes[0]])
        with self.assertRaises(AssertionError):
            self.assert_probe_manifest_contract(rules, probes[:-1] + [probes[0]])
        self.assertTrue(SEPOLICY_LIVE_PROBE.is_file())
        self.assertEqual(SEPOLICY_LIVE_PROBE.stat().st_mode & 0o777, 0o755)
        deploy = (REPOSITORY_ROOT / "scripts" / "rka-deploy.sh").read_text(encoding="utf-8")
        paired_start = deploy.index('RKA_REQUIRE_DIRECT_READY=true RKA_DIRECT_PROFILE_PATH="$state/profiles/direct.conf"')
        self.assertGreater(paired_start, deploy.index("ksud sepolicy apply"))
        self.assertGreater(deploy.index("timeout 5 nsenter -t 1 -m -- sh -eu -c"), paired_start)
        helper = SEPOLICY_LIVE_PROBE.read_text(encoding="utf-8")
        rule_by_digest = {hashlib.sha256(rule.encode()).hexdigest(): rule for rule in rules}
        dispatch = {
            line.split(") ", 1)[0].strip(): line.split(") ", 1)[1].split(" ", 1)[0]
            for line in helper.splitlines()
            if line.startswith("    ") and ") " in line and len(line.split(") ", 1)[0].strip()) == 64
        }
        self.assertEqual(set(dispatch), set(rule_by_digest))
        self.assertEqual(len(dispatch), len(set(dispatch)))
        for digest, rule in rule_by_digest.items():
            expected = (
                "unix_broker_probe" if "unix_stream_socket" in rule else
                "scratch_transition_probe" if rule.startswith(("type ", "type_transition")) or "teesimulator_rka_socket" in rule else
                "toybox"
            )
            self.assertEqual(dispatch[digest], expected, rule)
        self.assert_live_probe_contract(helper)
        for replacement in (
            ("toybox nc -U -w 2", "toybox stat -c"),
            ("toybox nc -l -U \"$scratch_socket\"", "toybox stat -c"),
            ("scratch=$state/p/$2", "scratch=$state/policy-probes/$1"),
            ("mv \"$scratch/sockets/create\"", "toybox stat -c"),
            ("rm -f \"$scratch_socket\"", ":"),
            ("rmdir \"$scratch\"", ":"),
        ):
            with self.assertRaises(AssertionError):
                self.assert_live_probe_contract(helper.replace(*replacement))
        self.assert_probe_dispatch_contract(helper, rule_by_digest)
        first_case = next(line for line in helper.splitlines() if line.startswith("    ") and ") " in line and len(line.split(") ", 1)[0].strip()) == 64)
        with self.assertRaises(AssertionError):
            self.assert_probe_dispatch_contract(helper.replace(first_case, "", 1), rule_by_digest)
        with self.assertRaises(AssertionError):
            self.assert_probe_dispatch_contract(helper.replace(first_case, f"{first_case}\n{first_case}", 1), rule_by_digest)
        with self.assertRaises(AssertionError):
            self.assert_probe_dispatch_contract(helper.replace(" t02 ;;", " t01 ;;", 1), rule_by_digest)

    def test_sepolicy_probe_helper_executes_all_manifest_hashes(self) -> None:
        hashes = [line.split("|", 1)[0] for line in SEPOLICY_PROBES.read_text(encoding="ascii").splitlines()]
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            suffix = "/p/t01/sockets/broker.sock"
            state = root / ("x" * (107 - len(str(root)) - 1 - len(suffix)))
            scratch_socket = state / "p" / "t01" / "sockets" / "broker.sock"
            self.assertEqual(len(str(scratch_socket)), 107)
            state.mkdir()
            tools = root / "tools"
            tools.mkdir()
            toybox = tools / "toybox"
            toybox.write_text(
                "#!/bin/sh\ncommand=$1\nshift\ncase $command in nc) exec /usr/bin/nc \"$@\" ;; stat) exec /usr/bin/stat \"$@\" ;; *) exit 64 ;; esac\n",
                encoding="utf-8",
            )
            toybox.chmod(0o755)
            broker = root / "broker.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(broker))
            server.listen()
            server.settimeout(0.1)
            stopping = threading.Event()

            def accept_connections() -> None:
                while not stopping.is_set():
                    try:
                        connection, _ = server.accept()
                    except TimeoutError:
                        continue
                    except OSError:
                        return
                    with connection:
                        pass

            thread = threading.Thread(target=accept_connections, daemon=True)
            thread.start()
            environment = os.environ | {
                "PATH": f"{tools}:{os.environ['PATH']}",
                "RKA_SEPOLICY_PROBE_STATE": str(state),
                "RKA_SEPOLICY_PROBE_SOCKET": str(broker),
            }
            try:
                for digest in hashes:
                    result = run(
                        ["timeout", "5", "sh", str(SEPOLICY_LIVE_PROBE), digest],
                        check=False,
                        capture_output=True,
                        env=environment,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 0, f"{digest}: {result.stderr}")
                self.assertFalse((state / "p").exists())
                hostile_state = root / "state ; * ? [x]"
                hostile_state.mkdir()
                hostile_environment = environment | {"RKA_SEPOLICY_PROBE_STATE": str(hostile_state)}
                result = run(
                    ["timeout", "5", "sh", str(SEPOLICY_LIVE_PROBE), "b25eeb0f71d1a9d04fb60cf3b2693bfac938b5916d1ef774973739925bded4ab"],
                    check=False,
                    capture_output=True,
                    env=hostile_environment,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((hostile_state / "p").exists())
            finally:
                stopping.set()
                server.close()
                thread.join(timeout=1)

    def test_production_validator_rejects_every_tampered_archive_class(self) -> None:
        release = self.current_archives()["Release"]
        mutations = {
            "secret": ("secrets/transport.key", b"secret"),
            "profile": ("profiles/active.conf", b"profile"),
            "trust": ("trust/transport.pem", b"trust"),
            "device_identity": ("device-id.txt", b"identity"),
            "keybox": ("keybox.xml", b"keybox"),
            "persistent": ("persistent_keys/key", b"key"),
            "action": ("action.sh", b"action"),
            "customize": ("customize.sh", b"customize"),
            "diag": ("diag.sh", b"diag"),
            "probe": ("probe-service.sh", b"probe"),
            "companion": ("companion.apk", b"companion"),
            "update": ("update.json", b"{}"),
        }
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            for name, (entry, payload) in mutations.items():
                archive = temporary_root / f"{name}-Release.zip"
                self.copy_archive(release, archive, {entry: payload})
                self.assert_rejected(archive, "FORBIDDEN_ENTRY", name)

            unexpected = temporary_root / "unexpected-Release.zip"
            self.copy_archive(release, unexpected, {"unexpected.txt": b"unexpected"})
            self.assert_rejected(unexpected, "UNEXPECTED_ENTRY", "unexpected")

            for name, payload in {
                "donor": {"rka-role.conf": b"version=1\nrole=DONOR\n"},
                "candidate": {"rka-role.conf": b"version=1\nrole=CANDIDATE\n"},
            }.items():
                archive = temporary_root / f"{name}-Release.zip"
                self.copy_archive(release, archive, payload)
                self.assert_rejected(archive, "ROLE_SPECIFIC", name)
            for name, payload in {
                "private": b"#!/system/bin/sh\nprivate key\n",
                "reboot": b"#!/system/bin/sh\nreboot\n",
                "deploy": b"#!/system/bin/sh\nadb push\n",
                "start": b"#!/system/bin/sh\nstart-service\n",
            }.items():
                archive = temporary_root / f"{name}-Release.zip"
                self.copy_archive(release, archive, {"service.sh": payload})
                self.assert_rejected(archive, "FORBIDDEN_CONTENT", name)

            missing = temporary_root / "missing-Release.zip"
            self.copy_archive(release, missing, {}, {"rka-sidecar"})
            self.assert_rejected(missing, "ENTRY_MISSING", "missing")
            for required_agent_pgp_entry in (
                "rka-agent-pgp-public.gpg",
                "rka-agent-pgp-verify",
            ):
                missing_agent_pgp = temporary_root / f"missing-{required_agent_pgp_entry}-Release.zip"
                self.copy_archive(release, missing_agent_pgp, {}, {required_agent_pgp_entry})
                self.assert_rejected(
                    missing_agent_pgp,
                    "ENTRY_MISSING",
                    required_agent_pgp_entry,
                )
            wrong_mode = temporary_root / "wrong-mode-Release.zip"
            self.copy_archive(release, wrong_mode, {"daemon": b"#!/system/bin/sh\n"}, modes={"daemon": 0o644})
            self.assert_rejected(wrong_mode, "MODE_MISMATCH", "wrong mode")
            missing_webui = temporary_root / "webui-missing-Release.zip"
            self.copy_archive(release, missing_webui, {}, {"webroot/DESIGN.md"})
            self.assert_rejected(missing_webui, "WEBUI_MISSING", "missing webui")
            extra_webui = temporary_root / "webui-extra-Release.zip"
            self.copy_archive(release, extra_webui, {"webroot/nested/extra.txt": b"extra"})
            self.assert_rejected(extra_webui, "WEBUI_EXTRA", "extra webui")
            for name, payload in {
                "schema": b"schema=9\n",
                "roles": b"schema=1\nroles=DONOR\n",
                "all": b"invalid\n",
            }.items():
                archive = temporary_root / f"manifest-{name}-Release.zip"
                self.copy_archive(release, archive, {"rka-runtime.manifest": payload})
                self.assert_rejected(archive, "MANIFEST_MISMATCH", name)

    def test_two_clean_fixed_epoch_release_builds_are_byte_identical(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            first = temporary_root / "first.zip"
            second = temporary_root / "second.zip"
            for destination in (first, second):
                result = run(
                    ["./gradlew", "clean", "zipRelease"],
                    cwd=REPOSITORY_ROOT,
                    check=False,
                    capture_output=True,
                    env=os.environ | {"SOURCE_DATE_EPOCH": FIXED_EPOCH},
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                copy2(self.current_archives()["Release"], destination)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(hashlib.sha256(first.read_bytes()).digest(), hashlib.sha256(second.read_bytes()).digest())

    def test_manifest_webui_modes_and_hashes_exactly_match_release_archive(self) -> None:
        manifest = self.parse_manifest(RUNTIME_MANIFEST)
        self.assertEqual(manifest, {
            "schema": "1", "roles": "LOCAL|DONOR|CANDIDATE", "sidecar_abi": "arm64-v8a",
            "manager_appid_probe": "rka-sidecar:manager-appid",
            "direct_identity": "rka-sidecar:direct-identity", "direct_probe": "rka-sidecar:direct-probe",
            "activation": "staged-by-installer", "runtime_state": "external-root-only",
            "archive_entries": manifest["archive_entries"], "archive_executables": manifest["archive_executables"],
        })
        release = self.current_archives()["Release"]
        source_webroot = {
            f"webroot/{path.relative_to(REPOSITORY_ROOT / 'module' / 'webroot').as_posix()}": path
            for path in (REPOSITORY_ROOT / "module" / "webroot").rglob("*")
            if path.is_file()
        }
        expected_entries = set(manifest["archive_entries"].split(",")) | set(source_webroot) | {"classes.dex"}
        expected_executables = set(manifest["archive_executables"].split(","))
        with ZipFile(release) as archive:
            self.assertEqual(archive.read("rka-runtime.manifest"), RUNTIME_MANIFEST.read_bytes())
            for runtime_entry, arm64_entry in {
                "inject": "lib/arm64-v8a/libinject.so",
                "libTEESimulator.so": "lib/arm64-v8a/libTEESimulator.so",
                "libcertgen.so": "lib/arm64-v8a/libcertgen.so",
                "supervisor": "lib/arm64-v8a/libsupervisor.so",
            }.items():
                self.assertEqual(archive.read(runtime_entry), archive.read(arm64_entry), runtime_entry)
            relevant_entries = {
                info.filename
                for info in archive.infolist()
                if not info.is_dir() and not info.filename.startswith(("lib/", "META-INF/"))
            }
            self.assertEqual(relevant_entries, expected_entries)
            for name, source in source_webroot.items():
                info = archive.getinfo(name)
                self.assertEqual(archive.read(name), source.read_bytes(), name)
                self.assertEqual(info.external_attr >> 16 & 0o777, 0o644, name)
            for info in archive.infolist():
                if info.is_dir() or info.filename.startswith("lib/"):
                    continue
                expected_mode = 0o755 if info.filename in expected_executables else 0o644
                self.assertEqual(info.external_attr >> 16 & 0o777, expected_mode, info.filename)
            hashes = self.parse_hash_manifest(archive.read("META-INF/rka-artifacts.sha256"))
            installed_entries = {
                info.filename
                for info in archive.infolist()
                if not info.is_dir()
                and not info.filename.startswith("META-INF/")
                and info.filename != "customize.sh"
            }
            self.assertEqual(set(hashes), installed_entries)
            for name, expected_hash in hashes.items():
                self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), expected_hash, name)

    def run_validator(self, archive: Path) -> CompletedProcess[str]:
        return run(
            ["./gradlew", "verifyRkaModuleArchive", f"-PrkaArchivePath={archive}"],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_rejected(self, archive: Path, code: str, name: str) -> None:
        result = self.run_validator(archive)
        self.assertNotEqual(result.returncode, 0, name)
        self.assertIn(f"RKA_VALIDATE:{code}", result.stdout + result.stderr, name)

    def copy_archive(
        self,
        source: Path,
        destination: Path,
        replacements: dict[str, bytes],
        removals: set[str] | None = None,
        modes: dict[str, int] | None = None,
    ) -> None:
        removed = removals or set()
        replacement_modes = modes or {}
        with ZipFile(source) as original, ZipFile(destination, "w", ZIP_DEFLATED) as copied:
            for info in original.infolist():
                if info.is_dir() or info.filename in removed:
                    continue
                payload = replacements.get(info.filename, original.read(info.filename))
                entry = ZipInfo(info.filename, info.date_time)
                entry.compress_type = ZIP_DEFLATED
                entry.create_system = info.create_system
                entry.external_attr = ((replacement_modes.get(info.filename, info.external_attr >> 16 & 0o777)) << 16) | 0o100000
                copied.writestr(entry, payload)
            for name, payload in replacements.items():
                if name not in original.namelist():
                    entry = ZipInfo(name)
                    entry.compress_type = ZIP_DEFLATED
                    entry.create_system = 3
                    entry.external_attr = (0o644 << 16) | 0o100000
                    copied.writestr(entry, payload)

    def current_archives(self) -> dict[str, Path]:
        count = int(run(["git", "rev-list", "HEAD", "--count"], cwd=REPOSITORY_ROOT, check=True, capture_output=True, text=True).stdout) + 5
        return {variant: REPOSITORY_ROOT / "out" / f"TEESimulator-RS-v6.0.1-{count}-{variant}.zip" for variant in ("Debug", "Release")}

    def parse_manifest(self, path: Path) -> dict[str, str]:
        return dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines())

    def parse_hash_manifest(self, payload: bytes) -> dict[str, str]:
        return {name: digest for digest, name in (line.split("  ", 1) for line in payload.decode().splitlines())}

    def assert_probe_manifest_contract(self, rules: list[str], probes: list[list[str]]) -> None:
        self.assertEqual(len(probes), len(rules))
        digests = [probe[0] for probe in probes]
        self.assertEqual(len(digests), len(set(digests)))
        self.assertEqual(set(digests), {hashlib.sha256(rule.encode()).hexdigest() for rule in rules})
        for digest, encoded in probes:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            command = base64.b64decode(encoded, validate=True).decode("ascii")
            self.assertEqual(base64.b64encode(command.encode()).decode(), encoded)
            self.assertEqual(command, f"exec /data/adb/modules/tricky_store/rka-sepolicy-probe.sh {digest}")
            self.assertLessEqual(len(command), 256)

    def fake_ksu_next_apply(self, rules: list[str]) -> list[str]:
        rejected_targets = {"self", "node", "port"}
        rejects: list[str] = []
        for rule in rules:
            fields = rule.split()
            if "magisk" in fields:
                rejects.append(f"inactive domain: {rule}")
            elif len(fields) >= 3 and fields[0] == "allow" and fields[1] == "ksu" and fields[2] in rejected_targets:
                rejects.append(f"unknown type: {rule}")
        return rejects

    def assert_live_probe_contract(self, helper: str) -> None:
        for required in (
            "toybox nc -U -w 2 \"$socket\"",
            "mkdir -p \"$scratch/sockets\"",
            "scratch=$state/p/$2",
            "scratch_socket=$scratch/sockets/broker.sock",
            "[ \"${#scratch_socket}\" -le 107 ]",
            "toybox nc -l -U \"$scratch_socket\"",
            "toybox nc -U -w 2 \"$scratch_socket\"",
            "rm -f \"$scratch_socket\"",
            "mv \"$scratch/sockets/create\" \"$scratch/sockets/renamed\"",
            "rm -f \"$scratch/sockets/renamed\"",
            "rmdir \"$scratch\"",
            "rmdir \"$state/p\"",
            "trap cleanup EXIT HUP INT TERM",
            "cleanup",
        ):
            self.assertIn(required, helper)

    def assert_probe_dispatch_contract(self, helper: str, rule_by_digest: dict[str, str]) -> None:
        dispatch: dict[str, str] = {}
        scratch_keys: list[str] = []
        for line in helper.splitlines():
            if not line.startswith("    ") or ") " not in line:
                continue
            digest, action = line.strip().split(") ", 1)
            if len(digest) != 64:
                continue
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertNotIn(digest, dispatch)
            dispatch[digest] = action
            if action.startswith('scratch_transition_probe "$1" '):
                scratch_keys.append(action.removesuffix(" ;;").rsplit(" ", 1)[1])
        self.assertEqual(set(dispatch), set(rule_by_digest))
        self.assertEqual(len(scratch_keys), 6)
        self.assertEqual(len(scratch_keys), len(set(scratch_keys)))
        self.assertEqual(set(scratch_keys), {f"t{index:02d}" for index in range(1, 7)})


if __name__ == "__main__":
    unittest.main()
