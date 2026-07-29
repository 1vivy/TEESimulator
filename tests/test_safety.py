from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

class SafetyTests(unittest.TestCase):
    def test_no_bundled_keybox(self):
        self.assertFalse((ROOT / "module/keybox.xml").exists())
        for path in (ROOT / "module").rglob("*"):
            if path.is_file():
                self.assertNotIn("<Keybox", path.read_text(errors="ignore"))

    def test_boot_and_action_cannot_inject(self):
        service = (ROOT / "module/service.sh").read_text()
        action = (ROOT / "module/action.sh").read_text()
        for forbidden in ("./daemon", "./inject", "app_process", "ptrace"):
            self.assertNotIn(forbidden, service)
            self.assertNotIn(forbidden, action)

    def test_probe_has_no_mutating_adb_verbs(self):
        probe = (ROOT / "scripts/probe-api36.sh").read_text()
        for forbidden in (r"\badb\s+push\b", r"\badb\s+reboot\b", r"\bshell\s+setprop\b",
                          r"\bshell\s+(?:start|stop)\s+keystore", r"/data/local/tmp",
                          r"remote_provisioning", r"\bcsr\b", r"\bcertify\b"):
            self.assertIsNone(re.search(forbidden, probe, re.IGNORECASE))

        probe_sources = tuple(sorted((ROOT / "scripts").rglob("probe-api36*.sh")))
        self.assertIn(ROOT / "scripts/probe-api36.sh", probe_sources)
        for source in probe_sources:
            contents = source.read_text()
            for forbidden in (r"\badb\s+push\b", r"\badb\s+reboot\b", r"\bshell\s+setprop\b",
                              r"\bshell\s+(?:start|stop)\s+keystore", r"/data/local/tmp",
                              r"remote_provisioning", r"\bcsr\b", r"\bcertify\b"):
                with self.subTest(source=source, forbidden=forbidden):
                    self.assertIsNone(re.search(forbidden, contents, re.IGNORECASE))

    def test_verify_parses_probe_library(self):
        verifier = (ROOT / "scripts/verify.sh").read_text()
        self.assertIn("scripts/probe-api36-lib.sh", verifier)

    def test_exact_profile_gate(self):
        profile = (ROOT / "profiles/api36-arm64-qcom-default-v1.conf").read_text()
        for expected in ("SDK=36", "ABI=arm64-v8a", "DEFAULT_INSTANCE=", "MAX_OPERATIONS=1",
                         "DEADLINE_SECONDS=120"):
            self.assertIn(expected, profile)

    def test_current_g0_modules_are_registered(self):
        settings = (ROOT / "settings.gradle.kts").read_text()
        self.assertIn('include(":two-phone")', settings)
        self.assertIn('include(":physical-harness")', settings)

    def test_two_phone_architecture_keeps_device_paths_inert(self):
        architecture = (ROOT / "docs/TWO_PHONE_ARCHITECTURE.md").read_text()
        for expected in (
            "cannot arbitrary-sign",
            "corresponding donor app process",
            "ATTESTATION_APPLICATION_ID",
            "fails closed",
            "StrongBox",
            "AVF",
        ):
            self.assertIn(expected, architecture)

        routing = (ROOT / "two-phone/src/main/kotlin/org/matrix/teesimulator/twophone/Routing.kt").read_text()
        self.assertIn("PLATFORM_BYTE_FOR_BYTE", routing)
        self.assertIn("localFallbackCount", routing)
        self.assertNotIn("android.os.Parcel", routing)

    def test_protocol_has_no_private_material_or_raw_binder(self):
        protocol = (ROOT / "two-phone/src/main/kotlin/org/matrix/teesimulator/twophone/Protocol.kt").read_text()
        self.assertNotIn("android.os.Parcel", protocol)
        self.assertNotIn("PRIVATE KEY", protocol)
        self.assertNotIn("donorAlias", protocol)

    def test_host_orchestrator_has_no_compiled_device_route_or_shell_escape(self):
        host_sources = tuple(sorted((*((ROOT / "scripts").glob("two_phone*.py")), ROOT / "scripts/gate-g2.py")))
        self.assertEqual(
            {path.name for path in host_sources},
            {
                "two_phone_adb.py",
                "two_phone_attestation.py",
                "two_phone_cleanup.py",
                "two_phone_fixture.py",
                "two_phone_g2.py",
                "two_phone_lifecycle.py",
                "two_phone_run.py",
                "two_phone_state.py",
                "two_phone_types.py",
                "gate-g2.py",
            },
        )
        for source in host_sources:
            contents = source.read_text()
            for forbidden in (
                "3C15AT003ZB00000",
                "100.104.29.92",
                "10.9.11.113",
                "shell=True",
                "eval(",
                "android.os.Parcel",
                "PRIVATE KEY",
                "StrongBox",
                "remote_provisioning",
            ):
                with self.subTest(source=source, forbidden=forbidden):
                    self.assertNotIn(forbidden, contents)

if __name__ == "__main__":
    unittest.main()
