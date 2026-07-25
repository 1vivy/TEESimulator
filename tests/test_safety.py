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

    def test_exact_profile_gate(self):
        profile = (ROOT / "profiles/api36-arm64-qcom-default-v1.conf").read_text()
        for expected in ("SDK=36", "ABI=arm64-v8a", "DEFAULT_INSTANCE=", "MAX_OPERATIONS=1",
                         "DEADLINE_SECONDS=120"):
            self.assertIn(expected, profile)

if __name__ == "__main__":
    unittest.main()
