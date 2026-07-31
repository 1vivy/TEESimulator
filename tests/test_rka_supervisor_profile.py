from __future__ import annotations

import unittest

from tests import test_rka_supervisor


class RkaSupervisorProfileConsumerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = test_rka_supervisor.RkaSupervisorTest()

    def test_sidecar_consumes_direct_profile_with_active_epoch(self) -> None:
        temporary, root, state = self.harness.fixture("DONOR")
        try:
            self.assertEqual(self.harness.command(root, state, "start").returncode, 0)
            child_log = (root / "children.log").read_text(encoding="utf-8")
            self.assertIn(f"RKA_PROFILE_PATH={state / 'profiles' / 'direct.conf'}", child_log)
            self.assertIn("RKA_EXPECTED_PROFILE_EPOCH=0", child_log)
            self.assertIn(
                f"RKA_PROFILE_RECEIPT_PATH={state / 'run' / 'direct-profile.receipt'}",
                child_log,
            )
        finally:
            self.harness.clean(root, state)
            temporary.cleanup()

    def test_missing_malformed_or_stale_direct_profile_starts_nothing(self) -> None:
        profiles = (
            None,
            "version=1\nrole=DONOR\nprofile_epoch=0\n",
            "version=1\nrole=DONOR\nprofile_epoch=1\n"
            "peer_endpoint=192.0.2.44\n"
            f"peer_spki_sha256={'ab' * 32}\n"
            "transport=DIRECT\n",
        )
        for direct_profile in profiles:
            temporary, root, state = self.harness.fixture("DONOR")
            try:
                path = state / "profiles" / "direct.conf"
                if direct_profile is None:
                    path.unlink()
                else:
                    path.write_text(direct_profile, encoding="utf-8")
                result = self.harness.command(root, state, "start")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "children.log").exists())
            finally:
                self.harness.clean(root, state)
                temporary.cleanup()
