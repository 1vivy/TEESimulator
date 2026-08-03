import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ReleasePlatformStubTest(unittest.TestCase):
    def test_hidden_keystore_parcelables_keep_boot_class_names(self) -> None:
        rules = (ROOT / "app" / "proguard-rules.pro").read_text(encoding="utf-8")

        self.assertIn(
            "-keep class android.hardware.security.keymint.** { *; }",
            rules,
        )
        self.assertIn(
            "-keep class android.system.keystore2.** { *; }",
            rules,
        )


if __name__ == "__main__":
    unittest.main()
