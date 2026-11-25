"""Offline tests for the key inventory, .env loading and masking."""

import os
import tempfile
import unittest
from pathlib import Path

from specter.config import KEYS, Config, load_env_file
from specter.keys import inventory


class EnvFileTests(unittest.TestCase):
    def test_values_are_loaded_without_overwriting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / ".env"
            env.write_text(
                "# comment\nGITHUB_TOKEN=from-file\nSPECTER_TEST_VALUE=\"quoted value\"\n",
                encoding="utf-8",
            )
            os.environ["GITHUB_TOKEN"] = "from-shell"
            os.environ.pop("SPECTER_TEST_VALUE", None)
            try:
                loaded = load_env_file(env)
                self.assertEqual(os.environ["GITHUB_TOKEN"], "from-shell")
                self.assertEqual(os.environ["SPECTER_TEST_VALUE"], "quoted value")
                self.assertEqual(loaded, ["SPECTER_TEST_VALUE"])
            finally:
                os.environ.pop("SPECTER_TEST_VALUE", None)
                os.environ.pop("GITHUB_TOKEN", None)

    def test_missing_file_is_ignored(self) -> None:
        self.assertEqual(load_env_file(Path(tempfile.gettempdir()) / "no-such.env"), [])


class KeyInventoryTests(unittest.TestCase):
    def test_every_key_documents_a_free_tier_and_signup(self) -> None:
        for spec in KEYS:
            self.assertTrue(spec.signup.startswith("https://"), spec.key)
            self.assertTrue(spec.free, spec.key)

    def test_missing_keys_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Config(Path(tmp) / "config.json")
            for spec in KEYS:
                os.environ.pop(spec.env, None)
            rows = inventory(config)
            self.assertEqual({row.state for row in rows}, {"missing"})
            self.assertEqual(len(rows), len(KEYS))

    def test_secrets_are_masked_and_never_printed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Config(Path(tmp) / "config.json")
            os.environ.pop("GITHUB_TOKEN", None)
            config.set("github_token", "ghp_supersecretvalue1234567890")
            rows = {row.key: row for row in inventory(config)}
            self.assertEqual(rows["github_token"].state, "set")
            self.assertNotIn("supersecretvalue", rows["github_token"].detail)
            self.assertTrue(rows["github_token"].detail.startswith("ghp_"))

    def test_check_mode_validates_only_configured_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Config(Path(tmp) / "config.json")
            for spec in KEYS:
                os.environ.pop(spec.env, None)
            rows = inventory(config, http=None, check=True)
            self.assertTrue(all(row.state == "missing" for row in rows))

    def test_env_example_lists_variables_without_values(self) -> None:
        from specter.keys import env_example

        text = env_example()
        for spec in KEYS:
            self.assertIn(f"{spec.env}=\n", text)
            self.assertIn(spec.signup, text)


if __name__ == "__main__":
    unittest.main()
