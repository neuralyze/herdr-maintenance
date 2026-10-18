from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from maintenance import ci


def lock_fixture() -> dict:
    return {"schema_version": 1, "platform": "linux-x86_64", "products": {
        name: {"repository": repository, "commit": "a" * 40,
               "upstream_repository": "herdrdev/herdr" if name == "herdr" else "nikok6/herdr-mirror",
               "upstream_commit": "b" * 40, "upstream_tag": None}
        for name, repository in ci.PRODUCTS.items()}}


class CIContracts(unittest.TestCase):
    def test_allowlist_never_inherits_auth_cloud_or_action_tokens(self):
        with tempfile.TemporaryDirectory() as temporary:
            poison = {"GITHUB_TOKEN": "secret", "GH_TOKEN": "secret", "ACTIONS_RUNTIME_TOKEN": "secret",
                      "AWS_ACCESS_KEY_ID": "secret", "ANTHROPIC_API_KEY": "secret", "OPENAI_API_KEY": "secret",
                      "SSH_AUTH_SOCK": "/real/agent", "CARGO_REGISTRIES_CRATES_IO_TOKEN": "secret",
                      "GIT_CONFIG_COUNT": "1", "BASH_ENV": "/real/config", "PYTHONPATH": "/real/code"}
            with patch.dict(os.environ, poison):
                environment = ci.clean_environment(Path(temporary), build=True)
            self.assertFalse(set(poison) & set(environment))
            self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(environment["CARGO_HOME"], str(Path(temporary) / "cargo"))
            self.assertEqual(environment["RUSTUP_HOME"], str(Path(temporary) / "rustup"))
            for variable in ("HOME", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "TMPDIR"):
                directory = Path(environment[variable])
                self.assertTrue(directory.is_relative_to(Path(temporary)))
                self.assertEqual(directory.stat().st_mode & 0o077, 0)

    def test_lock_accepts_only_exact_approved_pair(self):
        ci.validate_lock(lock_fixture())
        cases = []
        for value in ("maintained", "a" * 39, "A" * 40, "a" * 40 + "\n"):
            lock = lock_fixture()
            lock["products"]["herdr"]["commit"] = value
            cases.append(lock)
        lock = lock_fixture()
        lock["products"]["herdr"]["repository"] = "attacker/herdr"
        cases.append(lock)
        lock = lock_fixture()
        lock["products"]["herdr"]["upstream_repository"] = "attacker/herdr"
        cases.append(lock)
        lock = lock_fixture()
        del lock["products"]["herdr-mirror"]
        cases.append(lock)
        lock = lock_fixture()
        lock["platform"] = "macos-aarch64"
        cases.append(lock)
        for lock in cases:
            with self.subTest(lock=lock), self.assertRaises(ValueError):
                ci.validate_lock(lock)

    def test_runner_executes_real_child_with_private_environment_and_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = ci.Runner(root / "logs", ci.clean_environment(root / "home"))
            with patch.dict(os.environ, {"GITHUB_TOKEN": "must-not-leak"}):
                text = runner.run([sys.executable, "-c", "import json,os;print(json.dumps(dict(os.environ)))"], root)
            observed = json.loads(text)
            self.assertNotIn("GITHUB_TOKEN", observed)
            self.assertEqual(observed["HOME"], str(root / "home"))
            self.assertEqual(len(list((root / "logs").glob("*.log"))), 1)
            with self.assertRaises(RuntimeError):
                runner.run([sys.executable, "-c", "raise SystemExit(9)"], root)
            runner.run([sys.executable, "-c", "raise SystemExit(2)"], root, expected_code=2)

    def test_runner_deadline_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = ci.Runner(root / "logs", ci.clean_environment(root / "home"))
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.run([sys.executable, "-c", "import time;time.sleep(60)"], root, timeout=0.05)

    def test_actual_git_checkout_provenance_origin_and_mutation_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            runner = ci.Runner(root / "logs", ci.clean_environment(root / "home"))
            runner.run(["git", "init", "--quiet"], source)
            runner.run(["git", "config", "user.name", "Fixture"], source)
            runner.run(["git", "config", "user.email", "fixture@example.invalid"], source)
            runner.run(["git", "config", "commit.gpgsign", "false"], source)
            runner.run(["git", "remote", "add", "origin", "https://github.com/neuralyze/herdr.git"], source)
            metadata = source / ".maintenance/upstream.json"
            metadata.parent.mkdir()
            metadata.write_text(json.dumps({"schema_version": 1, "product": "herdr",
                                             "upstream_repository": "herdrdev/herdr", "upstream_commit": "b" * 40}))
            runner.run(["git", "add", "."], source)
            runner.run(["git", "commit", "--quiet", "-m", "fixture"], source)
            observed = ci.source_identity("herdr", source, runner)
            self.assertEqual(observed["repository"], "neuralyze/herdr")
            self.assertRegex(observed["commit"], r"^[0-9a-f]{40}$")
            self.assertEqual(observed["upstream_commit"], "b" * 40)
            metadata.write_text(metadata.read_text() + "\n")
            with self.assertRaisesRegex(ValueError, "tracked modifications"):
                ci.source_identity("herdr", source, runner)
            runner.run(["git", "restore", ".maintenance/upstream.json"], source)
            runner.run(["git", "remote", "set-url", "origin", "https://github.com/attacker/herdr.git"], source)
            with self.assertRaisesRegex(ValueError, "configured public fork"):
                ci.source_identity("herdr", source, runner)

    def test_invalid_pair_cannot_retain_stale_passing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / "lock.json"
            lock.write_text(json.dumps({"schema_version": 999}))
            output = root / "out"
            output.mkdir()
            evidence = output / "ci-evidence.json"
            evidence.write_text(json.dumps({"schema_version": 1, "status": "pass"}))
            with self.assertRaises(ValueError):
                ci.pair(lock, root / "workspace", output, 2)
            self.assertEqual(json.loads(evidence.read_text())["status"], "fail")
            self.assertFalse((root / "workspace").exists())


if __name__ == "__main__":
    unittest.main()
