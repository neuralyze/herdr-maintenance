import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from maintenance.updater import pair


class PairPinTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = {"owner": "neuralyze", "maintenance_repository": "neuralyze/herdr-maintenance", "products": {
            name: {"fork": "neuralyze/" + name, "upstream": "upstream/" + name, "branch": "maintained"}
            for name in ("herdr", "herdr-mirror")}}
        self.lock = {"schema_version": 1, "platform": "linux-x86_64", "products": {
            name: {"repository": p["fork"], "commit": "a" * 40, "upstream_repository": p["upstream"], "upstream_commit": "b" * 40, "upstream_tag": None}
            for name, p in self.config["products"].items()}}
        self.path = self.root / "pair.lock.json"
        self.path.write_text(json.dumps(self.lock))
        self.calls = []
        self.tip = "c" * 40

    def tearDown(self):
        self.temp.cleanup()

    def api(self, method, endpoint, payload=None):
        self.calls.append((method, endpoint))
        if "/git/ref/heads/maintained" in endpoint:
            return {"object": {"sha": self.tip}}
        for name, p in self.config["products"].items():
            if endpoint.startswith("repos/" + p["fork"] + "/contents/"):
                data = {"schema_version": 1, "product": name, "upstream_repository": p["upstream"], "upstream_commit": "b" * 40, "upstream_tag": None, "patches": []}
                return {"content": base64.b64encode(json.dumps(data).encode()).decode()}
        raise AssertionError(endpoint)

    def test_dry_pair_reads_only_approved_tips_and_exact_metadata(self):
        original = self.path.read_bytes()
        result = pair(self.config, self.path, self.root / "work", gh=self)
        self.assertEqual(result["status"], "review")
        self.assertEqual(self.path.read_bytes(), original)
        for p in result["lock"]["products"].values():
            self.assertEqual(p["commit"], self.tip)
        self.assertTrue(all(method == "GET" for method, _ in self.calls))
        self.assertTrue(all("/git/ref/heads/maintained" in endpoint or "?ref=" + self.tip in endpoint for _, endpoint in self.calls))

    def test_unchanged_pair_is_success(self):
        self.tip = "a" * 40
        self.assertEqual(pair(self.config, self.path, self.root / "work", gh=self)["status"], "up_to_date")

    def test_foreign_lock_repository_is_rejected(self):
        self.lock["products"]["herdr"]["repository"] = "attacker/herdr"
        self.path.write_text(json.dumps(self.lock))
        with self.assertRaises(ValueError):
            pair(self.config, self.path, self.root / "work", gh=self)
        self.assertEqual(self.calls, [])

    def test_apply_rejects_foreign_coordinator_before_api(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "attacker/repo"}):
            with self.assertRaises(ValueError):
                pair(self.config, self.path, self.root / "work", True, self)
        self.assertEqual(self.calls, [])
