"""Temporary real Git histories; only GitHub network/publication boundaries are fake."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from maintenance.updater import component, git, prepare_import, clean_env


class FakeGitHub:
    def __init__(self, tag="v2", notes=""):
        self.tag, self.notes = tag, notes
        self.calls = []
        self.prs, self.issues = [], []
        self.runs = []

    def api(self, method, endpoint, payload=None):
        self.calls.append((method, endpoint, payload))
        if endpoint.endswith("/releases/latest"):
            return {"tag_name": self.tag, "body": self.notes, "name": self.tag, "draft": False, "prerelease": False}
        if "/pulls?" in endpoint:
            return self.prs
        if "/issues?" in endpoint:
            return self.issues
        if method == "POST" and endpoint.endswith("/pulls"):
            pr = {"number": 1, "html_url": "https://github.com/neuralyze/herdr/pull/1",
                  "head": {"sha": self.next_head}, "requested_reviewers": []}
            self.prs.append(pr)
            return pr
        if method == "POST" and endpoint.endswith("/issues"):
            item = {"number": len(self.issues) + 1, **payload}
            self.issues.append(item)
            return item
        if "/reviews?" in endpoint:
            return []
        if "/runs?" in endpoint:
            return {"workflow_runs": self.runs}
        if endpoint.endswith("/requested_reviewers"):
            self.prs[0]["requested_reviewers"] = [{"login": name} for name in payload["reviewers"]]
        if endpoint.endswith("/dispatches"):
            self.runs.append({"head_sha": self.prs[0]["head"]["sha"]})
        return {}


class UpdaterFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.upstream = self.root / "upstream"
        self.fork = self.root / "fork"
        self.upstream.mkdir()
        self.fork.mkdir()
        git(self.upstream, "init")
        self.write(self.upstream, "code.txt", "base\n")
        self.write(self.upstream, ".github/workflows/upstream.yml", "old\n")
        self.base = self.commit(self.upstream, "base")
        git(self.upstream, "tag", "v1")
        git(self.fork, "init")
        git(self.fork, "fetch", str(self.upstream), self.base)
        git(self.fork, "checkout", "-b", "maintained", "FETCH_HEAD")
        self.write(self.fork, "local.txt", "managed fix\n")
        self.fix = self.commit(self.fork, "managed fix")
        self.ledger = [{"id": "managed", "commit": self.fix, "description": "managed fix", "keywords": ["managed"]}]
        self.write(self.fork, ".maintenance/upstream.json", json.dumps({"schema_version": 1, "product": "herdr", "upstream_repository": "herdrdev/herdr", "upstream_commit": self.base, "upstream_tag": "v1", "patches": self.ledger}))
        self.write(self.fork, ".github/workflows/owned.yml", "trusted pin\n")
        self.maintained = self.commit(self.fork, "baseline metadata")
        self.write(self.upstream, "new.txt", "new release\n")
        self.write(self.upstream, ".github/workflows/upstream.yml", "dangerous new workflow\n")
        self.write(self.upstream, ".github/workflows/new.yml", "new execution\n")
        self.target = self.commit(self.upstream, "release")
        git(self.upstream, "tag", "v2")
        self.config = {"owner": "neuralyze", "maintenance_repository": "neuralyze/herdr-maintenance", "products": {"herdr": {"fork": "neuralyze/herdr", "upstream": "herdrdev/herdr", "branch": "maintained"}}}
        self.gh = FakeGitHub()
        self.published = []

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, directory, name, content):
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def commit(self, directory, message):
        git(directory, "add", ".")
        git(directory, "commit", "-m", message)
        return git(directory, "rev-parse", "HEAD")

    def publish(self, directory, repo, branch, commit):
        git(directory, "push", str(self.fork), f"{commit}:refs/heads/{branch}")
        self.published.append((branch, commit))
        self.gh.next_head = commit

    def run_update(self, apply=True):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "neuralyze/herdr"}), patch("maintenance.updater.push_candidate", self.publish):
            return component(self.config, "herdr", self.root / "work", apply, self.gh, (str(self.fork), str(self.upstream)))

    def test_clean_squash_preserves_fixes_workflows_and_ledger(self):
        result = self.run_update()
        self.assertEqual(result["status"], "pr_opened")
        branch, commit = self.published[0]
        self.assertEqual(git(self.fork, "show", commit + ":local.txt"), "managed fix")
        self.assertEqual(git(self.fork, "show", commit + ":new.txt"), "new release")
        self.assertEqual(git(self.fork, "rev-list", "--parents", "-n", "1", commit).split(), [commit, self.maintained])
        self.assertEqual(git(self.fork, "rev-parse", commit + ":.github/workflows"), git(self.fork, "rev-parse", self.maintained + ":.github/workflows"))
        info = json.loads(git(self.fork, "show", commit + ":.maintenance/upstream.json"))
        self.assertEqual(info["patches"], self.ledger)
        self.assertEqual((info["upstream_commit"], info["upstream_tag"]), (self.target, "v2"))
        self.assertEqual(git(self.fork, "rev-parse", "maintained"), self.maintained)
        second = self.run_update()
        self.assertEqual(second["branch"], branch)
        self.assertFalse(second["dispatched"])
        self.assertEqual(len(self.published), 1)
        self.assertEqual(sum("dispatches" in endpoint for _, endpoint, _ in self.gh.calls), 1)

    def test_existing_pr_recovers_missing_review_and_validation(self):
        self.run_update()
        self.gh.prs[0]["requested_reviewers"] = []
        self.gh.runs.clear()
        self.gh.calls.clear()
        result = self.run_update()
        self.assertTrue(result["dispatched"])
        self.assertEqual(len(self.published), 1)
        self.assertEqual(self.gh.prs[0]["requested_reviewers"], [{"login": "neuralyze"}])
        self.assertEqual(self.gh.runs, [{"head_sha": self.published[0][1]}])

    def test_conflict_aborts_and_names_files(self):
        self.write(self.fork, "code.txt", "local edit\n")
        self.maintained = self.commit(self.fork, "local code")
        self.write(self.upstream, "code.txt", "upstream edit\n")
        self.target = self.commit(self.upstream, "upstream code")
        git(self.upstream, "tag", "v3")
        self.gh.tag = "v3"
        result = self.run_update()
        self.assertEqual(result["status"], "conflict")
        self.assertEqual(result["conflicts"], ["code.txt"])
        self.assertIn("code.txt", self.gh.issues[0]["body"])
        self.assertEqual(self.gh.issues[0]["assignees"], ["neuralyze"])
        self.assertEqual(git(self.fork, "rev-parse", "maintained"), self.maintained)
        self.assertFalse(self.published)
        self.run_update()
        self.assertEqual(len(self.gh.issues), 1)

    def test_old_release_never_downgrades_dev_base(self):
        self.gh.tag = "v1"
        result = self.run_update()
        self.assertEqual(result["status"], "up_to_date")
        self.assertFalse(self.published)

    def test_retarget_requires_review(self):
        git(self.upstream, "tag", "-f", "v1", self.target)
        self.gh.tag = "v1"
        self.assertEqual(self.run_update()["status"], "review")
        self.assertFalse(self.published)

    def test_divergence_requires_review(self):
        git(self.upstream, "checkout", "--orphan", "different")
        self.write(self.upstream, "other.txt", "unrelated\n")
        self.commit(self.upstream, "unrelated release")
        git(self.upstream, "tag", "v3")
        self.gh.tag = "v3"
        self.assertEqual(self.run_update()["status"], "review")
        self.assertFalse(self.published)

    def test_exact_patch_adoption_retains_ledger(self):
        # Import the real fix object then cherry-pick its actual patch upstream.
        git(self.upstream, "fetch", str(self.fork), self.fix)
        git(self.upstream, "cherry-pick", self.fix)
        self.target = git(self.upstream, "rev-parse", "HEAD")
        git(self.upstream, "tag", "v3")
        self.gh.tag = "v3"
        result = self.run_update()
        self.assertTrue(result["adoption_candidates"][0]["exact_patch_id"])
        commit = self.published[0][1]
        self.assertEqual(json.loads(git(self.fork, "show", commit + ":.maintenance/upstream.json"))["patches"], self.ledger)

    def test_dry_run_has_no_remote_or_api_mutations(self):
        result = self.run_update(False)
        self.assertEqual(result["status"], "review")
        self.assertFalse(self.published)
        self.assertTrue(all(method == "GET" for method, _, _ in self.gh.calls))

    def test_wrong_apply_identity_fails_before_api(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "other/repo"}):
            with self.assertRaises(ValueError):
                component(self.config, "herdr", self.root / "work", True, self.gh)
        self.assertEqual(self.gh.calls, [])

    def test_source_environment_has_no_credentials(self):
        with patch.dict(os.environ, {"GH_TOKEN": "private", "AWS_ACCESS_KEY_ID": "private", "GIT_CONFIG_COUNT": "1", "SSH_AUTH_SOCK": "/private"}):
            env = clean_env()
        for key in ("GH_TOKEN", "AWS_ACCESS_KEY_ID", "GIT_CONFIG_COUNT", "SSH_AUTH_SOCK"):
            self.assertNotIn(key, env)


if __name__ == "__main__":
    unittest.main()
