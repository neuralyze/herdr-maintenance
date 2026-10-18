"""Stateful GitHub fixture stores and transfers actual verified release bytes."""
import base64
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from maintenance import package, release
from maintenance.github import GitHubError
from test_package import VALIDATOR, make_distribution, rewrite_checksums


class MemoryGitHub:
    def __init__(self):
        self.releases = {}
        self.tags = {}
        self.contents = {}
        self.locks = {}
        self.latest = None
        self.calls = []
        self.patches = 0
        self.fail_after_asset = None

    def seed(self, directory: Path, *, prerelease=True):
        manifest = package.validate_dist(directory)
        tag = manifest["candidate_tag"]
        self.locks.setdefault(manifest["validator_commit"], (directory.parent / "lock.json").read_bytes())
        self.tags[tag] = manifest["validator_commit"]
        row = {"id": len(self.releases) + 1, "tag_name": tag, "draft": False,
               "prerelease": prerelease, "published_at": "2026-10-18T00:00:00Z", "assets": []}
        self.releases[tag] = row
        self.contents[tag] = {}
        if not prerelease:
            self.latest = tag
        for name in package.ASSETS:
            self.store(tag, name, (directory / name).read_bytes())
        return tag

    def store(self, tag, name, content):
        if name in self.contents[tag]:
            raise AssertionError("attempted immutable asset overwrite")
        self.contents[tag][name] = content
        self.releases[tag]["assets"].append({"name": name, "size": len(content), "state": "uploaded"})

    def api(self, method, endpoint, payload=None):
        self.calls.append((method, endpoint, copy.deepcopy(payload)))
        prefix = f"repos/{package.REPOSITORY}/"
        if not endpoint.startswith(prefix):
            raise AssertionError("unexpected repository access")
        route = endpoint[len(prefix):]
        if method == "GET" and route.startswith("contents/config/pair.lock.json?ref="):
            validator = route.rsplit("=", 1)[1]
            if validator not in self.locks:
                raise GitHubError("historical lock missing", status=404)
            content = self.locks[validator]
            return {"type": "file", "path": "config/pair.lock.json", "encoding": "base64",
                    "size": len(content), "content": base64.b64encode(content).decode(),
                    "sha": hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()}
        if method == "GET" and route == "releases/latest":
            if self.latest is None:
                raise GitHubError("no approved release", status=404)
            return copy.deepcopy(self.releases[self.latest])
        if method == "GET" and route.startswith("git/ref/tags/"):
            tag = route[len("git/ref/tags/"):]
            if tag not in self.tags:
                raise GitHubError("missing", status=404)
            return {"ref": f"refs/tags/{tag}", "object": {"type": "commit", "sha": self.tags[tag]}}
        if method == "POST" and route == "git/refs":
            tag = payload["ref"][len("refs/tags/"):]
            if tag in self.tags:
                raise AssertionError("tag overwrite")
            self.tags[tag] = payload["sha"]
            return {}
        if method == "GET" and route.startswith("releases/tags/"):
            tag = route[len("releases/tags/"):]
            if tag not in self.releases:
                raise GitHubError("missing", status=404)
            return copy.deepcopy(self.releases[tag])
        if method == "POST" and route == "releases":
            tag = payload["tag_name"]
            if tag in self.releases:
                raise AssertionError("release overwrite")
            self.releases[tag] = {"id": len(self.releases) + 1, "tag_name": tag, "draft": False,
                                  "prerelease": True, "assets": [], "published_at": "2026-10-18T01:00:00Z"}
            self.contents[tag] = {}
            return copy.deepcopy(self.releases[tag])
        if method == "PATCH" and route.startswith("releases/"):
            identifier = int(route.split("/")[-1])
            row = next(item for item in self.releases.values() if item["id"] == identifier)
            self.patches += 1
            row["prerelease"] = payload["prerelease"]
            if payload.get("make_latest") == "true":
                self.latest = row["tag_name"]
            return copy.deepcopy(row)
        raise AssertionError((method, route, payload))

    def command(self, args, input_text=None):
        self.calls.append(tuple(args))
        if args[:2] not in (["release", "download"], ["release", "upload"]):
            raise AssertionError("only authenticated asset transfer is allowed")
        tag = args[2]
        if args[3:5] != ["--repo", package.REPOSITORY]:
            raise AssertionError("transfer ownership mismatch")
        if args[1] == "download":
            name = args[6]
            directory = Path(args[8])
            (directory / name).write_bytes(self.contents[tag][name])
        else:
            for filename in args[5:]:
                path = Path(filename)
                self.store(tag, path.name, path.read_bytes())
                if self.fail_after_asset == path.name:
                    self.fail_after_asset = None
                    raise GitHubError("interrupted upload")
        return ""


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dist, self.lock_path, _ = make_distribution(self.root / "current")
        self.github = MemoryGitHub()
        self.github.locks[VALIDATOR] = self.lock_path.read_bytes()
        self.trusted_lock = patch.object(release, "publisher_lock", side_effect=self.lock_path.read_bytes)
        self.trusted_lock.start()
        self.addCleanup(self.trusted_lock.stop)
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.head = patch.object(release, "validator_head", return_value=VALIDATOR)
        self.head.start()
        self.addCleanup(self.head.stop)

    def test_candidate_bytes_and_idempotence(self):
        with patch("subprocess.run", side_effect=AssertionError("publisher executed a process")):
            first = release.candidate(self.github, self.dist, package.REPOSITORY)
            before = copy.deepcopy(self.github.contents)
            second = release.candidate(self.github, self.dist, package.REPOSITORY)
        self.assertEqual(first, second)
        self.assertEqual(self.github.contents, before)
        self.assertEqual(len(self.github.releases), 1)
        self.assertEqual(set(self.github.contents[first["tag"]]), set(package.ASSETS))
        for name in package.ASSETS:
            self.assertEqual(self.github.contents[first["tag"]][name], (self.dist / name).read_bytes())
        self.assertFalse(any("--clobber" in item for item in self.github.calls if isinstance(item, tuple)))

    def test_candidate_rejects_existing_asset_or_tag_mismatch(self):
        tag = self.github.seed(self.dist)
        self.github.contents[tag]["SHA256SUMS"] = b"different"
        with self.assertRaises(ValueError):
            release.candidate(self.github, self.dist, package.REPOSITORY)
        self.github.contents[tag]["SHA256SUMS"] = (self.dist / "SHA256SUMS").read_bytes()
        self.github.tags[tag] = "f" * 40
        with self.assertRaises(ValueError):
            release.candidate(self.github, self.dist, package.REPOSITORY)
        self.assertEqual(self.github.patches, 0)

    def test_candidate_finishes_only_missing_assets(self):
        tag = self.github.seed(self.dist)
        del self.github.contents[tag]["SHA256SUMS"]
        self.github.releases[tag]["assets"] = [item for item in self.github.releases[tag]["assets"] if item["name"] != "SHA256SUMS"]
        release.candidate(self.github, self.dist, package.REPOSITORY)
        self.assertEqual(self.github.contents[tag]["SHA256SUMS"], (self.dist / "SHA256SUMS").read_bytes())

    def test_candidate_does_not_mutate_approved_release(self):
        tag = self.github.seed(self.dist, prerelease=False)
        before = copy.deepcopy(self.github.releases)
        result = release.candidate(self.github, self.dist, package.REPOSITORY)
        self.assertEqual(result["status"], "already_approved")
        self.assertEqual(before, self.github.releases)
        self.assertEqual(tag, result["tag"])

    def test_candidate_checks_trusted_head_and_context(self):
        self.head.stop()
        with patch.object(release, "validator_head", return_value="f" * 40), self.assertRaises(ValueError):
            release.candidate(self.github, self.dist, package.REPOSITORY)
        self.head.start()
        good = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": package.REPOSITORY,
                "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": VALIDATOR}
        for key, value in (("GITHUB_REPOSITORY", "attacker/repo"), ("GITHUB_REF", "refs/pull/1/merge"),
                           ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_SHA", "f" * 40)):
            with self.subTest(key=key), patch.dict(os.environ, {**good, key: value}, clear=True), self.assertRaises(ValueError):
                release.candidate(self.github, self.dist, package.REPOSITORY)
        with patch.dict(os.environ, good, clear=True):
            self.assertEqual(release.candidate(self.github, self.dist, package.REPOSITORY)["status"], "candidate")

    def test_promotion_records_previous_actual_manifest_and_is_idempotent(self):
        previous_dist, _, _ = make_distribution(self.root / "old", validator="d" * 40)
        previous_tag = self.github.seed(previous_dist, prerelease=False)
        tag = self.github.seed(self.dist)
        with patch("subprocess.run", side_effect=AssertionError("publisher executed a process")):
            first = release.promote(self.github, tag, package.REPOSITORY)
            before = copy.deepcopy(self.github.contents)
            second = release.promote(self.github, tag, package.REPOSITORY)
        self.assertEqual(first, second)
        self.assertEqual(first["previous_approved_tag"], previous_tag)
        self.assertEqual(self.github.contents[tag][release.PREVIOUS], (previous_dist / "pair-manifest.json").read_bytes())
        self.assertEqual(self.github.patches, 1)
        self.assertEqual(self.github.contents, before)
        self.assertFalse(self.github.releases[tag]["prerelease"])

    def test_first_promotion_has_explicit_empty_rollback(self):
        tag = self.github.seed(self.dist)
        result = release.promote(self.github, tag, package.REPOSITORY)
        self.assertIsNone(result["previous_approved_tag"])
        self.assertIsNone(result["previous_manifest_sha256"])
        self.assertNotIn(release.PREVIOUS, self.github.contents[tag])
        self.assertIn(release.APPROVAL, self.github.contents[tag])

    def test_interrupted_promotion_resumes_without_overwriting(self):
        previous_dist, _, _ = make_distribution(self.root / "old", validator="d" * 40)
        self.github.seed(previous_dist, prerelease=False)
        tag = self.github.seed(self.dist)
        self.github.fail_after_asset = release.PREVIOUS
        with self.assertRaises(GitHubError):
            release.promote(self.github, tag, package.REPOSITORY)
        self.assertTrue(self.github.releases[tag]["prerelease"])
        previous_bytes = self.github.contents[tag][release.PREVIOUS]
        release.promote(self.github, tag, package.REPOSITORY)
        self.assertEqual(self.github.contents[tag][release.PREVIOUS], previous_bytes)
        self.assertFalse(self.github.releases[tag]["prerelease"])

    def test_promote_rejects_tampered_bytes_and_missing_assets(self):
        tag = self.github.seed(self.dist)
        self.github.contents[tag][package.ASSETS[0]] = b"malicious archive"
        with self.assertRaises(ValueError):
            release.promote(self.github, tag, package.REPOSITORY)
        self.assertEqual(self.github.patches, 0)
        self.github.releases[tag]["assets"].pop()
        with self.assertRaises(ValueError):
            release.promote(self.github, tag, package.REPOSITORY)
        self.assertEqual(self.github.patches, 0)

    def test_release_asset_boundaries_and_unknown_members(self):
        tag = self.github.seed(self.dist)
        original = copy.deepcopy(self.github.releases[tag]["assets"])
        for extra in ({"name": "evil", "size": 1, "state": "uploaded"},
                      {"name": package.ASSETS[0], "size": 1, "state": "uploaded"}):
            self.github.releases[tag]["assets"] = original + [extra]
            with self.assertRaises(ValueError):
                release.promote(self.github, tag, package.REPOSITORY)
        self.github.releases[tag]["assets"] = copy.deepcopy(original)
        self.github.releases[tag]["assets"][0]["size"] = package.MAX_ARCHIVE + 1
        with self.assertRaises(ValueError):
            release.promote(self.github, tag, package.REPOSITORY)
        self.assertEqual(self.github.patches, 0)

    def test_approval_tamper_and_ownership_fail_closed(self):
        tag = self.github.seed(self.dist)
        release.promote(self.github, tag, package.REPOSITORY)
        self.github.contents[tag][release.APPROVAL] = b'{"schema_version":1,"tag":"wrong"}'
        with self.assertRaises(ValueError):
            release.promote(self.github, tag, package.REPOSITORY)
        with self.assertRaises(ValueError):
            release.promote(self.github, tag, "attacker/repo")
        self.assertEqual(self.github.patches, 1)

    def test_promotion_actions_dispatch_only(self):
        tag = self.github.seed(self.dist)
        context = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": package.REPOSITORY,
                   "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": VALIDATOR}
        with patch.dict(os.environ, context, clear=True), self.assertRaises(ValueError):
            release.promote(self.github, tag, package.REPOSITORY)
        self.assertEqual(self.github.patches, 0)

    def test_candidate_rejects_self_consistent_unapproved_lock_or_provenance_before_writes(self):
        manifest_path = self.dist / "pair-manifest.json"
        original = manifest_path.read_bytes()
        for field, value in (("lock_sha256", "f" * 64), ("commit", "f" * 40),
                             ("upstream_commit", "f" * 40), ("upstream_tag", "unapproved-tag")):
            with self.subTest(field=field):
                manifest = package.load_json(manifest_path)
                if field == "lock_sha256":
                    manifest[field] = value
                else:
                    manifest["products"]["herdr"][field] = value
                manifest["candidate_tag"] = package.candidate_tag(manifest)
                manifest_path.write_bytes(package.json_bytes(manifest))
                rewrite_checksums(self.dist)
                package.validate_dist(self.dist)
                with self.assertRaises(ValueError):
                    release.candidate(self.github, self.dist, package.REPOSITORY)
                self.assertEqual(self.github.calls, [])
                self.assertEqual(self.github.releases, {})
                self.assertEqual(self.github.tags, {})
                manifest_path.write_bytes(original)
                rewrite_checksums(self.dist)

    def test_promotion_binds_historical_lock_not_current_publisher_lock(self):
        old_dist, old_lock, _ = make_distribution(self.root / "historical", validator="d" * 40)
        old_tag = self.github.seed(old_dist)
        current_lock = package.load_json(self.lock_path)
        current_lock["products"]["herdr"]["commit"] = "f" * 40
        self.lock_path.write_bytes(package.json_bytes(current_lock))
        result = release.promote(self.github, old_tag, package.REPOSITORY)
        self.assertEqual(result["status"], "approved")
        historical_calls = [call for call in self.github.calls if len(call) == 3 and
                            isinstance(call[1], str) and "/contents/" in call[1]]
        self.assertTrue(historical_calls)
        self.assertTrue(all(call[1].endswith("?ref=" + "d" * 40) for call in historical_calls))
        self.assertEqual(self.github.locks["d" * 40], old_lock.read_bytes())

    def test_promotion_rejects_rechecksummed_unapproved_source_pin(self):
        manifest_path = self.dist / "pair-manifest.json"
        manifest = package.load_json(manifest_path)
        manifest["products"]["herdr"]["commit"] = "f" * 40
        manifest["candidate_tag"] = package.candidate_tag(manifest)
        manifest_path.write_bytes(package.json_bytes(manifest))
        rewrite_checksums(self.dist)
        package.validate_dist(self.dist)
        tag = self.github.seed(self.dist)
        with self.assertRaises(ValueError):
            release.promote(self.github, tag, package.REPOSITORY)
        self.assertEqual(self.github.patches, 0)
        self.assertEqual(set(self.github.contents[tag]), set(package.ASSETS))

    def test_historical_lock_exact_bytes_and_response_boundaries(self):
        tag = self.github.seed(self.dist)
        original = self.github.locks[VALIDATOR]
        self.github.locks[VALIDATOR] = original + b"\n"
        with self.assertRaises(ValueError):
            release.promote(self.github, tag, package.REPOSITORY)
        self.github.locks[VALIDATOR] = original
        real_api = self.github.api
        for field, value in (("path", "other.json"), ("type", "symlink"), ("encoding", "none"),
                             ("size", package.MAX_JSON + 1), ("size", 1), ("sha", "f" * 40),
                             ("content", "%%%"), ("content", "A" * (package.MAX_JSON * 2 + 1))):
            with self.subTest(field=field, value=str(value)[:24]):
                def malformed(method, endpoint, payload=None):
                    response = real_api(method, endpoint, payload)
                    if "/contents/" in endpoint:
                        response[field] = value
                    return response
                with patch.object(self.github, "api", side_effect=malformed), self.assertRaises(ValueError):
                    release.historical_lock(self.github, package.REPOSITORY, VALIDATOR)
        with self.assertRaises(ValueError):
            release.historical_lock(self.github, "attacker/repository", VALIDATOR)
        with self.assertRaises(ValueError):
            release.historical_lock(self.github, package.REPOSITORY, "main")
        self.assertEqual(self.github.patches, 0)

    def test_rollback_follows_latest_approval_not_candidate_publication(self):
        first_dist, _, _ = make_distribution(self.root / "first", validator="d" * 40)
        second_dist, _, _ = make_distribution(self.root / "second", validator="e" * 40)
        first = self.github.seed(first_dist)
        second = self.github.seed(second_dist)
        current = self.github.seed(self.dist)
        self.github.releases[first]["published_at"] = "2026-10-15T00:00:00Z"
        self.github.releases[second]["published_at"] = "2026-10-16T00:00:00Z"
        release.promote(self.github, second, package.REPOSITORY)
        release.promote(self.github, first, package.REPOSITORY)
        self.assertEqual(self.github.latest, first)
        result = release.promote(self.github, current, package.REPOSITORY)
        self.assertEqual(result["previous_approved_tag"], first)
        self.assertEqual(self.github.contents[current][release.PREVIOUS],
                         (first_dist / "pair-manifest.json").read_bytes())

    def test_interrupted_rollback_identity_survives_intervening_approval(self):
        old_dist, _, _ = make_distribution(self.root / "old", validator="d" * 40)
        old = self.github.seed(old_dist, prerelease=False)
        current = self.github.seed(self.dist)
        self.github.fail_after_asset = release.PREVIOUS
        with self.assertRaises(GitHubError):
            release.promote(self.github, current, package.REPOSITORY)
        persisted = self.github.contents[current][release.PREVIOUS]
        other_dist, _, _ = make_distribution(self.root / "other", validator="e" * 40)
        other = self.github.seed(other_dist)
        release.promote(self.github, other, package.REPOSITORY)
        self.assertEqual(self.github.latest, other)
        result = release.promote(self.github, current, package.REPOSITORY)
        self.assertEqual(result["previous_approved_tag"], old)
        self.assertEqual(self.github.contents[current][release.PREVIOUS], persisted)
        self.assertEqual(result["previous_manifest_sha256"], hashlib.sha256(persisted).hexdigest())
        again = release.promote(self.github, current, package.REPOSITORY)
        self.assertEqual(result, again)


if __name__ == "__main__":
    unittest.main()
