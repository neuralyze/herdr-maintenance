"""Publish verified candidates and promote approved pairs without executing them."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from .github import GitHub, GitHubError
from .package import (ASSETS, MAX_ARCHIVE, MAX_JSON, REPOSITORY, candidate_tag,
                      digest, hash_value, json_bytes, load_json, regular_file,
                      require, sha, unique_object, validate_dist, validate_lock,
                      validate_manifest, validator_head)

TAG = re.compile(r"pair-[0-9a-f]{40}-[0-9a-f]{40}-[0-9a-f]{40}\Z")
APPROVAL = "approval.json"
PREVIOUS = "previous-approved-pair-manifest.json"
PROMOTION_ASSETS = {APPROVAL, PREVIOUS}
LOCK_PATH = "config/pair.lock.json"
PIN_FIELDS = ("repository", "commit", "upstream_repository", "upstream_commit", "upstream_tag")


def publisher_lock() -> bytes:
    path = Path(__file__).resolve().parent.parent / LOCK_PATH
    regular_file(path, MAX_JSON)
    return path.read_bytes()


def validate_lock_binding(manifest: dict, lock_bytes: bytes) -> None:
    require(0 < len(lock_bytes) <= MAX_JSON, "invalid trusted lock size")
    lock = json.loads(lock_bytes, object_pairs_hook=unique_object)
    require(isinstance(lock, dict), "invalid trusted lock document")
    validate_lock(lock)
    require(hashlib.sha256(lock_bytes).hexdigest() == manifest["lock_sha256"], "manifest differs from trusted validator lock bytes")
    require(manifest["platform"] == lock["platform"], "manifest differs from trusted lock platform")
    for product in lock["products"]:
        require(all(manifest["products"][product].get(field) == lock["products"][product].get(field)
                    for field in PIN_FIELDS), "manifest source/provenance differs from trusted validator lock")


def historical_lock(github: GitHub, repository: str, validator: str) -> bytes:
    require(repository == REPOSITORY, "unapproved historical lock repository")
    sha(validator)
    response = github.api("GET", f"repos/{repository}/contents/{LOCK_PATH}?ref={validator}")
    require(isinstance(response, dict) and response.get("type") == "file" and
            response.get("path") == LOCK_PATH and response.get("encoding") == "base64",
            "invalid historical lock response")
    require(type(response.get("size")) is int and 0 < response["size"] <= MAX_JSON, "invalid historical lock size")
    content = response.get("content")
    require(isinstance(content, str) and len(content) <= MAX_JSON * 2, "invalid encoded historical lock")
    lock_bytes = base64.b64decode("".join(content.splitlines()), validate=True)
    require(len(lock_bytes) == response["size"], "historical lock size mismatch")
    blob = hashlib.sha1(b"blob " + str(len(lock_bytes)).encode() + b"\0" + lock_bytes).hexdigest()
    require(sha(response.get("sha")) == blob, "historical lock Git blob mismatch")
    return lock_bytes


def trusted_context(repository: str, *, promotion: bool = False) -> None:
    require(repository == REPOSITORY, "unapproved release repository")
    if any(key in os.environ for key in ("GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_EVENT_NAME")):
        require(os.environ.get("GITHUB_ACTIONS") == "true", "incomplete Actions context")
        require(os.environ.get("GITHUB_REPOSITORY") == repository, "Actions repository mismatch")
        require(os.environ.get("GITHUB_REF") == "refs/heads/main", "publishing is main-only")
        events = {"workflow_dispatch"} if promotion else {"push", "workflow_dispatch"}
        require(os.environ.get("GITHUB_EVENT_NAME") in events, "untrusted publication event")
        sha(os.environ.get("GITHUB_SHA"))


def get_release(github: GitHub, repository: str, tag: str) -> dict | None:
    require(TAG.fullmatch(tag) is not None, "invalid paired release tag")
    try:
        release = github.api("GET", f"repos/{repository}/releases/tags/{tag}")
    except GitHubError as exc:
        if exc.status == 404:
            return None
        raise
    require(isinstance(release, dict) and release.get("tag_name") == tag, "release identity mismatch")
    require(type(release.get("id")) is int and release["id"] > 0, "invalid release ID")
    require(release.get("draft") is False and type(release.get("prerelease")) is bool, "invalid release state")
    return release


def verify_tag(github: GitHub, repository: str, tag: str, validator: str, *, create: bool = False) -> None:
    try:
        reference = github.api("GET", f"repos/{repository}/git/ref/tags/{tag}")
    except GitHubError as exc:
        if not (create and exc.status == 404):
            raise
        github.api("POST", f"repos/{repository}/git/refs", {"ref": f"refs/tags/{tag}", "sha": validator})
        reference = github.api("GET", f"repos/{repository}/git/ref/tags/{tag}")
    require(isinstance(reference, dict) and reference.get("ref") == f"refs/tags/{tag}", "tag ref mismatch")
    # Maintained tags are intentionally lightweight, directly binding validator HEAD.
    require(reference.get("object", {}).get("type") == "commit" and reference["object"].get("sha") == validator, "immutable tag validator mismatch")


def asset_map(release: dict) -> dict:
    assets = release.get("assets")
    require(isinstance(assets, list), "missing release assets")
    result = {}
    for asset in assets:
        require(isinstance(asset, dict), "malformed release asset")
        name = asset.get("name")
        require(name in set(ASSETS) | PROMOTION_ASSETS and name not in result, "unexpected or duplicate release asset")
        maximum = MAX_ARCHIVE if name.endswith(".tar.gz") else MAX_JSON
        require(type(asset.get("size")) is int and 0 < asset["size"] <= maximum, "release asset exceeds size boundary")
        require(asset.get("state") == "uploaded", "release asset upload incomplete")
        result[name] = asset
    return result


def download(github: GitHub, repository: str, tag: str, names: set[str], directory: Path) -> None:
    require(not any(directory.iterdir()), "download directory must be empty")
    for name in sorted(names):
        require(name in set(ASSETS) | PROMOTION_ASSETS, "unapproved download filename")
        github.command(["release", "download", tag, "--repo", repository, "--pattern", name,
                        "--dir", str(directory)])
    require({path.name for path in directory.iterdir()} == names, "downloaded asset set mismatch")
    for path in directory.iterdir():
        regular_file(path, MAX_ARCHIVE if path.name.endswith(".tar.gz") else MAX_JSON)


def upload(github: GitHub, repository: str, tag: str, paths: list[Path]) -> None:
    if paths:
        github.command(["release", "upload", tag, "--repo", repository, *[str(path.resolve()) for path in paths]])


def verify_existing(github: GitHub, repository: str, release: dict, directory: Path) -> dict:
    assets = asset_map(release)
    require(set(ASSETS) <= set(assets), "candidate release is missing required assets")
    download(github, repository, release["tag_name"], set(ASSETS), directory)
    manifest = validate_dist(directory)
    require(candidate_tag(manifest) == release["tag_name"], "release/manifest tag mismatch")
    verify_tag(github, repository, release["tag_name"], manifest["validator_commit"])
    validate_lock_binding(manifest, historical_lock(github, repository, manifest["validator_commit"]))
    for name in ASSETS:
        require((directory / name).stat().st_size == assets[name]["size"], "asset metadata size mismatch")
    return manifest


def candidate(github: GitHub, directory: Path, repository: str) -> dict:
    trusted_context(repository)
    manifest = validate_dist(directory)
    validator = validator_head()
    require(manifest["validator_commit"] == validator, "candidate validator differs from trusted publisher HEAD")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        require(os.environ["GITHUB_SHA"] == validator, "Actions commit differs from candidate validator")
    validate_lock_binding(manifest, publisher_lock())
    tag = manifest["candidate_tag"]
    verify_tag(github, repository, tag, validator, create=True)
    release = get_release(github, repository, tag)
    if release is None:
        github.api("POST", f"repos/{repository}/releases", {
            "tag_name": tag, "target_commitish": validator, "name": tag,
            "body": "Validated paired Herdr candidate. Promotion requires release-approval review. No deployment is performed.",
            "draft": False, "prerelease": True, "make_latest": "false"})
        release = get_release(github, repository, tag)
        require(release is not None, "created release is not visible")
    assets = asset_map(release)
    # Existing objects are compared byte-for-byte; never pass --clobber or alter
    # existing release metadata. Missing assets may finish an interrupted upload.
    with tempfile.TemporaryDirectory(prefix="herdr-existing-") as temporary:
        downloaded = Path(temporary)
        existing = set(ASSETS) & set(assets)
        download(github, repository, tag, existing, downloaded)
        for name in existing:
            require((downloaded / name).stat().st_size == assets[name]["size"] and
                    digest(downloaded / name) == digest(directory / name), "immutable release asset differs")
    missing = set(ASSETS) - set(assets)
    require(release["prerelease"] or not missing, "approved release cannot acquire missing candidate assets")
    upload(github, repository, tag, [directory / name for name in sorted(missing)])
    refreshed = get_release(github, repository, tag)
    require(refreshed is not None, "release disappeared after upload")
    with tempfile.TemporaryDirectory(prefix="herdr-candidate-") as temporary:
        verified = verify_existing(github, repository, refreshed, Path(temporary))
        require(verified == manifest, "published manifest mismatch")
    return {"status": "candidate" if refreshed["prerelease"] else "already_approved", "repository": repository,
            "tag": tag, "manifest_sha256": digest(directory / "pair-manifest.json")}


def previous_approved_release(github: GitHub, repository: str, exclude: str) -> dict | None:
    # make_latest=true records approval order independently of when candidates
    # were originally published. Never infer approval order from timestamps.
    try:
        latest = github.api("GET", f"repos/{repository}/releases/latest")
    except GitHubError as exc:
        if exc.status == 404:
            return None
        raise
    require(isinstance(latest, dict), "invalid latest approved release")
    tag = latest.get("tag_name")
    require(isinstance(tag, str) and TAG.fullmatch(tag) is not None and tag != exclude,
            "latest approved release is not a different managed pair")
    approved = get_release(github, repository, tag)
    require(approved is not None and approved["id"] == latest.get("id") and
            approved["prerelease"] is False, "latest release is not approved")
    return approved


def validate_approval(record: dict, tag: str, manifest_hash: str) -> None:
    require(set(record) == {"schema_version", "tag", "manifest_sha256", "previous_approved_tag", "previous_manifest_sha256"}, "invalid approval record fields")
    require(record.get("schema_version") == 1 and record.get("tag") == tag and record.get("manifest_sha256") == manifest_hash, "approval identity mismatch")
    previous = record.get("previous_approved_tag")
    if previous is None:
        require(record.get("previous_manifest_sha256") is None, "invalid empty rollback identity")
    else:
        require(isinstance(previous, str) and TAG.fullmatch(previous) is not None and previous != tag, "invalid rollback tag")
        hash_value(record.get("previous_manifest_sha256"))


def promote(github: GitHub, tag: str, repository: str) -> dict:
    trusted_context(repository, promotion=True)
    release = get_release(github, repository, tag)
    require(release is not None, "candidate release does not exist")
    with tempfile.TemporaryDirectory(prefix="herdr-promotion-") as temporary:
        root = Path(temporary)
        distribution = root / "distribution"
        distribution.mkdir()
        manifest = verify_existing(github, repository, release, distribution)
        manifest_hash = digest(distribution / "pair-manifest.json")
        assets = asset_map(release)
        metadata = root / "metadata"
        metadata.mkdir()
        extras = set(assets) & PROMOTION_ASSETS
        download(github, repository, tag, extras, metadata)
        if APPROVAL in extras:
            record = load_json(metadata / APPROVAL)
            validate_approval(record, tag, manifest_hash)
            previous_tag = record["previous_approved_tag"]
        else:
            require(release["prerelease"], "approved release lacks an approval record")
            previous_hash = None
            if PREVIOUS in extras:
                persisted = load_json(metadata / PREVIOUS)
                validate_manifest(persisted)
                previous_tag = persisted["candidate_tag"]
                previous_hash = digest(metadata / PREVIOUS)
            else:
                previous = previous_approved_release(github, repository, tag)
                previous_tag = previous["tag_name"] if previous else None
            record = {"schema_version": 1, "tag": tag, "manifest_sha256": manifest_hash,
                      "previous_approved_tag": previous_tag, "previous_manifest_sha256": previous_hash}
        pending = []
        if previous_tag is not None:
            previous_release = get_release(github, repository, previous_tag)
            require(previous_release is not None and previous_release["prerelease"] is False, "rollback release is not approved")
            previous_directory = root / "previous"
            previous_directory.mkdir()
            verify_existing(github, repository, previous_release, previous_directory)
            previous_manifest = previous_directory / "pair-manifest.json"
            previous_hash = digest(previous_manifest)
            if APPROVAL in extras or PREVIOUS in extras:
                require(record["previous_manifest_sha256"] == previous_hash, "recorded rollback identity differs")
            else:
                record["previous_manifest_sha256"] = previous_hash
            if PREVIOUS in extras:
                require((metadata / PREVIOUS).read_bytes() == previous_manifest.read_bytes(), "immutable rollback manifest differs")
            else:
                require(APPROVAL not in extras, "approval is missing recorded rollback manifest")
                (metadata / PREVIOUS).write_bytes(previous_manifest.read_bytes())
                pending.append(metadata / PREVIOUS)
        else:
            require(PREVIOUS not in extras, "unexpected rollback manifest")
        validate_approval(record, tag, manifest_hash)
        if APPROVAL not in extras:
            (metadata / APPROVAL).write_bytes(json_bytes(record))
            pending.append(metadata / APPROVAL)
        # Persist rollback bytes and approval identity before marking approved.
        upload(github, repository, tag, pending)
        refreshed = get_release(github, repository, tag)
        require(refreshed is not None, "release disappeared during promotion")
        require(set(asset_map(refreshed)) == set(ASSETS) | {APPROVAL} | ({PREVIOUS} if previous_tag else set()), "promotion asset set mismatch")
        confirmation = root / "confirmation"
        confirmation.mkdir()
        download(github, repository, tag, {APPROVAL} | ({PREVIOUS} if previous_tag else set()), confirmation)
        require(load_json(confirmation / APPROVAL) == record, "published approval record mismatch")
        if previous_tag:
            require(digest(confirmation / PREVIOUS) == record["previous_manifest_sha256"], "published rollback manifest checksum mismatch")
        if refreshed["prerelease"]:
            updated = github.api("PATCH", f"repos/{repository}/releases/{release['id']}", {"prerelease": False, "make_latest": "true"})
            require(isinstance(updated, dict) and updated.get("id") == release["id"] and updated.get("tag_name") == tag and updated.get("prerelease") is False, "promotion was not confirmed")
        return {"status": "approved", "repository": repository, **record}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("candidate")
    create.add_argument("--dist", type=Path, required=True)
    approve = commands.add_parser("promote")
    approve.add_argument("--tag", required=True)
    for command in (create, approve):
        command.add_argument("--repository", required=True)
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        github = GitHub()
        result = candidate(github, args.dist, args.repository) if args.command == "candidate" else promote(github, args.tag, args.repository)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(json_bytes(result))
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, EOFError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"release failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
