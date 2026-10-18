"""Deterministic paired archives and source-free distribution validation."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile

REPOSITORY = "neuralyze/herdr-maintenance"
PLATFORM = "linux-x86_64"
PRODUCTS = {"herdr": ("neuralyze/herdr", "herdrdev/herdr"),
            "herdr-mirror": ("neuralyze/herdr-mirror", "nikok6/herdr-mirror")}
SHA = re.compile(r"[0-9a-f]{40}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
MAX_BINARY = 512 * 1024 * 1024
MAX_ARCHIVE = MAX_BINARY + 1024 * 1024
MAX_JSON = 64 * 1024
ASSETS = tuple(f"{name}-{PLATFORM}.tar.gz" for name in PRODUCTS) + ("pair-manifest.json", "SHA256SUMS")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha(value: object) -> str:
    require(isinstance(value, str) and SHA.fullmatch(value) is not None, "invalid exact commit SHA")
    return value


def hash_value(value: object) -> str:
    require(isinstance(value, str) and HASH.fullmatch(value) is not None, "invalid SHA256")
    return value


def unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def json_bytes(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def regular_file(path: Path, maximum: int) -> int:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode), f"not a regular file: {path.name}")
    require(0 < info.st_size <= maximum, f"invalid file size: {path.name}")
    return info.st_size


def load_json(path: Path) -> dict:
    regular_file(path, MAX_JSON)
    result = json.loads(path.read_bytes(), object_pairs_hook=unique_object)
    require(isinstance(result, dict), "JSON root must be an object")
    return result


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def validator_head() -> str:
    # Do not inherit Git configuration, credentials, hooks, or cloud environment.
    environment = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"}
    result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                             "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parent.parent,
                            env=environment, check=True, capture_output=True, text=True)
    return sha(result.stdout.strip())


def validate_lock(lock: dict) -> None:
    require(lock.get("schema_version") == 1 and lock.get("platform") == PLATFORM, "invalid lock schema/platform")
    require(isinstance(lock.get("products"), dict) and set(lock["products"]) == set(PRODUCTS), "invalid locked products")
    for name, (repository, upstream) in PRODUCTS.items():
        row = lock["products"][name]
        require(isinstance(row, dict), "invalid locked product")
        require(row.get("repository") == repository and row.get("upstream_repository") == upstream, "unapproved source identity")
        sha(row.get("commit"))
        sha(row.get("upstream_commit"))
        require(row.get("upstream_tag") is None or isinstance(row["upstream_tag"], str), "invalid upstream tag")


def candidate_tag(manifest: dict) -> str:
    return "pair-" + "-".join([sha(manifest["products"][name]["commit"]) for name in PRODUCTS]
                              + [sha(manifest["validator_commit"])])


def archive_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o755
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = ""
    return info


def validate_archive(path: Path, name: str, expected_hash: str, expected_size: int) -> None:
    regular_file(path, MAX_ARCHIVE)
    require(type(expected_size) is int and 0 < expected_size <= MAX_BINARY, "invalid binary size")
    # Accept exactly the canonical one-file USTAR layout. No extraction, binary
    # execution, PAX overrides, links, duplicate members, or unbounded expansion.
    with gzip.open(path, "rb") as stream:
        header = stream.read(512)
        require(header == archive_info(name, expected_size).tobuf(format=tarfile.USTAR_FORMAT), "noncanonical or unsafe archive member")
        remaining = expected_size
        checksum = hashlib.sha256()
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            require(bool(block), "truncated archive binary")
            remaining -= len(block)
            checksum.update(block)
        require(checksum.hexdigest() == expected_hash, "archive binary checksum mismatch")
        padding = (-expected_size) % 512
        require(stream.read(padding) == b"\0" * padding, "invalid archive member padding")
        # tarfile writes a zero end marker and pads its record to 10240 bytes.
        trailer_size = (-(512 + expected_size + padding)) % tarfile.RECORDSIZE
        if trailer_size < 1024:
            trailer_size += tarfile.RECORDSIZE
        require(stream.read(trailer_size) == b"\0" * trailer_size, "extra, missing, or malformed archive members")
        require(stream.read(1) == b"", "trailing archive data")


def validate_manifest(manifest: dict) -> None:
    require(manifest.get("schema_version") == 1 and manifest.get("platform") == PLATFORM, "invalid manifest schema/platform")
    require(manifest.get("repository") == REPOSITORY and manifest.get("validator_repository") == REPOSITORY, "unapproved publisher/validator")
    sha(manifest.get("validator_commit"))
    hash_value(manifest.get("lock_sha256"))
    validate_lock(manifest)
    for name in PRODUCTS:
        row = manifest["products"][name]
        require(row.get("binary") == name and row.get("archive") == f"{name}-{PLATFORM}.tar.gz", "invalid product filenames")
        hash_value(row.get("sha256"))
        hash_value(row.get("archive_sha256"))
        require(type(row.get("size")) is int and 0 < row["size"] <= MAX_BINARY, "invalid binary size")
    require(manifest.get("candidate_tag") == candidate_tag(manifest), "candidate tag does not match identities")


def validate_dist(directory: Path) -> dict:
    require(directory.is_dir() and not directory.is_symlink(), "distribution must be a real directory")
    require({path.name for path in directory.iterdir()} == set(ASSETS), "distribution must contain exactly four fixed assets")
    for asset in ASSETS:
        regular_file(directory / asset, MAX_ARCHIVE if asset.endswith(".tar.gz") else MAX_JSON)
    manifest = load_json(directory / "pair-manifest.json")
    validate_manifest(manifest)
    regular_file(directory / "SHA256SUMS", MAX_JSON)
    expected = "".join(f"{digest(directory / name)}  {name}\n" for name in sorted(ASSETS) if name != "SHA256SUMS")
    require((directory / "SHA256SUMS").read_bytes() == expected.encode(), "distribution checksum list mismatch")
    for name in PRODUCTS:
        row = manifest["products"][name]
        archive = directory / row["archive"]
        require(digest(archive) == row["archive_sha256"], "archive SHA256 mismatch")
        validate_archive(archive, name, row["sha256"], row["size"])
    return manifest


def build(lock_path: Path, evidence_path: Path, output: Path) -> dict:
    lock = load_json(lock_path)
    validate_lock(lock)
    evidence = load_json(evidence_path)
    validator = validator_head()
    require(evidence.get("schema_version") == 1 and evidence.get("status") == "pass" and evidence.get("platform") == PLATFORM, "paired validation did not pass")
    require(evidence.get("validator_commit") == validator, "evidence validator differs from actual tools HEAD")
    lock_hash = digest(lock_path)
    require(evidence.get("lock_sha256") == lock_hash, "evidence lock bytes mismatch")
    require(isinstance(evidence.get("integration"), dict) and evidence["integration"].get("status") == "pass", "integration did not pass")
    require(isinstance(evidence.get("products"), dict) and set(evidence["products"]) == set(PRODUCTS), "invalid evidence products")
    binaries = {}
    for name in PRODUCTS:
        row = evidence["products"][name]
        require(isinstance(row, dict), "invalid product evidence")
        require(all(row.get(key) == lock["products"][name][key] for key in ("repository", "commit", "upstream_commit")), "evidence source/upstream pin mismatch")
        require(row.get("upstream_tests") == "pass" and row.get("regressions") == "pass", "upstream/regression tests did not pass")
        require(isinstance(row.get("binary"), str) and Path(row["binary"]).is_absolute(), "binary path must be absolute")
        binary = Path(row["binary"])
        size = regular_file(binary, MAX_BINARY)
        require(binary.stat().st_mode & 0o111 != 0, "binary is not executable")
        require(digest(binary) == hash_value(row.get("sha256")), "built binary checksum mismatch")
        binaries[name] = (binary, size)
    output.mkdir(parents=True, exist_ok=True)
    require(not output.is_symlink() and not any(output.iterdir()), "output must be an empty real directory")
    manifest = {"schema_version": 1, "repository": REPOSITORY, "platform": PLATFORM,
                "lock_sha256": lock_hash, "validator_repository": REPOSITORY,
                "validator_commit": validator, "products": {}}
    for name, (binary, size) in binaries.items():
        archive_name = f"{name}-{PLATFORM}.tar.gz"
        archive = output / archive_name
        with archive.open("xb") as destination:
            with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                    with binary.open("rb") as source:
                        tar.addfile(archive_info(name, size), source)
        row = dict(lock["products"][name])
        row.update(binary=name, size=size, sha256=evidence["products"][name]["sha256"],
                   archive=archive_name, archive_sha256=digest(archive))
        validate_archive(archive, name, row["sha256"], size)
        manifest["products"][name] = row
    manifest["candidate_tag"] = candidate_tag(manifest)
    (output / "pair-manifest.json").write_bytes(json_bytes(manifest))
    checksums = "".join(f"{digest(output / name)}  {name}\n" for name in sorted(ASSETS) if name != "SHA256SUMS")
    (output / "SHA256SUMS").write_text(checksums)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("build")
    command.add_argument("--lock", type=Path, required=True)
    command.add_argument("--evidence", type=Path, required=True)
    command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = build(args.lock, args.evidence, args.output)
        print(json.dumps({"status": "packaged", "tag": manifest["candidate_tag"]}))
    except (OSError, ValueError, KeyError, TypeError, EOFError, tarfile.TarError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"packaging failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
