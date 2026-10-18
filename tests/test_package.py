"""Exercise actual binary bytes, deterministic archives and evidence boundaries."""
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from maintenance import package

VALIDATOR = "c" * 40


def make_distribution(root: Path, validator: str = VALIDATOR) -> tuple[Path, Path, Path]:
    root.mkdir(parents=True, exist_ok=True)
    lock = {"schema_version": 1, "platform": package.PLATFORM, "products": {}}
    evidence = {"schema_version": 1, "status": "pass", "platform": package.PLATFORM,
                "validator_commit": validator, "products": {}, "integration": {"status": "pass", "report": "integration.json"}}
    for index, (name, (repository, upstream)) in enumerate(package.PRODUCTS.items()):
        pin = {"repository": repository, "commit": ("a" if index == 0 else "b") * 40,
               "upstream_repository": upstream, "upstream_commit": ("d" if index == 0 else "e") * 40,
               "upstream_tag": None}
        lock["products"][name] = pin
        binary = root / name
        binary.write_bytes(b"\x7fELF\x00real-fixture-bytes-" + name.encode())
        binary.chmod(0o755)
        evidence["products"][name] = {key: pin[key] for key in ("repository", "commit", "upstream_commit")}
        evidence["products"][name].update(binary=str(binary.resolve()), sha256=package.digest(binary), upstream_tests="pass", regressions="pass")
    lock_path = root / "lock.json"
    evidence_path = root / "evidence.json"
    lock_path.write_bytes(package.json_bytes(lock))
    evidence["lock_sha256"] = package.digest(lock_path)
    evidence_path.write_bytes(package.json_bytes(evidence))
    distribution = root / "dist"
    with patch.object(package, "validator_head", return_value=validator):
        package.build(lock_path, evidence_path, distribution)
    return distribution, lock_path, evidence_path


def rewrite_checksums(distribution: Path) -> None:
    manifest_path = distribution / "pair-manifest.json"
    manifest = package.load_json(manifest_path)
    for row in manifest["products"].values():
        row["archive_sha256"] = package.digest(distribution / row["archive"])
    manifest_path.write_bytes(package.json_bytes(manifest))
    (distribution / "SHA256SUMS").write_text("".join(
        f"{package.digest(distribution / name)}  {name}\n" for name in sorted(package.ASSETS) if name != "SHA256SUMS"))


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dist, self.lock_path, self.evidence_path = make_distribution(self.root)

    def test_deterministic_real_archives(self):
        manifest = package.validate_dist(self.dist)
        second = self.root / "second"
        with patch.object(package, "validator_head", return_value=VALIDATOR):
            package.build(self.lock_path, self.evidence_path, second)
        for name in package.ASSETS:
            self.assertEqual((self.dist / name).read_bytes(), (second / name).read_bytes())
        for name in package.PRODUCTS:
            archive = self.dist / manifest["products"][name]["archive"]
            self.assertEqual(archive.read_bytes()[4:8], b"\0" * 4)
            with tarfile.open(archive, "r:gz") as tar:
                self.assertEqual([item.name for item in tar], [name])
                member = tar.getmember(name)
                self.assertEqual(member.mode, 0o755)
                self.assertEqual(member.mtime, 0)
                self.assertEqual(tar.extractfile(member).read(), (self.root / name).read_bytes())

    def test_evidence_fail_closed(self):
        original = package.load_json(self.evidence_path)
        cases = [("status", "fail"), ("validator_commit", "f" * 40), ("lock_sha256", "0" * 64)]
        for key, value in cases:
            with self.subTest(key=key):
                evidence = copy.deepcopy(original)
                evidence[key] = value
                self.evidence_path.write_bytes(package.json_bytes(evidence))
                with patch.object(package, "validator_head", return_value=VALIDATOR), self.assertRaises(ValueError):
                    package.build(self.lock_path, self.evidence_path, self.root / "rejected")
        for key, value in (("repository", "attacker/herdr"), ("commit", "f" * 40), ("upstream_commit", "f" * 40),
                           ("upstream_tests", "fail"), ("regressions", "fail"), ("sha256", "0" * 64)):
            with self.subTest(product_key=key):
                evidence = copy.deepcopy(original)
                evidence["products"]["herdr"][key] = value
                self.evidence_path.write_bytes(package.json_bytes(evidence))
                with patch.object(package, "validator_head", return_value=VALIDATOR), self.assertRaises(ValueError):
                    package.build(self.lock_path, self.evidence_path, self.root / "rejected")
        original["integration"]["status"] = "fail"
        self.evidence_path.write_bytes(package.json_bytes(original))
        with patch.object(package, "validator_head", return_value=VALIDATOR), self.assertRaises(ValueError):
            package.build(self.lock_path, self.evidence_path, self.root / "rejected")

    def test_exact_lock_bytes_and_binary_bytes(self):
        self.lock_path.write_bytes(self.lock_path.read_bytes() + b"\n")
        with patch.object(package, "validator_head", return_value=VALIDATOR), self.assertRaises(ValueError):
            package.build(self.lock_path, self.evidence_path, self.root / "rejected")
        evidence = package.load_json(self.evidence_path)
        evidence["lock_sha256"] = package.digest(self.lock_path)
        self.evidence_path.write_bytes(package.json_bytes(evidence))
        (self.root / "herdr").write_bytes(b"tampered")
        with patch.object(package, "validator_head", return_value=VALIDATOR), self.assertRaises(ValueError):
            package.build(self.lock_path, self.evidence_path, self.root / "rejected")

    def test_symlink_and_nonexecutable_source_rejected(self):
        binary = self.root / "herdr"
        binary.chmod(0o644)
        with patch.object(package, "validator_head", return_value=VALIDATOR), self.assertRaises(ValueError):
            package.build(self.lock_path, self.evidence_path, self.root / "rejected")
        binary.rename(self.root / "real")
        binary.symlink_to(self.root / "real")
        with patch.object(package, "validator_head", return_value=VALIDATOR), self.assertRaises(ValueError):
            package.build(self.lock_path, self.evidence_path, self.root / "rejected")

    def test_dist_checksum_tamper(self):
        (self.dist / package.ASSETS[0]).write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            package.validate_dist(self.dist)

    def test_exact_distribution_members_and_symlinks(self):
        extra = self.dist / "unexpected"
        extra.write_bytes(b"extra")
        with self.assertRaises(ValueError):
            package.validate_dist(self.dist)
        extra.unlink()
        archive = self.dist / package.ASSETS[0]
        archive.rename(self.root / "original.tar.gz")
        archive.symlink_to(self.root / "original.tar.gz")
        with self.assertRaises(ValueError):
            package.validate_dist(self.dist)

    def test_archive_unsafe_and_duplicate_members(self):
        archive = self.dist / package.ASSETS[0]
        binary = (self.root / "herdr").read_bytes()
        original = archive.read_bytes()
        for kind in ("traversal", "absolute", "symlink", "hardlink", "duplicate", "extra", "missing", "nonexecutable", "oversize", "pax"):
            with self.subTest(kind=kind):
                with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT if kind == "pax" else tarfile.USTAR_FORMAT) as tar:
                    info = package.archive_info("herdr", len(binary))
                    if kind == "traversal":
                        info.name = "../herdr"
                    elif kind == "absolute":
                        info.name = "/herdr"
                    elif kind in ("symlink", "hardlink"):
                        info.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                        info.linkname = "outside"
                        info.size = 0
                    elif kind == "nonexecutable":
                        info.mode = 0o644
                    elif kind == "oversize":
                        info.size = package.MAX_BINARY + 1
                    elif kind == "pax":
                        info.pax_headers = {"comment": "extension not allowed"}
                    if kind != "missing":
                        if kind == "oversize":
                            # An actual oversized declared header, not oversized allocation.
                            tar.fileobj.write(info.tobuf(format=tarfile.USTAR_FORMAT))
                        else:
                            tar.addfile(info, io.BytesIO(binary) if info.size else None)
                    if kind in ("duplicate", "extra"):
                        tar.addfile(package.archive_info("herdr" if kind == "duplicate" else "other", 1), io.BytesIO(b"x"))
                rewrite_checksums(self.dist)
                with self.assertRaises(ValueError):
                    package.validate_dist(self.dist)
                archive.write_bytes(original)
                rewrite_checksums(self.dist)

    def test_trailing_truncated_and_binary_hash_tamper(self):
        archive = self.dist / package.ASSETS[0]
        original = archive.read_bytes()
        uncompressed = gzip.decompress(original)
        for payload in (uncompressed + b"x", uncompressed[:513], uncompressed[:512] + b"X" + uncompressed[513:]):
            archive.write_bytes(gzip.compress(payload, mtime=0))
            rewrite_checksums(self.dist)
            with self.assertRaises(ValueError):
                package.validate_dist(self.dist)
        archive.write_bytes(original[:-5])
        rewrite_checksums(self.dist)
        with self.assertRaises((ValueError, EOFError)):
            package.validate_dist(self.dist)

    def test_duplicate_json_key_and_manifest_identity(self):
        duplicate = self.root / "duplicate.json"
        duplicate.write_bytes(b'{"schema_version":1,"schema_version":1}')
        with self.assertRaises(ValueError):
            package.load_json(duplicate)
        manifest = package.load_json(self.dist / "pair-manifest.json")
        manifest["products"]["herdr"]["repository"] = "other/herdr"
        with self.assertRaises(ValueError):
            package.validate_manifest(manifest)
        manifest["products"]["herdr"]["repository"] = "neuralyze/herdr"
        manifest["candidate_tag"] = "pair-wrong"
        with self.assertRaises(ValueError):
            package.validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
