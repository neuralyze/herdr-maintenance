"""Pinned public-source validation; subprocesses never inherit authentication variables."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import tempfile

PRODUCTS = {"herdr": "neuralyze/herdr", "herdr-mirror": "neuralyze/herdr-mirror"}
SHA = re.compile(r"[0-9a-f]{40}\Z")
HERDR_REGRESSIONS = (
    "managed_terminal_cycles_preserve_connection_binding_dimensions_and_release_lease",
    "managed_terminal_input_is_read_only_before_acquire_and_after_demote",
    "managed_terminal_transition_waits_for_synchronized_full_frame_without_delaying_release",
    "backpressured_observer_skips_runtime_access_and_recovers_without_new_output",
    "reliable_overflow_wakes_inflight_writer_and_reader_without_affecting_peer",
    "api_pane_output_is_fanned_out_as_pane_surface_updates",
)
MIRROR_REGRESSIONS = (
    "first_input_waits_for_initial_state_and_exact_control_ack_once",
    "transitions_keep_one_stream_and_stale_observe_ack_cannot_flush_paste",
    "denied_acquire_keeps_viewable_stream_and_discards_rejected_input",
    "idle_release_and_first_wheel_retake_are_in_place_and_exactly_once",
)


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def clean_environment(home: Path, *, build: bool = False) -> dict[str, str]:
    """Allowlist, rather than an ever-incomplete blacklist of credential names."""
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
           "HOME": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "TERM": "xterm-256color", "SHELL": "/bin/sh", "CI": "true",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_TERMINAL_PROMPT": "0", "HERDR_NO_UPDATE_CHECK": "1"}
    for name, directory in (("XDG_CONFIG_HOME", "config"), ("XDG_CACHE_HOME", "cache"),
                            ("XDG_DATA_HOME", "data"), ("XDG_STATE_HOME", "state"),
                            ("XDG_RUNTIME_DIR", "run"), ("TMPDIR", "tmp")):
        path = home / directory
        path.mkdir(mode=0o700, exist_ok=True)
        env[name] = str(path)
    if build:
        # Both toolchain installs and Cargo state are invocation-private: no
        # global installation, rustup settings, registry credentials or config.
        env["RUSTUP_HOME"] = str(home / "rustup")
        env["CARGO_HOME"] = str(home / "cargo")
        for name in ("ZIG", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"):
            if name in os.environ:
                env[name] = os.environ[name]
    return env


class Runner:
    def __init__(self, output: Path, env: dict[str, str]):
        self.output = output
        self.env = env
        self.sequence = 0
        output.mkdir(parents=True, exist_ok=True)

    def run(self, args: list[str], cwd: Path, *, timeout: int = 1800, expected_code: int = 0) -> str:
        self.sequence += 1
        log = self.output / f"{self.sequence:02d}-{Path(args[0]).name}.log"
        with log.open("wb") as handle:
            process = subprocess.Popen(args, cwd=cwd, env=self.env, stdin=subprocess.DEVNULL,
                                       stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
                raise
        if code != expected_code:
            raise RuntimeError(f"{args!r} exited {code}; see {log}")
        return log.read_text(errors="replace")


def require_sha(value: object) -> str:
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError("commit must be an exact lowercase 40-hex SHA")
    return value


def validate_lock(lock: dict) -> None:
    if not isinstance(lock, dict) or lock.get("schema_version") != 1 or lock.get("platform") != "linux-x86_64":
        raise ValueError("unsupported pair lock schema/platform")
    if not isinstance(lock.get("products"), dict) or set(lock["products"]) != set(PRODUCTS):
        raise ValueError("pair lock must name exactly both approved products")
    for product, repository in PRODUCTS.items():
        row = lock["products"][product]
        if not isinstance(row, dict) or row.get("repository") != repository:
            raise ValueError("unapproved fork repository")
        expected_upstream = "herdrdev/herdr" if product == "herdr" else "nikok6/herdr-mirror"
        if row.get("upstream_repository") != expected_upstream:
            raise ValueError("unapproved upstream repository")
        require_sha(row.get("commit"))
        require_sha(row.get("upstream_commit"))


def source_identity(product: str, source: Path, runner: Runner) -> dict:
    origin = runner.run(["git", "remote", "get-url", "origin"], source, timeout=20).strip()
    if origin not in (f"https://github.com/{PRODUCTS[product]}.git", f"https://github.com/{PRODUCTS[product]}"):
        raise ValueError("source origin must be the configured public fork HTTPS URL")
    commit = require_sha(runner.run(["git", "rev-parse", "HEAD"], source, timeout=20).strip())
    if runner.run(["git", "status", "--porcelain", "--untracked-files=no"], source, timeout=20).strip():
        raise ValueError("source checkout has tracked modifications")
    provenance = json.loads((source / ".maintenance/upstream.json").read_text())
    upstream = "herdrdev/herdr" if product == "herdr" else "nikok6/herdr-mirror"
    if (provenance.get("schema_version") != 1 or provenance.get("product") != product
            or provenance.get("upstream_repository") != upstream):
        raise ValueError("source upstream provenance does not match product")
    return {"repository": PRODUCTS[product], "commit": commit,
            "upstream_commit": require_sha(provenance.get("upstream_commit"))}


def component(product: str, source: Path, output: Path, jobs: int) -> dict:
    source = source.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="herdr-build-") as private:
        env = clean_environment(Path(private), build=True)
        env["CARGO_BUILD_JOBS"] = str(jobs)
        runner = Runner(output, env)
        row = source_identity(product, source, runner)
        if product == "herdr":
            import tomllib
            toolchain = tomllib.loads((source / "rust-toolchain.toml").read_text())["toolchain"]
            channel = toolchain["channel"]
            if not isinstance(channel, str) or not re.fullmatch(r"[0-9A-Za-z_.-]+", channel):
                raise ValueError("invalid source Rust toolchain")
            runner.run(["rustup", "toolchain", "install", channel, "--profile", "minimal",
                        "--component", "clippy,rustfmt"], source)
            env["RUSTUP_TOOLCHAIN"] = channel
            runner.run(["just", "ci"], source, timeout=3600)
            # Each filter runs separately: one existing test cannot mask a removed one.
            for name in HERDR_REGRESSIONS:
                runner.run(["cargo", "nextest", "run", "--locked", "--no-tests=fail", "-E", f"test({name})"], source)
        else:
            runner.run(["rustup", "toolchain", "install", "stable", "--profile", "minimal",
                        "--component", "clippy"], source)
            env["RUSTUP_TOOLCHAIN"] = "stable"
            runner.run(["cargo", "test", "--locked"], source)
            runner.run(["cargo", "clippy", "--all-targets", "--locked", "--", "-D", "warnings"], source)
            listing = runner.run(["cargo", "test", "--locked", "--", "--list"], source)
            for name in MIRROR_REGRESSIONS:
                full = f"pane::tests::{name}"
                if f"{full}: test" not in listing.splitlines():
                    raise RuntimeError(f"required consumer regression missing: {full}")
                runner.run(["cargo", "test", "--locked", full, "--", "--exact"], source)
        runner.run(["cargo", "build", "--release", "--locked", "--jobs", str(jobs)], source, timeout=3600)
        binary = (source / "target/release" / product).resolve(strict=True)
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError("release executable missing")
        if product == "herdr":
            version = runner.run([str(binary), "--version"], source, timeout=15)
            if product not in version:
                raise RuntimeError("binary version check did not identify the product")
        else:
            # Mirror has no --version/--help option. Its real CLI argument
            # parser identifies the binary without resolving any user state.
            usage = runner.run([str(binary), "pane"], source, timeout=15, expected_code=2)
            if "usage: herdr-mirror pane" not in usage:
                raise RuntimeError("mirror binary command contract check failed")
        # Refuse source mutation by build hooks, tests or background processes.
        if source_identity(product, source, runner) != row:
            raise RuntimeError("source identity changed during validation")
        row.update(binary=str(binary), sha256=digest(binary), upstream_tests="pass", regressions="pass")
        return row


def pair(lock_path: Path, workspace: Path, output: Path, jobs: int) -> dict:
    from .pair_smoke import smoke
    output.mkdir(parents=True, exist_ok=True)
    evidence_path = output / "ci-evidence.json"
    evidence_path.write_text(json.dumps({"schema_version": 1, "status": "fail"}) + "\n")
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
        raise RuntimeError("paired fixture requires linux-x86_64")
    lock_bytes = lock_path.read_bytes()
    lock = json.loads(lock_bytes)
    validate_lock(lock)
    workspace.mkdir(parents=True, exist_ok=True)
    rows = {}
    with tempfile.TemporaryDirectory(prefix="herdr-fetch-") as private:
        runner = Runner(output / "checkout", clean_environment(Path(private)))
        tool_root = Path(__file__).resolve().parents[1]
        validator = require_sha(runner.run(["git", "rev-parse", "HEAD"], tool_root, timeout=20).strip())
        if runner.run(["git", "status", "--porcelain", "--untracked-files=no"], tool_root, timeout=20).strip():
            raise RuntimeError("validator checkout has tracked modifications")
        for product, pin in lock["products"].items():
            source = workspace / product
            source.mkdir()  # A used workspace is an error, never a mutable-ref update.
            runner.run(["git", "init", "--quiet", str(source.resolve())], workspace, timeout=20)
            runner.run(["git", "remote", "add", "origin", f"https://github.com/{pin['repository']}.git"], source, timeout=20)
            runner.run(["git", "fetch", "--depth=1", "--no-tags", "origin", pin["commit"]], source, timeout=180)
            runner.run(["git", "checkout", "--detach", pin["commit"]], source, timeout=30)
            rows[product] = component(product, source, output / product, jobs)
            if any(rows[product][key] != pin[key] for key in ("repository", "commit", "upstream_commit")):
                raise RuntimeError("validated source identity differs from pair pin")
    report_path = output / "integration.json"
    report = smoke(Path(rows["herdr"]["binary"]), Path(rows["herdr-mirror"]["binary"]), report_path)
    if report.get("status") != "pass" or report.get("cleanup", {}).get("complete") is not True:
        raise RuntimeError(f"real private paired integration failed; see {report_path}")
    for row in rows.values():
        if digest(Path(row["binary"])) != row["sha256"]:
            raise RuntimeError("binary changed during integration")
    evidence = {"schema_version": 1, "status": "pass", "platform": "linux-x86_64",
                "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(), "validator_commit": validator,
                "products": rows, "integration": {"status": "pass", "report": str(report_path.resolve())}}
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n")
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("component")
    one.add_argument("--product", choices=PRODUCTS, required=True)
    one.add_argument("--source", type=Path, required=True)
    both = sub.add_parser("pair")
    both.add_argument("--lock", type=Path, required=True)
    both.add_argument("--workspace", type=Path, required=True)
    for command in (one, both):
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32:
        parser.error("--jobs must be between 1 and 32")
    try:
        if args.command == "component":
            result = component(args.product, args.source, args.output, args.jobs)
            (args.output / "component-evidence.json").write_text(json.dumps(result, indent=2) + "\n")
        else:
            pair(args.lock, args.workspace.resolve(), args.output.resolve(), args.jobs)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"validation failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
