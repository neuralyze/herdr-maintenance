"""Real localhost SSH/mirror/sink acceptance fixture; no models or fleet endpoints.

The transparent relay records real Herdr state barriers without creating or
interpreting requests. Mirror's normal stdin path owns all acquire/release
requests. --dump exposes the actual mirror grid for consumer-visible assertions.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import selectors
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

CAP = 8 * 1024 * 1024
HERE = Path(__file__).resolve()


def identity(pid: int) -> dict:
    root = Path("/proc") / str(pid)
    fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "start": fields[19], "uid": root.stat().st_uid,
            "state": fields[0], "ppid": int(fields[1])}


def alive(row: dict) -> bool:
    try:
        now = identity(row["pid"])
        return now["start"] == row["start"] and now["uid"] == row["uid"] and now["state"] != "Z"
    except (OSError, ValueError):
        return False


def signal_owned(row: dict, signum: int) -> None:
    """pidfd pins the checked generation, including privileged sshd descendants."""
    if not alive(row):
        return
    try:
        fd = os.pidfd_open(row["pid"])
    except ProcessLookupError:
        return
    try:
        if alive(row):
            try:
                signal.pidfd_send_signal(fd, signum)
            except ProcessLookupError:
                pass
    finally:
        os.close(fd)


def rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    if path.stat().st_size > CAP:
        raise RuntimeError(f"fixture journal size bound: {path.name}")
    lines = path.read_bytes().split(b"\n")
    # Last line can be in flight; a complete malformed line is never ignored.
    return [json.loads(line) for line in lines[:-1] if line]


def rpc(path: Path, method: str, **params: object) -> dict:
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(3)
        connection.connect(str(path))
        connection.sendall((json.dumps({"id": "pair-fixture", "method": method, "params": params}) + "\n").encode())
        data = bytearray()
        while b"\n" not in data:
            block = connection.recv(65536)
            if not block:
                raise RuntimeError("private API EOF")
            data.extend(block)
            if len(data) > CAP:
                raise RuntimeError("private API response bound")
    row = json.loads(data.split(b"\n", 1)[0])
    if row.get("error") or row.get("ok") is False:
        raise RuntimeError(f"private API {method} failed: {row}")
    return row.get("result", row)


def relay(binary: Path, journal_dir: Path, argv: list[str]) -> int:
    """Byte-for-byte stdio tee around the *actual* pinned remote Herdr CLI."""
    if argv[:3] != ["terminal", "session", "managed"]:
        os.execve(str(binary), [str(binary), *argv], dict(os.environ))
    process = subprocess.Popen([str(binary), *argv], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert process.stdin is not None and process.stdout is not None
    path = journal_dir / f"stream-{os.getpid()}.jsonl"
    with path.open("x", buffering=1) as log:
        def record(kind: str, **values: object) -> None:
            log.write(json.dumps({"type": kind, "mono_ns": time.monotonic_ns(), **values}) + "\n")
        record("start", relay=identity(os.getpid()), cli=identity(process.pid), argv=argv)
        poll = selectors.DefaultSelector()
        poll.register(sys.stdin.fileno(), selectors.EVENT_READ, "input")
        poll.register(process.stdout.fileno(), selectors.EVENT_READ, "output")
        pending = bytearray()
        end = time.monotonic() + 110
        try:
            while time.monotonic() < end:
                for key, _ in poll.select(.25):
                    data = os.read(key.fd, 65536)
                    if key.data == "input":
                        if not data:
                            poll.unregister(key.fd)
                            process.stdin.close()
                        else:
                            process.stdin.write(data)
                            process.stdin.flush()
                    else:
                        if not data:
                            return process.wait(timeout=3)
                        # Log barriers before forwarding; timestamps are real
                        # receipt bounds, not claimed source render timestamps.
                        pending.extend(data)
                        if len(pending) > CAP:
                            raise RuntimeError("managed stdout frame bound exceeded")
                        while b"\n" in pending:
                            line, _, pending = pending.partition(b"\n")
                            message = json.loads(line)
                            if message.get("type") == "terminal.state":
                                record("state", state=message)
                        sys.stdout.buffer.write(data)
                        sys.stdout.buffer.flush()
            raise TimeoutError("remote relay deadline")
        finally:
            poll.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)


class Fixture:
    def __init__(self, root: Path, herdr: Path, mirror: Path):
        from maintenance.ci import clean_environment
        self.root, self.herdr, self.mirror = root, herdr, mirror
        self.env = clean_environment(root / "home")
        # No inherited paths to ssh, cloud helpers, agents or user dotfiles.
        self.env["PATH"] = str(root / "bin") + ":/usr/local/bin:/usr/bin:/bin"
        self.env.update(HERDR_CONFIG_PATH=str(root / "config.toml"),
                        HERDR_SOCKET_PATH=str(root / "api.sock"),
                        HERDR_CLIENT_SOCKET_PATH=str(root / "client.sock"))
        self.processes: list[subprocess.Popen] = []
        self.ledger: dict[tuple[int, str], dict] = {}
        self.handles = []
        self.mirrors: list[dict] = []
        self.privileged = os.geteuid() != 0
        self.sshd: Path | None = None
        self.sshd_identity: dict | None = None

    def command(self, argv: list[str], timeout: float = 10) -> str:
        process = subprocess.Popen(argv, env=self.env, cwd=self.root, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        self.processes.append(process)
        self.discover()
        try:
            data, _ = process.communicate(timeout=timeout)
        except BaseException:
            self.discover()
            process.kill()
            process.communicate(timeout=3)
            raise
        if process.returncode:
            raise RuntimeError(f"fixture command {argv[:3]!r} failed: {data.decode(errors='replace')[:1500]}")
        return data.decode(errors="replace")

    def spawn(self, argv: list[str], name: str, *, input_pipe: bool = False) -> subprocess.Popen:
        output = (self.root / f"{name}.log").open("xb")
        self.handles.append(output)
        process = subprocess.Popen(argv, env=self.env, cwd=self.root,
                                   stdin=subprocess.PIPE if input_pipe else subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        self.processes.append(process)
        self.discover()
        return process

    def discover(self) -> None:
        pending = []
        for process in self.processes:
            if process.poll() is None:
                try:
                    pending.append(identity(process.pid))
                except OSError:
                    pass
        pending.extend(row for row in self.ledger.values() if alive(row))
        pid_file = self.root / "sshd.pid"
        if pid_file.exists() and self.sshd_identity is None:
            candidate = identity(int(pid_file.read_text().strip()))
            command = (Path("/proc") / str(candidate["pid"]) / "cmdline").read_bytes()
            if str(self.root / "sshd_config").encode() not in command:
                raise RuntimeError("private sshd pidfile no longer names this daemon")
            self.sshd_identity = candidate
        if self.sshd_identity is not None and alive(self.sshd_identity):
            pending.append(self.sshd_identity)
        for path in (self.root / "streams").glob("stream-*.jsonl"):
            events = rows(path)
            if events:
                for key in ("relay", "cli"):
                    row = events[0].get(key)
                    if row and alive(row):
                        pending.append(row)
        seen = set()
        while pending:
            row = pending.pop()
            pid = row["pid"]
            generation = (pid, row["start"])
            if generation in seen or not alive(row):
                continue
            seen.add(generation)
            if len(seen) > 256:
                raise RuntimeError("private process descendant bound")
            self.ledger[generation] = row
            try:
                for task in (Path("/proc") / str(pid) / "task").iterdir():
                    try:
                        children = (task / "children").read_text().split()
                        for value in children:
                            child = identity(int(value))
                            # A rapidly reaped/reused PID is not ownership.
                            if child["ppid"] == pid and alive(row):
                                pending.append(child)
                    except (OSError, ValueError):
                        pass
            except OSError:
                pass

    def wait(self, predicate, label: str, seconds: float = 5):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.discover()
            result = predicate()
            if result:
                return result
            for mirror in self.mirrors:
                if mirror["process"].poll() is not None:
                    raise RuntimeError(f"mirror {mirror['pane']} exited during {label}")
            for path in self.root.glob("*.log"):
                if path.stat().st_size > CAP:
                    raise RuntimeError("fixture output size bound")
            time.sleep(.02)
        raise TimeoutError(f"deadline waiting for {label}")

    def setup(self) -> None:
        for executable in ("ssh", "ssh-keygen", "sshd"):
            found = shutil.which(executable, path="/usr/sbin:/usr/bin:/sbin:/bin")
            if found is None:
                raise RuntimeError(f"required existing openssh-server/client executable unavailable: {executable}")
            if executable == "sshd":
                self.sshd = Path(found)
        if self.privileged:
            self.command(["sudo", "-n", "true"])
        (self.root / "bin").mkdir(mode=0o700)
        (self.root / "streams").mkdir(mode=0o700)
        (self.root / "config.toml").write_text(
            'onboarding = false\n[terminal]\ndefault_shell = "/bin/sh"\nshell_mode = "non_login"\n'
            '[session]\nresume_agents_on_restore = false\n[remote]\nmanage_ssh_config = false\n')
        self.command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.root / "host_key")])
        self.command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.root / "client_key")])
        username = pwd.getpwuid(os.getuid()).pw_name
        if not username.replace("_", "").replace("-", "").isalnum():
            raise RuntimeError("unsupported local ssh fixture username")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        (self.root / "authorized_keys").write_text((self.root / "client_key.pub").read_text())
        os.chmod(self.root / "authorized_keys", 0o600)
        host_key = (self.root / "host_key.pub").read_text().split()
        (self.root / "known_hosts").write_text(f"[127.0.0.1]:{port} {host_key[0]} {host_key[1]}\n")
        config = self.root / "ssh_config"
        config.write_text(
            f"Host fixture\n HostName 127.0.0.1\n Port {port}\n User {username}\n"
            f" IdentityFile {self.root}/client_key\n IdentitiesOnly yes\n IdentityAgent none\n"
            f" UserKnownHostsFile {self.root}/known_hosts\n GlobalKnownHostsFile /dev/null\n"
            " StrictHostKeyChecking yes\n BatchMode yes\n ConnectTimeout 3\n ConnectionAttempts 1\n"
            " ProxyCommand none\n ProxyJump none\n ControlMaster no\n ControlPath none\n"
            " CanonicalizeHostname no\n ClearAllForwardings yes\n LogLevel ERROR\n")
        wrapper = self.root / "bin/ssh"
        wrapper.write_text("#!/bin/sh\nexec /usr/bin/ssh -F " + shlex.quote(str(config)) + ' "$@"\n')
        wrapper.chmod(0o700)
        remote = self.root / "remote-herdr"
        remote.write_text("#!/bin/sh\nexec /usr/bin/env -i " + shlex.join([f"{key}={value}" for key, value in self.env.items()])
                          + " " + shlex.join([sys.executable, str(HERE), "relay", "--binary", str(self.herdr),
                                              "--journal-dir", str(self.root / "streams"), "--"]) + ' "$@"\n')
        remote.chmod(0o700)
        self.remote = remote
        dispatch = self.root / "remote-dispatch"
        dispatch.write_text("#!/bin/sh\ncd " + shlex.quote(str(self.root)) + "\nexec /usr/bin/env -i "
                            + shlex.join([f"{key}={value}" for key, value in self.env.items()])
                            + ' /bin/sh -c "$SSH_ORIGINAL_COMMAND"\n')
        dispatch.chmod(0o700)
        # A private -f file, explicit host key, private authorization, loopback
        # only. No ssh-agent, user RC, password, forwarding, subsystem or PAM.
        daemon_config = self.root / "sshd_config"
        daemon_config.write_text(
            f"Port {port}\nListenAddress 127.0.0.1\nHostKey {self.root}/host_key\n"
            f"PidFile {self.root}/sshd.pid\nAuthorizedKeysFile {self.root}/authorized_keys\n"
            f"ForceCommand {dispatch}\nSetEnv HOME={self.root}/home BASH_ENV=/dev/null ENV=/dev/null\n"
            f"AllowUsers {username}\nStrictModes yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
            "PubkeyAuthentication yes\nAuthenticationMethods publickey\nUsePAM no\nPermitRootLogin prohibit-password\n"
            "PermitUserEnvironment no\nPermitUserRC no\nAllowAgentForwarding no\nAllowTcpForwarding no\n"
            "AllowStreamLocalForwarding no\nX11Forwarding no\nPermitTunnel no\nPrintMotd no\nPrintLastLog no\n"
            "LoginGraceTime 10\nMaxAuthTries 1\nMaxSessions 8\nLogLevel VERBOSE\n")
        # sshd's compiled privilege-separation directory must already exist.
        # The workflow installs openssh-server; this fixture never mutates /run.
        self.command((["sudo", "-n"] if self.privileged else []) + [str(self.sshd), "-t", "-f", str(daemon_config)])
        self.spawn((["sudo", "-n"] if self.privileged else []) + [str(self.sshd), "-D", "-e", "-f", str(daemon_config)], "sshd")
        self.wait(lambda: (self.root / "sshd.pid").is_file(), "private foreground sshd")
        self.spawn([str(self.herdr), "server"], "server")
        self.wait(lambda: Path(self.env["HERDR_SOCKET_PATH"]).is_socket(), "private Herdr server", 10)
        status = json.loads(self.command([str(self.herdr), "status", "--json"]))
        if status.get("server", {}).get("socket") != self.env["HERDR_SOCKET_PATH"]:
            raise RuntimeError("Herdr selected a non-private socket")
        self.command([str(wrapper), "fixture", "true"])

    def pane(self, index: int) -> dict:
        result = rpc(Path(self.env["HERDR_SOCKET_PATH"]), "workspace.create", cwd=str(self.root), label=f"pair-sink-{index}", focus=False)
        pane_id = result.get("root_pane", {}).get("pane_id")
        if not isinstance(pane_id, str):
            raise RuntimeError("unsupported actual workspace.create root_pane schema")
        receipt = self.root / f"sink-{index}.jsonl"
        sink = HERE.parents[1] / "fixtures/input_sink.py"
        self.command([str(self.herdr), "pane", "run", pane_id,
                      "exec " + shlex.join([sys.executable, str(sink), "--receipts", str(receipt), "--seconds", "110"])])
        ready = self.wait(lambda: next((row for row in rows(receipt) if row["type"] == "ready"), None), "real raw sink")
        if ready.get("raw_echo_off") is not True:
            raise RuntimeError("source terminal is not echo-off")
        process = self.spawn([str(self.mirror), "pane", "fixture", pane_id, "--remote-bin", str(self.remote),
                              "--dump", "--cols", "120", "--rows", "40", "--control-idle", "0"],
                             f"mirror-{index}", input_pipe=True)
        result = {"process": process, "pane": pane_id, "receipt": receipt,
                  "output": self.root / f"mirror-{index}.log", "received": b"", "source_ready": ready}
        self.mirrors.append(result)
        self.wait(lambda: b"SOURCE-SINK-READY" in result["output"].read_bytes(), "actual mirror grid")
        initial = self.wait(lambda: self.states(result, "observe", 0), "initial authoritative observe")
        result["stream"] = initial["stream"]
        result["initial"] = initial
        self.assert_stream(result)
        return result

    def states(self, pane: dict, mode: str, after: int, *, exact: bool = False):
        found = []
        for path in (self.root / "streams").glob("stream-*.jsonl"):
            events = rows(path)
            if not events or events[0].get("argv", [])[:4] != ["terminal", "session", "managed", pane["pane"]]:
                continue
            for event in events:
                state = event.get("state", {})
                request = state.get("request_id", -1)
                if (state.get("mode") == mode and (request == after if exact else request >= after)
                        and not state.get("error")):
                    found.append({"stream": events[0], "state": state, "mono_ns": event["mono_ns"]})
        return found[-1] if found else None

    def assert_stream(self, pane: dict) -> None:
        starts = [events[0] for path in (self.root / "streams").glob("stream-*.jsonl")
                  if (events := rows(path)) and events[0].get("argv", [])[:4] == ["terminal", "session", "managed", pane["pane"]]]
        if starts != [pane["stream"]] or not alive(pane["stream"]["cli"]) or not alive(pane["stream"]["relay"]):
            raise RuntimeError("managed remote CLI generation changed or reconnected")
        # Also pin the *local SSH* process, not only its remote CLI.
        self.discover()
        candidates = []
        for row in self.ledger.values():
            if not alive(row) or row["uid"] != os.getuid():
                continue
            try:
                argv = (Path("/proc") / str(row["pid"]) / "cmdline").read_bytes().split(b"\0")
                if argv and Path(os.fsdecode(argv[0])).name == "ssh" and any(
                        ("terminal session managed '" + pane["pane"] + "'").encode() in arg for arg in argv):
                    candidates.append(row)
            except OSError:
                pass
        if len(candidates) != 1:
            raise RuntimeError("exact actual SSH stream process unavailable")
        pinned = {key: candidates[0][key] for key in ("pid", "start", "uid")}
        if "ssh" in pane and pane["ssh"] != pinned:
            raise RuntimeError("SSH stream process identity changed")
        pane["ssh"] = pinned

    def input_cycle(self, pane: dict, text: bytes, previous: int) -> dict:
        assert pane["process"].stdin is not None
        sent = time.monotonic_ns()
        pane["process"].stdin.write(text)
        pane["process"].stdin.flush()
        expected = pane["received"] + text
        receipt = self.wait(lambda: next((row for row in rows(pane["receipt"])
                                          if row.get("cumulative_hex") == expected.hex()), None), "source-confirmed ordinary input", 3)
        control = self.wait(lambda: self.states(pane, "control", previous + 1), "authoritative control ack", 3)
        if not sent <= control["mono_ns"] <= receipt["mono_ns"]:
            raise RuntimeError("first input arrived without its authoritative control barrier")
        self.wait(lambda: ("SOURCE-RECEIPT-" + expected.hex()).encode() in pane["output"].read_bytes(),
                  "source receipt rendered by real mirror", 3)
        visible = time.monotonic_ns()
        pane["received"] = expected
        pane["process"].stdin.write(b"\x1c")  # Ordinary Ctrl+backslash, not a direct API acquire/release.
        pane["process"].stdin.flush()
        released = self.wait(lambda: self.states(pane, "observe", control["state"]["request_id"] + 1), "in-place ordinary release", 3)
        self.assert_stream(pane)
        if released["stream"] != pane["stream"]:
            raise RuntimeError("release replaced stream")
        if [row.get("cumulative_hex") for row in rows(pane["receipt"]) if row["type"] == "input"][-1] != expected.hex():
            raise RuntimeError("input was duplicated or release reached source app")
        return {"sent_mono_ns": sent, "source_receipt_mono_ns": receipt["mono_ns"],
                "source_latency_ms": (receipt["mono_ns"] - sent) / 1e6,
                "consumer_visible_ms": (visible - sent) / 1e6, "input_hex": text.hex(),
                "control": control, "release": released, "ssh": pane["ssh"]}

    def cleanup(self) -> dict:
        errors = []
        try:
            self.discover()
        except (OSError, RuntimeError) as exc:
            errors.append(str(exc))
        # Stop every exact descendant generation before deleting private keys,
        # sockets, configs. No pkill, shared process groups, ports or broad roots.
        cleanup_deadline = time.monotonic() + 20
        for signum, seconds in ((signal.SIGTERM, 3), (signal.SIGKILL, 3)):
            for row in reversed(list(self.ledger.values())):
                if time.monotonic() >= cleanup_deadline:
                    errors.append("20-second exact cleanup deadline exceeded")
                    break
                if not alive(row):
                    continue
                try:
                    if row["uid"] != os.geteuid() and self.privileged:
                        subprocess.run(["sudo", "-n", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", sys.executable,
                                        str(HERE), "signal-owned", "--pid", str(row["pid"]), "--start", row["start"],
                                        "--uid", str(row["uid"]), "--signum", str(signum)],
                                       env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=max(.1, min(3, cleanup_deadline - time.monotonic())), check=True)
                    else:
                        signal_owned(row, signum)
                except (OSError, subprocess.SubprocessError) as exc:
                    errors.append(f"exact process cleanup {row['pid']}: {exc}")
            end = min(cleanup_deadline, time.monotonic() + seconds)
            while time.monotonic() < end and any(alive(row) for row in self.ledger.values()):
                for process in self.processes:
                    process.poll()
                time.sleep(.02)
        remaining = [row for row in self.ledger.values() if alive(row)]
        for process in self.processes:
            if process.poll() is None:
                errors.append(f"launched process remains: {process.pid}")
            if process.stdin:
                process.stdin.close()
        for handle in self.handles:
            handle.close()
        return {"complete": not errors and not remaining, "remaining": remaining,
                "errors": errors, "owned_processes": list(self.ledger.values())}


def smoke(herdr: Path, mirror: Path, output: Path) -> dict:
    herdr, mirror = herdr.resolve(strict=True), mirror.resolve(strict=True)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": 1, "status": "fail", "fixture": "localhost actual managed SSH + raw echo-off sink",
              "consumer": "herdr-mirror --dump grid; ordinary stdin keys", "cycles": [], "errors": []}
    # OpenSSH StrictModes checks authorization-file ancestors up to the account's
    # real passwd home. A private directory under /tmp still fails at /tmp.
    account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    root = Path(tempfile.mkdtemp(prefix=".herdr-pair-", dir=account_home))
    fixture = Fixture(root, herdr, mirror)
    original_handler = signal.getsignal(signal.SIGALRM)
    original_alarm = signal.alarm(0)
    def deadline(_signum, _frame):
        raise TimeoutError("120-second private pair fixture deadline")
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(120)
    try:
        fixture.setup()
        primary, sibling = fixture.pane(0), fixture.pane(1)
        report["sources"] = [{"pane": pane["pane"], "ready": pane["source_ready"]}
                             for pane in (primary, sibling)]
        sibling_before = max(row.get("sequence", 0) for row in rows(sibling["receipt"]))
        last = 0
        for text in (b"a", b"B", b"7"):
            cycle = fixture.input_cycle(primary, text, last)
            report["cycles"].append(cycle)
            last = cycle["release"]["state"]["request_id"]
            fixture.assert_stream(sibling)
        primary_cycles_finished = time.monotonic_ns()
        sibling_cycle = fixture.input_cycle(sibling, b"s", 0)
        fixture.assert_stream(primary)
        heartbeat = fixture.wait(lambda: next((row for row in reversed(rows(sibling["receipt"]))
                                               if row.get("sequence", 0) > sibling_before
                                               and row["mono_ns"] >= primary_cycles_finished), None),
                                 "sibling source heartbeat after primary transitions")
        sibling_after = heartbeat["sequence"]
        fixture.wait(lambda: f"SOURCE-HEARTBEAT-{sibling_after}".encode() in sibling["output"].read_bytes(), "sibling consumer heartbeat")
        report["sibling"] = {"cycle": sibling_cycle, "before": sibling_before, "after": sibling_after,
                             "primary_cycles_finished_mono_ns": primary_cycles_finished,
                             "heartbeat_mono_ns": heartbeat["mono_ns"], "same_ssh_stream": True}
        for pane in (primary, sibling):
            source_bytes = b"".join(bytes.fromhex(row["hex"]) for row in rows(pane["receipt"]) if row["type"] == "input")
            if source_bytes != pane["received"]:
                raise RuntimeError("actual source input bytes differ from exactly-once keys")
        report["behavior_passed"] = True
    except Exception as exc:
        report["errors"].append(f"{type(exc).__name__}: {exc}")
    finally:
        signal.alarm(0)
        if report["errors"]:
            report["diagnostics"] = {path.name: path.read_bytes()[-8192:].decode(errors="replace")
                                     for path in root.glob("*.log")}
        try:
            report["cleanup"] = fixture.cleanup()
        except Exception as exc:
            report["cleanup"] = {"complete": False, "errors": [str(exc)]}
        # Keep failure evidence in report; never retain private keys/home/config.
        if report["cleanup"]["complete"]:
            try:
                shutil.rmtree(root)
                report["cleanup"]["private_root_absent"] = not root.exists()
                report["cleanup"]["complete"] = not root.exists()
            except OSError as exc:
                report["cleanup"].update(complete=False, errors=[str(exc)])
        else:
            report["cleanup"]["retained_private_root"] = str(root)
        signal.signal(signal.SIGALRM, original_handler)
        if original_alarm:
            signal.alarm(original_alarm)
        if report.get("behavior_passed") and report["cleanup"]["complete"] and not report["errors"]:
            report["status"] = "pass"
        output.write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--herdr", type=Path, required=True)
    run.add_argument("--mirror", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    tee = sub.add_parser("relay")
    tee.add_argument("--binary", type=Path, required=True)
    tee.add_argument("--journal-dir", type=Path, required=True)
    tee.add_argument("argv", nargs=argparse.REMAINDER)
    kill = sub.add_parser("signal-owned")
    for name in ("pid", "uid", "signum"):
        kill.add_argument("--" + name, type=int, required=True)
    kill.add_argument("--start", required=True)
    args = parser.parse_args()
    if args.command == "relay":
        argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
        return relay(args.binary, args.journal_dir, argv)
    if args.command == "signal-owned":
        signal_owned({"pid": args.pid, "start": args.start, "uid": args.uid}, args.signum)
        return 0
    return 0 if smoke(args.herdr, args.mirror, args.output)["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
