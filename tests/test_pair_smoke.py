from __future__ import annotations

import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time
import unittest

from maintenance import ci, pair_smoke


class FixturePrimitives(unittest.TestCase):
    def test_journal_reader_rejects_malformed_complete_lines_and_size_overflow(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "journal.jsonl"
            self.assertEqual(pair_smoke.rows(path), [])
            path.write_bytes(b'{"type":"ready"}\n{"partial":')
            self.assertEqual(pair_smoke.rows(path), [{"type": "ready"}])
            path.write_bytes(b'{bad}\n')
            with self.assertRaises(json.JSONDecodeError):
                pair_smoke.rows(path)
            with path.open("wb") as handle:
                handle.truncate(pair_smoke.CAP + 1)
            with self.assertRaisesRegex(RuntimeError, "size bound"):
                pair_smoke.rows(path)

    def test_exact_generation_signal_cannot_kill_unrelated_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            environment = ci.clean_environment(Path(temporary))
            selected = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], env=environment)
            unrelated = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], env=environment)
            try:
                row = pair_smoke.identity(selected.pid)
                stale = {**row, "start": str(int(row["start"]) - 1)}
                pair_smoke.signal_owned(stale, signal.SIGKILL)
                self.assertIsNone(selected.poll())
                pair_smoke.signal_owned(row, signal.SIGTERM)
                selected.wait(timeout=3)
                self.assertIsNone(unrelated.poll())
                self.assertFalse(pair_smoke.alive(row))
            finally:
                for process in (selected, unrelated):
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=3)

    def test_cleanup_is_limited_to_launched_process_descendants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = pair_smoke.Fixture(root, Path(sys.executable), Path(sys.executable))
            unrelated = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], env=fixture.env)
            try:
                launched = fixture.spawn([sys.executable, "-c", "import time;time.sleep(30)"], "owned")
                result = fixture.cleanup()
                self.assertTrue(result["complete"], result)
                self.assertIsNotNone(launched.poll())
                self.assertIsNone(unrelated.poll())
                self.assertNotIn(unrelated.pid, [row["pid"] for row in result["owned_processes"]])
            finally:
                unrelated.kill()
                unrelated.wait(timeout=3)

    def test_authoritative_state_journal_does_not_accept_error_or_wrong_pane(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = pair_smoke.Fixture(root, Path(sys.executable), Path(sys.executable))
            (root / "streams").mkdir()
            start = {"type": "start", "argv": ["terminal", "session", "managed", "w1:p1"]}
            states = [start,
                      {"type": "state", "mono_ns": 1, "state": {"mode": "observe", "request_id": 0}},
                      {"type": "state", "mono_ns": 2, "state": {"mode": "observe", "request_id": 1, "error": "denied"}},
                      {"type": "state", "mono_ns": 3, "state": {"mode": "control", "request_id": 2}}]
            (root / "streams/stream-1.jsonl").write_text("".join(json.dumps(row) + "\n" for row in states))
            self.assertIsNone(fixture.states({"pane": "w1:p2"}, "control", 0))
            self.assertIsNone(fixture.states({"pane": "w1:p1"}, "observe", 1))
            control = fixture.states({"pane": "w1:p1"}, "control", 2, exact=True)
            self.assertEqual(control["mono_ns"], 3)
            self.assertEqual(control["stream"], start)


class RealSourceSink(unittest.TestCase):
    def test_real_pty_echo_off_input_receipt_and_source_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            master, slave = pty.openpty()
            original = termios.tcgetattr(slave)
            receipt = root / "receipts.jsonl"
            sink = Path(__file__).resolve().parents[1] / "fixtures/input_sink.py"
            process = subprocess.Popen([sys.executable, str(sink), "--receipts", str(receipt), "--seconds", "3"],
                                       stdin=slave, stdout=slave, stderr=slave, env=ci.clean_environment(root / "home"))
            observed = bytearray()
            try:
                end = time.monotonic() + 4
                while not any(row["type"] == "ready" for row in pair_smoke.rows(receipt)):
                    if time.monotonic() >= end:
                        self.fail("actual sink did not enter raw mode")
                    if select.select([master], [], [], .05)[0]:
                        observed.extend(os.read(master, 65536))
                attributes = termios.tcgetattr(slave)
                self.assertFalse(attributes[3] & (termios.ECHO | termios.ICANON))
                sent = time.monotonic_ns()
                os.write(master, b"Ab7")
                while not any(row.get("cumulative_hex") == b"Ab7".hex() for row in pair_smoke.rows(receipt)):
                    if time.monotonic() >= end:
                        self.fail("actual source did not confirm input")
                    if select.select([master], [], [], .05)[0]:
                        observed.extend(os.read(master, 65536))
                events = pair_smoke.rows(receipt)
                actual = [row for row in events if row["type"] == "input"]
                self.assertEqual(b"".join(bytes.fromhex(row["hex"]) for row in actual), b"Ab7")
                self.assertGreaterEqual(actual[-1]["mono_ns"], sent)
                while process.poll() is None:
                    if select.select([master], [], [], .05)[0]:
                        observed.extend(os.read(master, 65536))
                    if time.monotonic() >= end:
                        self.fail("actual sink exceeded fixed deadline")
                self.assertEqual(process.returncode, 0, observed.decode(errors="replace"))
                self.assertIn(b"SOURCE-RECEIPT-416237", observed)
                self.assertNotIn(b"Ab7", observed)  # Kernel echo cannot masquerade as source proof.
                self.assertEqual(termios.tcgetattr(slave), original)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
                os.close(master)
                os.close(slave)


@unittest.skipUnless(os.environ.get("HERDR_PAIR_TEST_BINARY") and os.environ.get("HERDR_MIRROR_PAIR_TEST_BINARY"),
                     "explicit real built pair paths required; unit results are not integration proof")
class ActualPairedBinaries(unittest.TestCase):
    def test_actual_private_localhost_managed_pair(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = pair_smoke.smoke(Path(os.environ["HERDR_PAIR_TEST_BINARY"]),
                                      Path(os.environ["HERDR_MIRROR_PAIR_TEST_BINARY"]),
                                      Path(temporary) / "integration.json")
            self.assertEqual(report["status"], "pass", report)
            self.assertTrue(report["cleanup"]["complete"])
            self.assertTrue(report["cleanup"]["private_root_absent"])
            self.assertEqual(len(report["cycles"]), 3)
            self.assertTrue(report["sibling"]["same_ssh_stream"])
            self.assertGreaterEqual(report["sibling"]["heartbeat_mono_ns"],
                                    report["sibling"]["primary_cycles_finished_mono_ns"])
            streams = [cycle["ssh"] for cycle in report["cycles"]]
            self.assertEqual(streams, [streams[0]] * 3)


if __name__ == "__main__":
    unittest.main()
