"""Phase E (implementation.md Phase 15 / security-spec.md section 15)
deterministic fuzz harness - INTERFACES.

Targets (host-side, trusted side only):

- CLI argv vectors (``cli.main``) for the session commands - fuzzed
  against an EMPTY state dir, so every frame reaches only the
  fail-closed argument/registry paths. ``create``/``run`` are EXCLUDED
  by design: they reach the real initialization boundary, which is
  exercised by the dedicated integration suites with explicit mocks -
  fuzzing must never drive the real SecurityInitializer.

- Audit read-back (``cli._cmd_logs``) - fuzzed on-disk JSONL bytes are
  parsed observationally (S-024: malformed audit lines are skipped,
  never an execution blocker and never a crash).

Invariants asserted for every mutation:

1. ``cli.main`` returns a deterministic int exit code and NEVER raises
   for any fuzzed argv on the safe command set.
2. No session-state mutation: fuzzed argv against an empty state dir
   creates/destroys NOTHING - the dir stays empty (fail closed).
3. Malformed audit data never raises out of ``_cmd_logs``.
4. Harness hygiene: the mutation stream is deterministic (same seed ->
   same stream) and bounded (exactly the budgeted rounds).

Stdlib only - zero new dependencies (TCB rule). Host-side evidence
only; never claims kernel-boundary evidence.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import random
import tempfile
import unittest

from agent_sandbox import cli as cli_mod
from agent_sandbox import registry
from agent_sandbox.config import RuntimeConfig

from tests.fuzz import _fuzzutil

SEED = 0xC0FFEE
ROUNDS = 200

# The safe fuzz surface: commands whose first action is a fail-closed
# argument parse + registry lookup. ``create``/``run`` are excluded -
# they reach the real initialization boundary (dedicated integration
# tests cover those paths with explicit mocks).
SAFE_COMMANDS = ("exec", "status", "diff", "logs", "destroy", "git")

_TOKEN_CORPUS = [
    "a" * 32, "0" * 32, "g" * 32, "", "x", "--json", "--workspace",
    "--mode", "restricted", "hardened", "deny", "--policy", "/tmp/p.json",
    "/workspace", "..", "../..", "/etc/passwd", "; rm -rf /", "&&", "|",
    "--", "-c", "x" * 500, "cmd", "python3", "-m", "pip", "install",
    "--no-index", "socketserver", "\x00", "a\x00b", "--help", "--version",
    "status", "destroy", "create", "logs",
]


class CliArgvFuzzTests(unittest.TestCase):
    """Fuzzed CLI argv against an empty state dir: every frame takes a
    fail-closed path - int exit code, never raises, never creates or
    destroys state."""

    def _run(self, argv, state_dir):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), \
             contextlib.redirect_stderr(err):
            return cli_mod.main(argv, state_dir=state_dir)

    def test_fuzzed_argv_fails_safely_and_never_mutates_state(self) -> None:
        rng = random.Random(SEED)
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "state")
            os.makedirs(base)
            for _ in range(ROUNDS):
                cmd = rng.choice(SAFE_COMMANDS)
                rest = [_fuzzutil.mutate_string(rng, rng.choice(_TOKEN_CORPUS))
                        for _ in range(rng.randint(0, 5))]
                argv = [cmd] + rest
                code = self._run(argv, base)
                # Deterministic documented exit-code surface
                # (0 success, 1 error, 2 usage, 3 init refused,
                #  4 exec refused, 5 session error, 6 destroy
                #  incomplete). A code outside it means an unexpected
                # control-flow path.
                self.assertIsInstance(code, int)
                self.assertIn(code, (0, 1, 2, 3, 4, 5, 6))
            # fail-closed invariant: fuzzed argv can never create or
            # destroy session state - the dir must still be empty
            self.assertEqual(os.listdir(base), [])

    def test_fuzzed_flags_with_json_mode_never_raises(self) -> None:
        rng = random.Random(SEED + 1)
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "state")
            os.makedirs(base)
            for _ in range(ROUNDS):
                cmd = rng.choice(SAFE_COMMANDS)
                rest = ["--json"]
                for _ in range(rng.randint(0, 4)):
                    rest.append(_fuzzutil.mutate_string(
                        rng, rng.choice(_TOKEN_CORPUS)))
                code = self._run([cmd] + rest, base)
                self.assertIsInstance(code, int)
            self.assertEqual(os.listdir(base), [])


class AuditReadBackFuzzTests(unittest.TestCase):
    """Fuzzed on-disk audit JSONL: parsed observationally by ``logs``
    (S-024) - never raises, never becomes an execution blocker."""

    def test_fuzzed_audit_bytes_never_raise(self) -> None:
        rng = random.Random(SEED + 2)
        sid = "d" * 32
        config = RuntimeConfig.from_dict({
            "mode": "restricted",
            "workspace": "/workspace",
            "resources": {
                "cpu_seconds": 10,
                "memory_mb": 256,
                "disk_mb": 64,
                "processes": 8,
                "open_files": 32,
                "output_mb": 8,
                "wall_time_seconds": 60,
            },
        })
        corpus = [
            json.dumps({"session_id": sid, "event": "init_decision"}).encode(),
            b"", b"{", b"[]", b"null", b"\xff\xfe\x00",
            b'{"session_id": "wrong", "event": "x"}',
            b"garbage line\nnot json",
        ]
        with tempfile.TemporaryDirectory() as td:
            base = td
            registry.save_session(base, sid, config,
                                  created="2026-08-22T00:00:00+00:00")
            audit_path = registry.session_audit_path(base, sid)
            out, err = io.StringIO(), io.StringIO()
            for _ in range(ROUNDS):
                data = _fuzzutil.mutate_bytes(rng, rng.choice(corpus))
                pathlib.Path(audit_path).write_bytes(data)
                with contextlib.redirect_stdout(out), \
                     contextlib.redirect_stderr(err):
                    code = cli_mod._cmd_logs([sid, "--json"], base)
                self.assertIsInstance(code, int)


class HarnessHygieneTests(unittest.TestCase):
    """The fuzz harness itself is deterministic and bounded - a broken
    harness cannot mask a real failure."""

    def test_same_seed_produces_identical_stream(self) -> None:
        corpus = ["a" * 32, "x", "", "--json", "/workspace"]
        a = list(_fuzzutil.fuzz_stream(random.Random(SEED), corpus, 50,
                                       _fuzzutil.mutate_string))
        b = list(_fuzzutil.fuzz_stream(random.Random(SEED), corpus, 50,
                                       _fuzzutil.mutate_string))
        self.assertEqual(a, b)

    def test_stream_is_exactly_bounded(self) -> None:
        stream = list(_fuzzutil.fuzz_stream(
            random.Random(SEED), ["x"], 10, _fuzzutil.mutate_string))
        self.assertEqual(len(stream), 10)

    def test_mutators_never_raise_on_corpus(self) -> None:
        rng = random.Random(SEED)
        for s in _TOKEN_CORPUS:
            for _ in range(20):
                _fuzzutil.mutate_string(rng, s)
                _fuzzutil.mutate_bytes(rng, s.encode("utf-8", "replace"))
                _fuzzutil.mutate_value(rng, {"k": s, "n": 1, "l": [s]})

    def test_corrupted_corpus_fails_the_harness_not_the_target(self) -> None:
        # A corpus item that is not a string must be caught by the
        # harness contract (mutation helpers require strings) - the
        # harness fails loudly, it never silently passes.
        with self.assertRaises((AttributeError, TypeError)):
            list(_fuzzutil.fuzz_stream(
                random.Random(SEED), [123], 5, _fuzzutil.mutate_string))


if __name__ == "__main__":
    unittest.main()
