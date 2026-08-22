"""Phase E (implementation.md Phase 15 / security-spec.md section 15)
deterministic fuzz harness - security-sensitive PARSERS.

Targets (host-side validation and protocol layers, trusted side only):

- ``policy.Policy.from_dict`` / ``load_policy_file``  (S-015/S-021)
- ``config.RuntimeConfig.from_dict``                  (S-021, ADR-007)
- ``isolation.environment.construct_environment``     (S-034)
- ``registry.is_valid_session_id`` / ``load_manifest`` (S-025/S-026)
- ``git.sanitized_git_argv``                          (Phase C argv-only)
- ``mcp.parse_message``                               (S-023 protocol)
- ``audit.recorder.AuditRecorder.record``             (S-024 observational)

Invariants asserted for EVERY mutation (fail-safe contract):

1. No unexpected exception escapes the tested interface - only the
   documented deterministic error type for that seam (or success).
2. No capability amplification: a fuzzed policy can NEVER grant a
   capability the fuzzed input did not explicitly declare ``true``.
   Undeclared capabilities stay absent -> denied by default.
3. No policy-state corruption: an accepted policy is a valid immutable
   ``Policy`` whose capability set is exactly the declared subset.
4. ``network_mode`` can only ever parse to the sole v0.1 value ``deny``
   (network deny-by-construction is frozen - ADR-006).
5. Git argv is DATA: hostile arguments stay single literal argv
   elements; the closed operation set and ``-C`` work-tree pin are
   always present.
6. Audit ``record()`` never raises and every successful write is a
   parseable JSON line (observational - S-024).

Determinism: every mutation comes from ``random.Random(seed)`` with a
fixed iteration budget. Same seed -> identical stream -> identical
result. Stdlib only - zero new dependencies (TCB rule).

Host-side evidence only: these seams run on the trusted host side
before any boundary work. The kernel boundary remains covered by the
native/adversarial suites; this harness never claims kernel evidence.
"""

from __future__ import annotations

import json
import os
import pathlib
import random
import tempfile
import unittest

from agent_sandbox import registry
from agent_sandbox.audit.recorder import AuditRecorder
from agent_sandbox.config import ConfigError, RuntimeConfig
from agent_sandbox.git import GIT_OPERATIONS, sanitized_git_argv
from agent_sandbox.isolation.environment import (
    SANITIZED_ENV,
    construct_environment,
)
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.mcp import parse_message
from agent_sandbox.policy import (
    ALL_CAPABILITIES,
    POLICY_VERSION,
    Policy,
    PolicyError,
    load_policy_file,
)
from tests.fuzz import _fuzzutil

# Fixed seeds / bounded budgets (CI-fast, fully deterministic).
SEED = 0xC0FFEE
ROUNDS = 250

# Resource limits are omitted so the validated defaults apply and no
# policy/config resource conflict can mask a parser result (ADR-007
# consistency check runs on every accepted config).
_BASE_POLICY = {
    "version": POLICY_VERSION,
    "capabilities": {
        "filesystem.read.workspace": True,
        "git.read": True,
    },
}

_BASE_CONFIG = {
    "mode": "restricted",
    "workspace": "/workspace",
    "network_mode": "deny",
    "env_allowlist": ["PATH", "HOME"],
    "policy": _BASE_POLICY,
}

_ATOMIC_INPUTS: list = [
    None, True, False, 0, 1, -1, "", "x", "[]", "{}", [], {},
    ["a"], {"a": 1}, 3.14, "deny", "restricted", 1.0, "true", "false",
]


def _seed() -> random.Random:
    return random.Random(SEED)


def _only(expected: tuple[type[Exception], ...]):
    """Call guard: return ``(value, None)`` on success or ``(None, exc)``
    on an exception that IS one of ``expected``; raise AssertionError for
    any other (unexpected) exception type."""

    def wrap(call):
        try:
            return call(), None
        except expected as e:
            return None, e
        except Exception as e:
            raise AssertionError(
                f"unexpected exception escaped the interface: "
                f"{type(e).__name__}: {e}") from e

    return wrap


class PolicyParserFuzzTests(unittest.TestCase):
    """Policy.from_dict: strict validation, no amplification, no
    unexpected exceptions."""

    def test_from_dict_structural_mutation_fails_safely(self) -> None:
        rng = _seed()
        for _ in range(ROUNDS):
            raw = _fuzzutil.mutate_value(rng, _BASE_POLICY)
            value, err = _only((ConfigError,))(lambda: Policy.from_dict(raw))
            if err is not None:
                continue  # deterministic refusal - correct fail-safe path
            self._assert_valid_no_amplification(raw, value)

    def test_from_dict_atomic_scalar_inputs_fail_safely(self) -> None:
        rng = _seed()
        corpus = _ATOMIC_INPUTS + [json.dumps(_BASE_POLICY)]
        for _ in range(ROUNDS):
            raw = _fuzzutil.mutate_value(
                rng, rng.choice(corpus))
            value, err = _only((ConfigError,))(lambda: Policy.from_dict(raw))
            if err is not None:
                continue
            self._assert_valid_no_amplification(raw, value)

    def test_from_dict_string_json_mutation_fails_safely(self) -> None:
        rng = _seed()
        base = json.dumps(_BASE_POLICY)
        for _ in range(ROUNDS):
            raw = _fuzzutil.mutate_string(rng, base)
            # A string is never a valid policy mapping - must refuse.
            _, err = _only((ConfigError,))(
                lambda: Policy.from_dict(raw))
            self.assertIsNotNone(err, "string policy input must be refused")

    def _assert_valid_no_amplification(self, raw, policy: Policy) -> None:
        self.assertIsInstance(policy, Policy)
        self.assertEqual(policy.version, POLICY_VERSION)
        declared: dict = {}
        if isinstance(raw, dict) and isinstance(raw.get("capabilities"), dict):
            declared = raw["capabilities"]
        for name, enabled in policy.capabilities.items():
            self.assertIn(name, ALL_CAPABILITIES)
            self.assertIs(enabled, True)
            self.assertIs(
                declared.get(name), True,
                "capability granted without an explicit true declaration - "
                "amplification")
        for name, value in declared.items():
            if value is True:
                self.assertTrue(
                    policy.capabilities.get(name, False),
                    f"explicitly declared true capability {name!r} lost")
        if isinstance(raw, dict) and "resources" in raw:
            res = raw["resources"]
            if isinstance(res, dict):
                for key, v in res.items():
                    if v is True or not isinstance(v, int) or v < 1:
                        self.assertIsNone(
                            policy.resources,
                            f"invalid resources {key!r} accepted")

    def test_load_policy_file_fuzzed_bytes_fail_safely(self) -> None:
        rng = _seed()
        valid = json.dumps(_BASE_POLICY).encode("utf-8")
        corpus = [valid, b"", b"{", b"[]", b"null",
                  b"\x00\xff\xfe", b"{} trailing", b'"x"']
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "policy.json")
            for _ in range(ROUNDS):
                data = _fuzzutil.mutate_bytes(rng, rng.choice(corpus))
                with open(path, "wb") as f:
                    f.write(data)
                value, err = _only((PolicyError, OSError))(
                    lambda: load_policy_file(path))
                if value is not None:
                    self._assert_valid_no_amplification(
                        json.loads(data.decode("utf-8", "replace")), value)


class ConfigParserFuzzTests(unittest.TestCase):
    """RuntimeConfig.from_dict: fail-safe parsing; the sole v0.1 network
    mode is ``deny`` - fuzzing can never open networking."""

    def test_from_dict_structural_mutation_fails_safely(self) -> None:
        rng = _seed()
        for _ in range(ROUNDS):
            raw = _fuzzutil.mutate_value(rng, _BASE_CONFIG)
            value, err = _only((ConfigError,))(lambda: RuntimeConfig.from_dict(raw))
            if err is not None:
                continue
            self.assertIsInstance(value, RuntimeConfig)
            self.assertEqual(value.network_mode, "deny",
                             "fuzzed config must never enable networking "
                             "(ADR-006)")

    def test_from_dict_atomic_scalar_inputs_fail_safely(self) -> None:
        rng = _seed()
        for _ in range(ROUNDS):
            raw = _fuzzutil.mutate_value(rng, rng.choice(_ATOMIC_INPUTS))
            value, err = _only((ConfigError,))(lambda: RuntimeConfig.from_dict(raw))
            if err is not None:
                continue
            self.assertIsInstance(value, RuntimeConfig)
            self.assertEqual(value.network_mode, "deny")


class EnvironmentParserFuzzTests(unittest.TestCase):
    """construct_environment: only the approved six-variable surface can
    ever be constructed; anything else refuses (S-034)."""

    def test_fuzzed_allowlist_never_escapes_approved_surface(self) -> None:
        rng = _seed()
        base = ["PATH", "HOME", "LANG"]
        for _ in range(ROUNDS):
            raw = _fuzzutil.mutate_value(rng, list(base))
            # The documented contract: ``allowlist`` is the config-validated
            # tuple of strings (``_parse_env_allowlist``). Mutations that
            # introduce non-string entries are outside that contract (they
            # can never reach this seam in production - config rejects them
            # first); only string-typed allowlists exercise the seam.
            if not isinstance(raw, list) or \
                    not all(isinstance(n, str) for n in raw):
                continue
            env, err = _only((NamespaceSetupError,))(
                lambda: construct_environment(tuple(raw)))
            if err is not None:
                continue
            for name, value in env.items():
                self.assertIn(name, SANITIZED_ENV)
                self.assertEqual(value, SANITIZED_ENV[name],
                                 "constructed value must be the approved "
                                 "value - never host data")


class RegistryParserFuzzTests(unittest.TestCase):
    """is_valid_session_id / load_manifest: malformed ids and manifests
    fail closed with the documented error - never unexpected exceptions,
    never a mismatch against the stored identity (S-025/S-026)."""

    def test_is_valid_session_id_never_raises(self) -> None:
        rng = _seed()
        corpus = ["a" * 32, "", "x" * 31, "x" * 33, "g" * 32, "0" * 32,
                  None, 123, 1.5, [], {}]
        for _ in range(ROUNDS):
            value = _fuzzutil.mutate_value(rng, rng.choice(corpus))
            with self.subTest(value=repr(value)):
                # Pure predicate: must NEVER raise, whatever the input.
                result, err = _only(())(
                    lambda: registry.is_valid_session_id(value))
                self.assertIsNone(err)
                self.assertIsInstance(result, bool)

    def test_load_manifest_fuzzed_manifest_bytes_fail_safely(self) -> None:
        rng = _seed()
        sid = "c" * 32
        config = RuntimeConfig.from_dict(_BASE_CONFIG)
        with tempfile.TemporaryDirectory() as td:
            base = td
            registry.save_session(base, sid, config,
                                  created="2026-08-22T00:00:00+00:00")
            path = registry.manifest_path(base, sid)
            valid = pathlib.Path(path).read_bytes()
            corpus = [valid, b"", b"{", b"[]", b"null", b"\xff\xfe\x00",
                      b'{"schema": 1}', b'{"session_id": "' + sid.encode() + b'"}']
            for _ in range(ROUNDS):
                data = _fuzzutil.mutate_bytes(rng, rng.choice(corpus))
                pathlib.Path(path).write_bytes(data)
                manifest, err = _only((registry.RegistryError, ValueError))(
                    lambda: registry.load_manifest(base, sid))
                if err is not None:
                    continue
                if manifest is None:
                    continue
                self.assertIsInstance(manifest, dict)
                self.assertEqual(manifest["session_id"], sid)
                self.assertEqual(manifest["schema"], registry.SCHEMA)

    def test_load_manifest_fuzzed_ids_fail_safely(self) -> None:
        rng = _seed()
        with tempfile.TemporaryDirectory() as td:
            for _ in range(ROUNDS):
                value = _fuzzutil.mutate_value(rng, rng.choice(
                    ["a" * 32, "", "x" * 40, None, 7, 2.5, ["a"], {}]))
                manifest, err = _only((registry.RegistryError, ValueError))(
                    lambda: registry.load_manifest(td, value))
                if err is not None:
                    self.assertIsInstance(err, registry.RegistryError)
                    continue
                self.assertIsNone(manifest)


class GitArgvFuzzTests(unittest.TestCase):
    """sanitized_git_argv: the operation set is closed; arguments are
    data - hostile strings stay single literal argv elements and can
    never split into shell words (Phase C containment)."""

    def test_fuzzed_operation_fails_safely(self) -> None:
        rng = _seed()
        corpus = ["status", "diff", "base", "current", "", "rm -rf /",
                  "status;x", "--help", "clone", "fetch", "pull"]
        for _ in range(ROUNDS):
            op = _fuzzutil.mutate_string(rng, rng.choice(corpus))
            argv, err = _only((ValueError,))(
                lambda: sanitized_git_argv(op))
            if err is not None:
                self.assertNotIn(op, GIT_OPERATIONS)
                continue
            self.assertIn(op, GIT_OPERATIONS)
            self.assertEqual(argv[0], "git")
            self.assertIn("-C", argv)

    def test_fuzzed_args_stay_single_argv_elements(self) -> None:
        rng = _seed()
        hostile = ["; rm -rf /", "$(touch /tmp/pwn)", "`id`", "| cat /etc/passwd",
                   "&& x", "--output=/etc/passwd", "..", "../..", "/workspace/../..",
                   "a\nb", "a\x00b", "-c", "core.hooksPath=/x", "--upload-pack=x"]
        for _ in range(ROUNDS):
            args = [_fuzzutil.mutate_string(rng, rng.choice(hostile))
                    for _ in range(rng.randint(0, 3))]
            argv = sanitized_git_argv("status", args)
            # every supplied argument appears VERBATIM as one element;
            # if any hostile token had been shell-split, the full token
            # would be absent and its fragments present instead
            for arg in args:
                self.assertIn(arg, argv,
                              "caller argument must be appended verbatim")
            self.assertIn("/workspace", argv)  # work-tree pin present


class McpParserFuzzTests(unittest.TestCase):
    """parse_message: malformed frames always yield a deterministic
    (request, error) pair - never an exception, never a request with a
    non-string method or non-dict params (S-023)."""

    def test_fuzzed_lines_fail_safely(self) -> None:
        rng = _seed()
        corpus = [
            '{"jsonrpc": "2.0", "method": "initialize", "id": 1}',
            '{"method": "ping", "params": {}}',
            '{"id": 1, "method": "x", "params": {"a": 1}}',
            "{}", "[]", "null", '"str"', "not json at all",
            '{"method": 3, "id": "a"}', '{"params": []}',
            "", " ", "\x00", "{", "}\n{",
        ]
        for _ in range(ROUNDS):
            line = _fuzzutil.mutate_string(rng, rng.choice(corpus))
            request, error = parse_message(line)
            self.assertTrue((request is None) ^ (error is None),
                            "exactly one of request/error must be set")
            if request is not None:
                self.assertIsInstance(request["method"], str)
                self.assertTrue(request["method"])
                self.assertIsInstance(request.get("params"), dict)
            else:
                self.assertIn(error.get("error", {}).get("code"),
                              (-32700, -32600, -32602))
                # id, when present, must be a scalar - never a dict/list
                rid = error.get("id")
                self.assertTrue(rid is None or isinstance(rid, (str, int, float)))


class AuditRecorderFuzzTests(unittest.TestCase):
    """AuditRecorder.record: observational (S-024) - fuzzed events never
    raise and every successful write stays parseable JSONL."""

    def test_fuzzed_events_never_raise_and_stay_valid_jsonl(self) -> None:
        rng = _seed()
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "audit.jsonl")
            rec = AuditRecorder(path)
            corpus = ["a", "", "x" * 200, "session_created", "init_decision",
                      "{}", "s\u0000id", "\u4e2d\u6587", "x\n" * 4]
            for _ in range(ROUNDS):
                sid = _fuzzutil.mutate_string(rng, rng.choice(corpus))
                event = _fuzzutil.mutate_string(rng, rng.choice(corpus))
                fields = _fuzzutil.mutate_value(
                    rng, {"reason": "x", "stage": "seccomp", "code": 5})
                ok, err = _only((OSError,))(
                    lambda: rec.record(str(sid), str(event), **fields))
                self.assertIsNone(err, "record() must never raise")
                self.assertIsInstance(ok, bool)
            # every line written must parse as JSON (the read-back contract)
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parsed = json.loads(line)
                    self.assertIsInstance(parsed, dict)
                    self.assertIn("session_id", parsed)
                    self.assertIn("event", parsed)


if __name__ == "__main__":
    unittest.main()
