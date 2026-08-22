"""Phase 4 policy engine tests (ADR-010, ARCHITECTURE section 12,
SECURITY_SPEC S-015/S-021/S-025/S-026/S-027).

Categories (kept separate per the charter):

1. VALIDATION (S-021) - the strict schema: version, unknown fields,
   unknown capabilities, malformed values, resource declarations. A
   malformed/ambiguous policy is REJECTED with a deterministic message
   naming the field - never warn-and-continue.
2. DECISION (S-015) - deny-by-default, explicit allow, the single
   decide()/require() path shared by every operation.
3. IMMUTABILITY (S-025/S-026) - a Policy is frozen after validation and
   never mounted into the sandbox (rootfs tree contains no policy).
4. SESSION GATE - RuntimeSession.execute() consults the policy BEFORE any
   boundary work: a denied capability refuses execution with a
   deterministic reason and a policy_decision audit event; an allowed
   policy proceeds.
5. INTERFACE WIRING - SessionManager.initialize accepts a policy dict
   (MCP/API inherit); the CLI --policy flag loads + validates a policy
   file and refuses (exit 2) on a malformed document.

Trust boundary: policy parsing/validation is host-side TCB code; the
workload never executes it and the policy is never mounted into the
sandbox (S-026 tested in the rootfs-absence category).
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
import unittest.mock

from agent_sandbox import cli as cli_mod
from agent_sandbox import config as config_mod
from agent_sandbox.config import RuntimeConfig
from agent_sandbox.interface import InterfaceParamError, SessionManager
from agent_sandbox.models import ExecutionRefused, ExecutionRequest
from agent_sandbox.policy import (
    ALL_CAPABILITIES,
    DEFAULT_CAPABILITIES,
    POLICY_RESOURCE_KEYS,
    Policy,
    PolicyDecision,
    PolicyError,
    load_policy_file,
)
from agent_sandbox.runtime import session as session_mod
from agent_sandbox.runtime.session import RuntimeSession, SessionState
from agent_sandbox.security import init as init_mod


def valid_config(workspace: str, mode: str = "restricted") -> dict:
    """Mirror of tests/unit/test_resources.py::valid_config."""
    return {
        "mode": mode,
        "workspace": workspace,
        "resources": {
            "cpu_seconds": 300, "memory_mb": 4096, "disk_mb": 10240,
            "processes": 256, "open_files": 4096, "output_mb": 50,
            "wall_time_seconds": 900,
        },
    }


def _policy_doc(**overrides) -> dict:
    doc = {"version": 1, "capabilities": dict(DEFAULT_CAPABILITIES)}
    doc.update(overrides)
    return doc


# ---------------------------------------------------------------------------
# 1. VALIDATION - strict schema (S-021)
# ---------------------------------------------------------------------------

class PolicyValidationTests(unittest.TestCase):
    def test_valid_policy_parses(self) -> None:
        policy = Policy.from_dict(_policy_doc())
        self.assertEqual(policy.version, 1)
        self.assertTrue(policy.capabilities["process.spawn"])
        self.assertFalse(policy.capabilities["git.push"])

    def test_default_policy_is_deny_by_default_except_documented_surface(
            self) -> None:
        policy = Policy.default()
        self.assertEqual(policy.version, 1)
        # The documented v0.1 surface.
        for cap in ("filesystem.read.workspace", "filesystem.write.workspace",
                    "process.spawn", "git.read", "git.commit"):
            self.assertTrue(policy.capabilities.get(cap, False), cap)
        # Deny by default.
        for cap in ("git.push", "network.connect", "secrets.read",
                    "privileged.exec"):
            self.assertFalse(policy.capabilities.get(cap, False), cap)

    def test_missing_version_rejected(self) -> None:
        doc = _policy_doc()
        del doc["version"]
        with self.assertRaises(PolicyError) as cm:
            Policy.from_dict(doc)
        self.assertIn("version", str(cm.exception))

    def test_unsupported_version_rejected(self) -> None:
        with self.assertRaises(PolicyError) as cm:
            Policy.from_dict(_policy_doc(version=2))
        self.assertIn("version", str(cm.exception))

    def test_unknown_top_level_field_rejected(self) -> None:
        with self.assertRaises(PolicyError) as cm:
            Policy.from_dict(_policy_doc(exec_allowlist=[1, 2]))
        self.assertIn("exec_allowlist", str(cm.exception))
        self.assertIn("unknown field", str(cm.exception))

    def test_unknown_capability_rejected(self) -> None:
        # S-021: an unknown security-critical capability must not silently
        # change behavior - reject the document.
        doc = _policy_doc()
        doc["capabilities"]["filesystem.read.host_root"] = True
        with self.assertRaises(PolicyError) as cm:
            Policy.from_dict(doc)
        self.assertIn("filesystem.read.host_root", str(cm.exception))
        self.assertIn("unknown capability", str(cm.exception))

    def test_non_bool_capability_value_rejected(self) -> None:
        doc = _policy_doc()
        doc["capabilities"]["process.spawn"] = "maybe"
        with self.assertRaises(PolicyError) as cm:
            Policy.from_dict(doc)
        self.assertIn("process.spawn", str(cm.exception))

    def test_capabilities_not_mapping_rejected(self) -> None:
        with self.assertRaises(PolicyError):
            Policy.from_dict(_policy_doc(capabilities=[1, 2]))

    def test_policy_not_mapping_rejected(self) -> None:
        with self.assertRaises(PolicyError) as cm:
            Policy.from_dict(["not", "a", "dict"])
        self.assertIn("mapping", str(cm.exception))

    def test_resources_unknown_key_rejected(self) -> None:
        doc = _policy_doc(resources={"memory_mb": 4096, "bananas": 10})
        with self.assertRaises(PolicyError) as cm:
            Policy.from_dict(doc)
        self.assertIn("bananas", str(cm.exception))

    def test_resources_non_int_rejected(self) -> None:
        doc = _policy_doc(resources={"memory_mb": "4096"})
        with self.assertRaises(PolicyError):
            Policy.from_dict(doc)

    def test_resources_zero_rejected(self) -> None:
        doc = _policy_doc(resources={"memory_mb": 0})
        with self.assertRaises(PolicyError):
            Policy.from_dict(doc)

    def test_every_declared_capability_is_known(self) -> None:
        # The vocabulary used by the runtime must be exactly the validated
        # set - a typo'd capability consulted at runtime would silently
        # deny (safe) or an undeclared one would be unvalidated (unsafe).
        for cap in DEFAULT_CAPABILITIES:
            self.assertIn(cap, ALL_CAPABILITIES)

    def test_config_policy_resources_conflict_rejected(self) -> None:
        # S-027/S-021: a policy declaring a limit that conflicts with the
        # config's limits is REJECTED - never a silent second source.
        src = tempfile.mkdtemp(prefix="as-policy-cfg-")
        self.addCleanup(shutil.rmtree, src, True)
        data = valid_config(src)
        data["policy"] = _policy_doc(resources={"memory_mb": 999999})
        with self.assertRaises(config_mod.ConfigError) as cm:
            RuntimeConfig.from_dict(data)
        self.assertIn("memory_mb", str(cm.exception))
        self.assertIn("conflicts", str(cm.exception))

    def test_config_policy_resources_consistent_accepted(self) -> None:
        src = tempfile.mkdtemp(prefix="as-policy-cfg-")
        self.addCleanup(shutil.rmtree, src, True)
        data = valid_config(src)
        data["policy"] = _policy_doc(resources={"memory_mb": 4096})
        cfg = RuntimeConfig.from_dict(data)
        self.assertEqual(cfg.policy.resources["memory_mb"], 4096)
        self.assertEqual(cfg.resources.memory_mb, 4096)


# ---------------------------------------------------------------------------
# 2. DECISION - deny by default, explicit allow, single path (S-015)
# ---------------------------------------------------------------------------

class PolicyDecisionTests(unittest.TestCase):
    def test_absent_capability_denied_by_default(self) -> None:
        policy = Policy.default()
        decision = policy.decide("process.spawn")
        self.assertTrue(decision.allowed)
        # A capability not declared anywhere is denied by default.
        decision = policy.decide("secrets.read")
        self.assertFalse(decision.allowed)

    def test_unknown_capability_denied(self) -> None:
        decision = Policy.default().decide("totally.made.up")
        self.assertFalse(decision.allowed)
        self.assertIn("unknown capability", decision.reason)

    def test_explicit_deny_wins(self) -> None:
        doc = _policy_doc()
        doc["capabilities"]["process.spawn"] = False
        policy = Policy.from_dict(doc)
        decision = policy.decide("process.spawn")
        self.assertFalse(decision.allowed)
        self.assertIn("denied", decision.reason)

    def test_require_first_denial_wins(self) -> None:
        doc = _policy_doc()
        doc["capabilities"]["filesystem.write.workspace"] = False
        policy = Policy.from_dict(doc)
        decision = policy.require("filesystem.read.workspace",
                                  "filesystem.write.workspace",
                                  "process.spawn")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.capability, "filesystem.write.workspace")

    def test_require_all_allowed(self) -> None:
        decision = Policy.default().require(
            "filesystem.read.workspace", "process.spawn")
        self.assertTrue(decision.allowed)

    def test_decision_is_deterministic(self) -> None:
        policy = Policy.default()
        a = policy.decide("process.spawn")
        b = policy.decide("process.spawn")
        self.assertEqual((a.allowed, a.reason), (b.allowed, b.reason))

    def test_decision_describe_machine_readable(self) -> None:
        denied = PolicyDecision(capability="git.push", allowed=False,
                                reason="denied by default")
        self.assertIn("DENIED", denied.describe())
        self.assertIn("git.push", denied.describe())


# ---------------------------------------------------------------------------
# 3. IMMUTABILITY (S-025/S-026)
# ---------------------------------------------------------------------------

class PolicyImmutabilityTests(unittest.TestCase):
    def test_policy_is_frozen(self) -> None:
        policy = Policy.from_dict(_policy_doc())
        with self.assertRaises(Exception):
            policy.version = 2  # type: ignore[misc]
        # The capabilities mapping is a read-only proxy.
        with self.assertRaises(TypeError):
            policy.capabilities["process.spawn"] = False  # type: ignore[index]

    def test_to_dict_does_not_expose_host_paths(self) -> None:
        # S-040: the observable configuration is the capability map only -
        # never workspace paths or other host data.
        view = Policy.default().to_dict()
        self.assertEqual(set(view), {"version", "capabilities"})
        self.assertEqual(view["capabilities"], dict(DEFAULT_CAPABILITIES))

    def test_policy_never_enters_rootfs(self) -> None:
        # S-026: the policy is host-side configuration; build_rootfs copies
        # only the workspace - no policy content may appear in the rootfs
        # tree. Exercised through the real production rootfs builder.
        src = tempfile.mkdtemp(prefix="as-policy-rootfs-")
        self.addCleanup(shutil.rmtree, src, True)
        (pathlib.Path(src) / "file.txt").write_text("workspace content\n")
        from agent_sandbox.isolation import rootfs as rootfs_mod
        state = rootfs_mod.build_rootfs(src)
        self.addCleanup(shutil.rmtree, state.layout.dir, True)
        for root, _dirs, files in os.walk(state.layout.dir):
            for name in files:
                with open(os.path.join(root, name), "rb") as f:
                    self.assertNotIn(b"process.spawn", f.read())
                    self.assertNotIn(b"capabilities", f.read())


# ---------------------------------------------------------------------------
# 4. SESSION GATE - RuntimeSession.execute() consults the policy
# ---------------------------------------------------------------------------

class SessionPolicyGateTests(unittest.TestCase):
    """The policy decision is enforced in RuntimeSession.execute() - the
    single entry point shared by CLI/MCP/API (ADR-013) - BEFORE any
    boundary work. The initialization is stubbed to READY via the
    documented stage-probe seams so the wiring is deterministic; the real
    boundary path is exercised in the mechanism suites. Never a mock that
    makes the policy decision succeed - the REAL Policy decides here."""

    STAGE_SEAMS = (
        ("_probe_impl",),
        ("_filesystem_probe_impl",),
        ("_network_probe_impl",),
        ("_privileges_probe_impl",),
        ("_seccomp_probe_impl",),
        ("_resources_probe_impl",),
        ("_environment_probe_impl",),
        ("_execution_probe_impl",),
    )

    def setUp(self) -> None:
        self._src = tempfile.mkdtemp(prefix="as-policy-ses-")
        self.addCleanup(shutil.rmtree, self._src, True)
        self._patches = [
            unittest.mock.patch.object(init_mod, "_is_linux",
                                       return_value=True),
            unittest.mock.patch.object(session_mod, "_can_fork",
                                       return_value=True),
        ]
        from agent_sandbox.isolation import setup as setup_mod
        for (seam,) in self.STAGE_SEAMS:
            from agent_sandbox.models import StageCheck
            self._patches.append(unittest.mock.patch.object(
                setup_mod, seam,
                return_value=StageCheck(ok=True, reason=f"{seam} ok (test)")))
        for p in self._patches:
            p.start()
        self.addCleanup(self._stop)

    def _stop(self) -> None:
        for p in reversed(self._patches):
            p.stop()

    def _ready_session(self, policy_doc: dict | None = None) -> RuntimeSession:
        data = valid_config(self._src)
        if policy_doc is not None:
            data["policy"] = policy_doc
        cfg = RuntimeConfig.from_dict(data)
        session = RuntimeSession(cfg)
        result = session.initialize()
        self.assertTrue(result.ok, result.describe())
        self.assertIs(session.state, SessionState.READY)
        return session

    def test_default_policy_allows_execution_request(self) -> None:
        # Control row: the documented default policy allows the v0.1
        # execution surface - the request proceeds past the gate.
        session = self._ready_session()
        # We only assert the gate lets it through: the request then hits
        # the (stubbed) mechanism path - reaching the boundary call is
        # exercised by the mechanism suites. Here we verify the policy
        # decision itself is allowed.
        decision = session.config.policy.require(
            "filesystem.read.workspace", "filesystem.write.workspace",
            "process.spawn")
        self.assertTrue(decision.allowed)

    def test_policy_denying_process_spawn_refuses_execution(self) -> None:
        # S-015: a request whose required capability is denied is refused
        # with a deterministic reason - the workload never runs.
        doc = _policy_doc()
        doc["capabilities"]["process.spawn"] = False
        session = self._ready_session(doc)
        outcome = session.execute(ExecutionRequest(command=("echo", "x")))
        self.assertIsInstance(outcome, ExecutionRefused)
        self.assertIn("blocked by policy", outcome.reason)
        self.assertIn("process.spawn", outcome.reason)
        self.assertIn("DENIED", outcome.reason)

    def test_policy_denying_workspace_read_refuses_execution(self) -> None:
        doc = _policy_doc()
        doc["capabilities"]["filesystem.read.workspace"] = False
        session = self._ready_session(doc)
        outcome = session.execute(ExecutionRequest(command=("echo", "x")))
        self.assertIsInstance(outcome, ExecutionRefused)
        self.assertIn("filesystem.read.workspace", outcome.reason)

    def test_policy_decision_recorded_in_audit(self) -> None:
        # S-022/S-023: the policy decision is a structured, session-
        # correlated audit event (observational, never enforcement).
        import json as _json
        from agent_sandbox.audit.recorder import AuditRecorder
        tmp = tempfile.mkdtemp(prefix="as-policy-audit-")
        self.addCleanup(shutil.rmtree, tmp, True)
        recorder = AuditRecorder(os.path.join(tmp, "audit.jsonl"))
        doc = _policy_doc()
        doc["capabilities"]["process.spawn"] = False
        data = valid_config(self._src)
        data["policy"] = doc
        session = RuntimeSession(RuntimeConfig.from_dict(data),
                                 audit=recorder)
        result = session.initialize()
        self.assertTrue(result.ok, result.describe())
        session.execute(ExecutionRequest(command=("echo", "x")))
        with open(recorder.path, encoding="utf-8") as f:
            lines = [_json.loads(l) for l in f.read().splitlines()
                     if l.strip()]
        events = [e["event"] for e in lines]
        self.assertIn("policy_loaded", events)
        self.assertIn("policy_decision", events)
        for e in lines:
            self.assertEqual(e["session_id"], session.session_id)
        decision = next(e for e in lines if e["event"] == "policy_decision")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["capability"], "process.spawn")


# ---------------------------------------------------------------------------
# 5. INTERFACE WIRING - SessionManager + CLI
# ---------------------------------------------------------------------------

class PolicyInterfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._src = tempfile.mkdtemp(prefix="as-policy-iface-")
        self.addCleanup(shutil.rmtree, self._src, True)

    def test_manager_initialize_accepts_policy(self) -> None:
        # The interface wiring: a validated policy dict is accepted and
        # reaches the session config. The initializer is stubbed to READY
        # (mirroring the CLI/MCP/API suites' _OK_INIT) so the wiring is
        # deterministic on every host; the real init is exercised by the
        # mechanism suites.
        from agent_sandbox.models import InitResult, SecurityMode
        from agent_sandbox.security.init import SecurityInitializer
        manager = SessionManager()
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize",
                return_value=InitResult(ok=True, mode=SecurityMode.RESTRICTED,
                                        stage=None)):
            payload = manager.initialize({
                "workspace": self._src,
                "mode": "restricted",
                "policy": _policy_doc(),
            })
        self.assertIn("session_id", payload)
        self.assertEqual(payload["mode"], "restricted")
        self.assertEqual(payload["refused"], False)

    def test_manager_initialize_rejects_malformed_policy(self) -> None:
        manager = SessionManager()
        bad = _policy_doc()
        bad["version"] = 99
        with self.assertRaises(InterfaceParamError) as cm:
            manager.initialize({
                "workspace": self._src,
                "mode": "restricted",
                "policy": bad,
            })
        self.assertIn("version", str(cm.exception))

    def test_manager_initialize_rejects_non_dict_policy(self) -> None:
        manager = SessionManager()
        with self.assertRaises(InterfaceParamError) as cm:
            manager.initialize({
                "workspace": self._src,
                "mode": "restricted",
                "policy": ["not", "a", "dict"],
            })
        self.assertIn("policy", str(cm.exception))

    def test_cli_loads_policy_file_and_uses_it(self) -> None:
        tmp = tempfile.mkdtemp(prefix="as-policy-cli-")
        self.addCleanup(shutil.rmtree, tmp, True)
        policy_path = os.path.join(tmp, "policy.json")
        with open(policy_path, "w", encoding="utf-8") as f:
            json.dump(_policy_doc(), f)
        policy = load_policy_file(policy_path)
        self.assertEqual(policy.version, 1)
        self.assertTrue(policy.capabilities["process.spawn"])

    def test_cli_refuses_malformed_policy_file(self) -> None:
        tmp = tempfile.mkdtemp(prefix="as-policy-cli-")
        self.addCleanup(shutil.rmtree, tmp, True)
        policy_path = os.path.join(tmp, "policy.json")
        with open(policy_path, "w", encoding="utf-8") as f:
            f.write("{ not json")
        with self.assertRaises(PolicyError) as cm:
            load_policy_file(policy_path)
        self.assertIn("malformed JSON", str(cm.exception))

    def test_cli_missing_policy_file_is_usage_error(self) -> None:
        # A policy file that cannot be read refuses at the CLI boundary
        # (exit 2 - never a session that silently ignores the policy).
        rc = cli_mod.main([
            "--workspace", self._src, "--mode", "restricted",
            "--policy", os.path.join(self._src, "missing.json"),
            "--", "echo", "x",
        ])
        self.assertEqual(rc, cli_mod.EXIT_USAGE)

    def test_cli_denying_policy_document_is_usage_error(self) -> None:
        # A policy document with an unknown capability is rejected at load
        # time - exit 2, workload never attempted.
        tmp = tempfile.mkdtemp(prefix="as-policy-cli-")
        self.addCleanup(shutil.rmtree, tmp, True)
        policy_path = os.path.join(tmp, "policy.json")
        bad = _policy_doc()
        bad["capabilities"]["nonsense.cap"] = True
        with open(policy_path, "w", encoding="utf-8") as f:
            json.dump(bad, f)
        rc = cli_mod.main([
            "--workspace", self._src, "--mode", "restricted",
            "--policy", policy_path,
            "--", "echo", "x",
        ])
        self.assertEqual(rc, cli_mod.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
