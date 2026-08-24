"""Phase 17 — Security Regression Suite: S-invariant coverage matrix.

Every security invariant defined in SECURITY_SPEC.md (S-001..S-040) must
map to one or more tests.  This module:

1. Declares the authoritative S-invariant → test-file mapping.
2. Verifies every mapped file exists and contains the referenced test
   class (structural coverage gate).
3. Runs a representative smoke test for each invariant group to confirm
   the underlying security property holds (functional regression gate).

Evidence classification: HOST-SIDE / unit-level.  This suite exercises
supervisor-side coverage tracking and lightweight property checks; it
does NOT replace native kernel-boundary verification (the adversarial
and native suites remain authoritative for boundary enforcement).

Created: 2026-08-23 (Phase 17, implementation.md §21)
"""

from __future__ import annotations

import importlib
import unittest
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# 1.  Authoritative S-invariant → test mapping
# ---------------------------------------------------------------------------

# Each entry: (invariant_id, description, [(test_module, test_class), ...])
# At least one entry per S-invariant is REQUIRED.

_S_COVERAGE: List[Tuple[str, str, List[Tuple[str, str]]]] = [
    # --- Filesystem ---
    (
        "S-001",
        "Filesystem Isolation",
        [
            ("tests.unit.test_rootfs", "WorkspaceIsolationTests"),
            ("tests.adversarial.test_filesystem_attacks", "PathTraversalTests"),
        ],
    ),
    (
        "S-002",
        "No Implicit Host Filesystem Access",
        [
            ("tests.unit.test_rootfs", "WorkspaceIsolationTests"),
            ("tests.unit.test_procdev", "RootfsHostSideTests"),
        ],
    ),
    (
        "S-028",
        "Workspace Boundary",
        [
            ("tests.unit.test_rootfs", "WorkspaceIsolationTests"),
            ("tests.adversarial.test_filesystem_attacks", "WorkspaceEscapeTests"),
        ],
    ),
    (
        "S-029",
        "Symlink Safety",
        [
            ("tests.adversarial.test_filesystem_attacks", "SymlinkEscapeTests"),
        ],
    ),
    (
        "S-030",
        "Path Traversal Protection",
        [
            ("tests.adversarial.test_filesystem_attacks", "PathTraversalTests"),
        ],
    ),
    # --- Credentials / Secrets ---
    (
        "S-003",
        "Credential Isolation",
        [
            ("tests.unit.test_credentials", "CredentialSandboxTests"),
            ("tests.adversarial.test_info_leakage", "AuditEnvironmentLeakageTests"),
        ],
    ),
    (
        "S-004",
        "Unix Socket Isolation",
        [
            ("tests.unit.test_credentials", "SocketCreationTests"),
        ],
    ),
    (
        "S-034",
        "Environment Isolation",
        [
            ("tests.unit.test_environment", "EnvConstructionTests"),
            ("tests.adversarial.test_info_leakage", "AuditEnvironmentLeakageTests"),
        ],
    ),
    # --- Network ---
    (
        "S-005",
        "Network Default Deny",
        [
            ("tests.unit.test_network", "NetworkBoundaryTests"),
        ],
    ),
    (
        "S-006",
        "Private Network Protection",
        [
            ("tests.unit.test_network", "NetworkBoundaryTests"),
            ("tests.unit.test_proxy", "DestinationGateTests"),
        ],
    ),
    (
        "S-007",
        "Metadata Protection",
        [
            ("tests.unit.test_network", "NetworkBoundaryTests"),
        ],
    ),
    # --- Privilege / Capabilities ---
    (
        "S-008",
        "Privilege Restriction",
        [
            ("tests.unit.test_privileges", "NoNewPrivsHostTests"),
            ("tests.unit.test_namespaces", "NamespaceCreationTests"),
        ],
    ),
    (
        "S-009",
        "Capability Restriction",
        [
            ("tests.unit.test_privileges", "CapabilityReductionHostTests"),
        ],
    ),
    (
        "S-010",
        "no_new_privs",
        [
            ("tests.unit.test_privileges", "NoNewPrivsHostTests"),
        ],
    ),
    (
        "S-011",
        "Syscall Restriction",
        [
            ("tests.unit.test_seccomp", "SeccompBoundaryTests"),
        ],
    ),
    # --- Resources ---
    (
        "S-012",
        "Resource Limits",
        [
            ("tests.unit.test_resources", "ResourcePolicyTests"),
            ("tests.unit.test_cgroups", "CgroupPolicyTests"),
        ],
    ),
    (
        "S-027",
        "Resource Policy Immutability",
        [
            ("tests.unit.test_resources", "ResourcePolicyTests"),
            ("tests.adversarial.test_resource_attacks", "ResourceLimitIncreaseTests"),
        ],
    ),
    (
        "S-036",
        "Timeout Enforcement",
        [
            ("tests.unit.test_timeout", "DeadlineCollectionTests"),
        ],
    ),
    (
        "S-037",
        "Output Limits",
        [
            ("tests.unit.test_output", "BoundedReadTests"),
        ],
    ),
    # --- Process ---
    (
        "S-013",
        "Process Containment",
        [
            ("tests.unit.test_namespaces", "NamespaceCreationTests"),
            ("tests.adversarial.test_resource_attacks", "ForkBombTests"),
        ],
    ),
    (
        "S-014",
        "Process Cleanup",
        [
            ("tests.unit.test_lifecycle", "SubreaperTests"),
        ],
    ),
    (
        "S-038",
        "Cleanup Failure Visibility",
        [
            ("tests.unit.test_lifecycle", "AbsenceVerificationTests"),
            ("tests.adversarial.test_lifecycle_attacks", "IncompleteCleanupTests"),
        ],
    ),
    # --- Policy ---
    (
        "S-015",
        "Policy Enforcement",
        [
            ("tests.unit.test_policy", "SessionPolicyGateTests"),
            ("tests.unit.test_cli", "SessionExecuteTests"),
        ],
    ),
    (
        "S-016",
        "MCP Cannot Bypass Security",
        [
            ("tests.unit.test_mcp", "ProtocolTests"),
        ],
    ),
    (
        "S-017",
        "API Cannot Bypass Security",
        [
            ("tests.unit.test_api", "ApiEquivalenceTests"),
        ],
    ),
    (
        "S-021",
        "Policy Validation",
        [
            ("tests.unit.test_policy", "PolicyValidationTests"),
        ],
    ),
    (
        "S-025",
        "Host Control",
        [
            ("tests.adversarial.test_lifecycle_attacks", "PolicyTamperingTests"),
        ],
    ),
    (
        "S-026",
        "Policy Immutability",
        [
            ("tests.unit.test_policy", "PolicyImmutabilityTests"),
            ("tests.adversarial.test_lifecycle_attacks", "PolicyTamperingTests"),
        ],
    ),
    # --- Fail closed ---
    (
        "S-018",
        "Fail Closed",
        [
            ("tests.unit.test_failclosed_matrix", "InitPathFailClosedTests"),
        ],
    ),
    (
        "S-019",
        "No Silent Security Downgrade",
        [
            ("tests.unit.test_skeleton", "InitializationTests"),
        ],
    ),
    (
        "S-020",
        "Explicit Security Mode",
        [
            ("tests.unit.test_skeleton", "InitializationTests"),
            ("tests.unit.test_cli", "SessionExecuteTests"),
        ],
    ),
    # --- Audit ---
    (
        "S-022",
        "Auditability",
        [
            ("tests.unit.test_policy", "SessionPolicyGateTests"),
            ("tests.adversarial.test_info_leakage", "AuditTamperingTests"),
        ],
    ),
    (
        "S-023",
        "Session Correlation",
        [
            ("tests.unit.test_cli", "AuditTests"),
        ],
    ),
    (
        "S-024",
        "Audit Is Not Enforcement",
        [
            ("tests.adversarial.test_info_leakage", "AuditTamperingTests"),
            ("tests.fuzz.test_fuzz_interfaces", "AuditReadBackFuzzTests"),
        ],
    ),
    (
        "S-039",
        "Security Errors Are Explicit",
        [
            ("tests.unit.test_output", "BoundedReadTests"),
        ],
    ),
    (
        "S-040",
        "Security Configuration Is Observable",
        [
            ("tests.unit.test_policy", "PolicyValidationTests"),
            ("tests.unit.test_cli_sessions", "StatusTests"),
        ],
    ),
    # --- Content / Supply chain ---
    (
        "S-032",
        "Malicious Repository Safety",
        [
            ("tests.adversarial.test_content_attacks", "HookAttackTests"),
            ("tests.adversarial.test_git_attacks", "HostileConfigContainmentTests"),
        ],
    ),
    (
        "S-033",
        "Dependency Safety",
        [
            ("tests.adversarial.test_content_attacks", "DependencyAttackTests"),
        ],
    ),
    # --- Controlled execution ---
    (
        "S-035",
        "Controlled Execution",
        [
            ("tests.unit.test_workload", "EndToEndWorkloadTests"),
        ],
    ),
    # --- Race safety ---
    (
        "S-031",
        "Race Safety",
        [
            ("tests.unit.test_race_concurrency", "RegistryAtomicityTests"),
            ("tests.adversarial.test_filesystem_attacks", "TOCTOURaceTests"),
        ],
    ),
]

# All 40 invariants must be present.
_ALL_INVARIANTS = {f"S-{i:03d}" for i in range(1, 41)}


# ---------------------------------------------------------------------------
# 2.  Structural coverage gate: every mapped file/class must exist
# ---------------------------------------------------------------------------

def _resolve_test_modules() -> Dict[str, object]:
    """Import every test module referenced in the coverage matrix."""
    modules: Dict[str, object] = {}
    for _, _, test_refs in _S_COVERAGE:
        for mod_path, _cls_name in test_refs:
            if mod_path not in modules:
                try:
                    import_path = mod_path.replace("/", ".").replace("\\", ".")
                    modules[mod_path] = importlib.import_module(import_path)
                except ImportError as exc:
                    modules[mod_path] = exc  # type: ignore[assignment]
    return modules


class SInvariantCoverageMatrixTests(unittest.TestCase):
    """Verify the S-invariant coverage matrix is complete and structurally valid."""

    def test_all_40_invariants_mapped(self) -> None:
        """SECURITY_SPEC defines S-001..S-040; every one must appear."""
        mapped = {entry[0] for entry in _S_COVERAGE}
        missing = _ALL_INVARIANTS - mapped
        self.assertEqual(
            missing,
            set(),
            f"S-invariants missing from coverage matrix: {sorted(missing)}",
        )

    def test_no_duplicate_invariant_entries(self) -> None:
        """Each S-invariant must appear exactly once in the matrix."""
        ids = [entry[0] for entry in _S_COVERAGE]
        dupes = [x for x in ids if ids.count(x) > 1]
        self.assertEqual(dupes, [], f"Duplicate S-invariant entries: {sorted(set(dupes))}")

    def test_every_mapped_module_exists(self) -> None:
        """Every test module referenced in the matrix must be importable."""
        modules = _resolve_test_modules()
        failures = {}
        for mod_path, result in modules.items():
            if isinstance(result, Exception):
                failures[mod_path] = str(result)
        self.assertEqual(
            failures,
            {},
            f"Test modules referenced in coverage matrix but not importable: {failures}",
        )

    def test_every_mapped_class_exists_in_module(self) -> None:
        """Every test class referenced in the matrix must exist in its module."""
        modules = _resolve_test_modules()
        missing: List[str] = []
        for invariant_id, _, test_refs in _S_COVERAGE:
            for mod_path, cls_name in test_refs:
                mod = modules.get(mod_path)
                if isinstance(mod, Exception):
                    continue
                if not hasattr(mod, cls_name):
                    missing.append(f"{invariant_id}: {mod_path}.{cls_name}")
        self.assertEqual(
            missing,
            [],
            f"Test classes referenced but not found: {missing}",
        )


# ---------------------------------------------------------------------------
# 3.  Functional regression gate: representative smoke tests per invariant
# ---------------------------------------------------------------------------

_SMOKE_TESTS: List[Tuple[str, str, str, str]] = [
    # (invariant_id, test_module, test_class, test_method)
    ("S-001", "tests.unit.test_rootfs", "WorkspaceIsolationTests", "test_workspace_copy_is_fresh_copy"),
    ("S-002", "tests.unit.test_rootfs", "WorkspaceIsolationTests", "test_sandbox_changes_do_not_modify_host_source"),
    ("S-003", "tests.unit.test_credentials", "CredentialSandboxTests", "test_credential_paths_unreachable_in_workload"),
    ("S-004", "tests.unit.test_credentials", "SocketCreationTests", "test_denied_reports_true"),
    ("S-005", "tests.unit.test_network", "NetworkBoundaryTests", "test_network_denied_at_syscall_level"),
    ("S-006", "tests.unit.test_network", "NetworkBoundaryTests", "test_no_non_loopback_interfaces"),
    ("S-007", "tests.unit.test_network", "NetworkBoundaryTests", "test_no_non_loopback_interfaces"),
    ("S-008", "tests.unit.test_privileges", "NoNewPrivsHostTests", "test_verify_ok_when_readback_is_one"),
    ("S-009", "tests.unit.test_privileges", "CapabilityReductionHostTests", "test_verify_capability_reduction_ok"),
    ("S-010", "tests.unit.test_privileges", "NoNewPrivsHostTests", "test_verify_ok_when_readback_is_one"),
    ("S-011", "tests.unit.test_seccomp", "SeccompBoundaryTests", "test_filter_installed_and_forbidden_syscall_denied"),
    ("S-012", "tests.unit.test_resources", "ResourcePolicyTests", "test_verify_readback_ok"),
    ("S-013", "tests.unit.test_namespaces", "NamespaceCreationTests", "test_user_namespace_created"),
    ("S-014", "tests.unit.test_lifecycle", "SubreaperTests", "test_establish_and_verify_subreaper"),
    ("S-015", "tests.unit.test_policy", "SessionPolicyGateTests", "test_policy_denying_workspace_read_refuses_execution"),
    ("S-016", "tests.unit.test_mcp", "ProtocolTests", "test_unknown_method_never_executes"),
    ("S-017", "tests.unit.test_api", "ApiEquivalenceTests", "test_success_equivalent_across_all_three"),
    ("S-018", "tests.unit.test_failclosed_matrix", "InitPathFailClosedTests", "test_hardened_init_reaches_ready_when_all_stages_pass"),
    ("S-019", "tests.unit.test_skeleton", "InitializationTests", "test_no_silent_downgrade"),
    ("S-020", "tests.unit.test_skeleton", "InitializationTests", "test_init_result_is_explicit"),
    ("S-021", "tests.unit.test_policy", "PolicyValidationTests", "test_valid_policy_parses"),
    ("S-022", "tests.unit.test_cli", "AuditTests", "test_recorder_writes_jsonl"),
    ("S-023", "tests.unit.test_cli", "AuditTests", "test_session_correlates_events"),
    ("S-024", "tests.unit.test_cli", "AuditTests", "test_audit_failure_does_not_block_execution"),
    ("S-025", "tests.unit.test_policy", "PolicyImmutabilityTests", "test_policy_is_frozen"),
    ("S-026", "tests.unit.test_policy", "PolicyImmutabilityTests", "test_policy_is_frozen"),
    ("S-027", "tests.unit.test_resources", "ResourcePolicyTests", "test_verify_readback_ok"),
    ("S-028", "tests.unit.test_rootfs", "WorkspaceIsolationTests", "test_workspace_copy_is_fresh_copy"),
    ("S-029", "tests.unit.test_rootfs", "WorkspaceIsolationTests", "test_symlink_escapes_blocked"),
    ("S-030", "tests.unit.test_rootfs", "WorkspaceIsolationTests", "test_workspace_copy_is_fresh_copy"),
    ("S-031", "tests.unit.test_race_concurrency", "RegistryAtomicityTests", "test_concurrent_writers_produce_valid_manifests"),
    ("S-032", "tests.unit.test_git_workflow", "GitCliTests", "test_git_denied_git_read_refuses_before_boundary"),
    ("S-033", "tests.adversarial.test_content_attacks", "DependencyAttackTests", "test_dependency_attack_executes_and_is_contained"),
    ("S-034", "tests.unit.test_environment", "EnvConstructionTests", "test_default_allowlist_is_the_six_approved"),
    ("S-035", "tests.unit.test_workload", "EndToEndWorkloadTests", "test_minimal_successful_workload_executes"),
    ("S-036", "tests.unit.test_timeout", "DeadlineCollectionTests", "test_deadline_expiry_terminates"),
    ("S-037", "tests.unit.test_output", "BoundedReadTests", "test_read_bounded_over_limit_truncates"),
    ("S-038", "tests.unit.test_lifecycle", "AbsenceVerificationTests", "test_no_survivors_ok"),
    ("S-039", "tests.unit.test_output", "BoundedReadTests", "test_truncation_notice_is_deterministic"),
    ("S-040", "tests.unit.test_policy", "PolicyValidationTests", "test_valid_policy_parses"),
]


class SInvariantSmokeTests(unittest.TestCase):
    """Run one representative test per S-invariant to confirm the property holds."""

    pass  # Dynamically generated below.


def _make_smoke_test(invariant_id: str, mod_path: str, cls_name: str, method_name: str):  # type: ignore[no-untyped-def]
    """Factory: return a test method that instantiates the class and runs one method."""

    def _smoke(self: unittest.TestCase) -> None:
        import_path = mod_path.replace("/", ".").replace("\\", ".")
        mod = importlib.import_module(import_path)
        cls = getattr(mod, cls_name)
        instance = cls()
        if hasattr(instance, "setUp"):
            instance.setUp()
        try:
            getattr(instance, method_name)()
        finally:
            # Run tearDown if defined, then always run doCleanups() to
            # execute any addCleanup() callbacks registered during setUp.
            # Without this, classes that use addCleanup (e.g.
            # InitPathFailClosedTests) leak mock patches into subsequent
            # tests, causing platform-detection tests to fail.
            if hasattr(instance, "tearDown"):
                instance.tearDown()
            instance.doCleanups()

    _smoke.__doc__ = f"Smoke: {invariant_id} via {cls_name}.{method_name}"
    _smoke.__name__ = f"test_smoke_{invariant_id.lower()}"
    return _smoke


for _inv, _mod, _cls, _meth in _SMOKE_TESTS:
    _test_method = _make_smoke_test(_inv, _mod, _cls, _meth)
    setattr(SInvariantSmokeTests, _test_method.__name__, _test_method)


# ---------------------------------------------------------------------------
# 4.  Coverage summary (printed on run)
# ---------------------------------------------------------------------------

def _print_coverage_summary() -> None:
    """Print the S-invariant coverage matrix summary."""
    print("\n" + "=" * 72)
    print("Phase 17 — S-Invariant Coverage Matrix (SECURITY_SPEC S-001..S-040)")
    print("=" * 72)
    mapped = {entry[0] for entry in _S_COVERAGE}
    missing = _ALL_INVARIANTS - mapped
    print("Total S-invariants:   40")
    print(f"Mapped in matrix:     {len(mapped)}")
    print(f"Missing from matrix:  {len(missing)} {sorted(missing) if missing else ''}")
    print(f"Smoke tests defined:  {len(_SMOKE_TESTS)}")
    print("-" * 72)
    for inv_id, desc, refs in _S_COVERAGE:
        files = ", ".join(f"{m}.{c}" for m, c in refs)
        print(f"  {inv_id}: {desc}")
        print(f"    -> {files}")
    print("=" * 72 + "\n")


_print_coverage_summary()


if __name__ == "__main__":
    unittest.main()
