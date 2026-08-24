"""Shared helpers for the unit suite (agent-sandbox Phase 1/2 evidence).

The suite is unittest-based; this package init carries only shared,
documented helpers - never security policy or enforcement logic.
"""

from __future__ import annotations


def require_delegation_unavailable(testcase):
    """Substrate-premise gate for the 'HARDENED refuses at RESOURCES
    without delegation' tests.

    Those tests assert the fail-closed behavior of the RESOURCES stage
    when cgroup v2 delegation is UNAVAILABLE to the caller. On a
    delegation-capable substrate (e.g. the native P3 VM as root) the
    premise is absent - HARDENED legitimately reaches READY there, and
    the delegation-capable path is proven by the privileged-substrate
    tests (test_cgroups.py CgroupDelegationGatedTests) and the native
    P3 HARDENED suite (tests/native/test_hardened_e2e.py). This helper
    SKIPS with an explicit recorded reason in that case; on substrates
    without delegation it returns and the test's fail-closed assertions
    run unchanged - never weakened, never removed.

    Returns the probe's blocked reason when delegation is unavailable
    (for the caller's own reporting); raises ``testcase.skipTest`` when
    delegation IS available.
    """
    from agent_sandbox.isolation.cgroups import probe_delegation
    blocked = probe_delegation()
    if blocked is None:
        testcase.skipTest(
            "Substrate note: cgroup delegation IS available to this "
            "caller (probe_delegation() succeeded), so the premise of "
            "this test - 'HARDENED must refuse when delegation is "
            "unavailable' - cannot hold here. The delegation-capable "
            "path is covered by the privileged-substrate tests and the "
            "native P3 HARDENED suite; the fail-closed assertion runs "
            "on substrates without delegation."
        )
    return blocked


def require_namespace_available(testcase):
    """Substrate-premise gate for tests that need the namespace boundary
    to form (execute-path and stage-specific init tests).

    Skips with a recorded reason when the real namespace probe
    (setup._probe_impl) cannot establish the user/mount/PID/network/UTS/IPC
    boundary on this host (e.g. GitHub Actions non-root runners where
    AppArmor blocks unprivileged user namespaces). Tests gated by this
    helper assert behavior that only exists once the boundary forms; on
    substrates where it cannot, skipping is the honest outcome - never a
    crash and never a weakened assertion.
    """
    import unittest.mock

    from agent_sandbox.isolation import setup
    from agent_sandbox.security import init as init_mod

    with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
        check = setup._probe_impl()
    if not check.ok:
        testcase.skipTest(
            "Substrate note: the namespace boundary cannot form here "
            f"({check.reason}); this test asserts behavior that requires "
            "the boundary to form, so it is skipped on this substrate. "
            "The fail-closed path is still covered by the init-path "
            "wiring tests."
        )
    return check.reason
