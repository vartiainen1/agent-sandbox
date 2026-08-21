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
