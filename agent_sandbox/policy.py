"""Capability-based policy engine (Phase 4, ADR-010, ARCHITECTURE section 12).

The policy engine is the SINGLE decision point for every requested action
across CLI, MCP and API (S-015, S-016, S-017): a validated request is
decided here BEFORE it reaches the enforcement core, and the OS boundary
remains the backstop (a policy bug can over-allow an action, but the
sandbox boundary still contains it).

Format decision (Phase 4 re-confirmation of ADR-010): the project carries
ZERO runtime dependencies (pyproject.toml ``dependencies = []``) and the
TCB rule forbids adding one merely for convenience. ADR-010 explicitly
provides a zero-dependency JSON alternative if PyYAML is rejected - this
module takes that documented fallback: policy documents are strict-schema
JSON, parsed and validated host-side with the stdlib ``json`` module. No
new dependency enters the trusted computing base.

Policy document (version 1, strict schema):

    {
      "version": 1,
      "capabilities": {
        "filesystem.read.workspace": true,
        "filesystem.write.workspace": true,
        "process.spawn": true,
        "git.read": true,
        "git.commit": true,
        "git.push": false,
        "network.connect": false,
        "secrets.read": false,
        "privileged.exec": false
      },
      "resources": { ...optional limit declarations, validated host-side... }
    }

Rules enforced here (SECURITY_SPEC S-021, ARCHITECTURE section 12):

- Versioned: ``version`` must be exactly 1; anything else is rejected.
- Deny by default: a capability that is absent or unknown is DENIED -
  allow decisions must be explicit.
- Unknown security-critical fields are REJECTED, never ignored: an unknown
  top-level key or an unknown capability name fails validation with a
  deterministic message naming the offending field.
- Malformed values (non-boolean capability entries, non-mapping policy,
  malformed resources) are rejected.
- Deterministic evaluation: ``decide()``/``require()`` return the same
  result for the same input on every call.
- Immutability (S-025/S-026): a ``Policy`` is frozen after validation; the
  capabilities mapping is a read-only proxy. The policy lives host-side in
  the trusted configuration and is NEVER mounted into the sandbox
  (``build_rootfs`` copies only the workspace - S-026 tested).
- Resource declarations are validated host-side; the authoritative limit
  enforcement stays single-sourced in ``RuntimeConfig.resources``
  (ADR-007) and a policy/config resource conflict is REJECTED (never a
  silent override).

Trust boundary: this module is TRUSTED host-side code (part of the TCB,
ADR-002). It runs BEFORE any untrusted code exists and never executes
untrusted content.
"""

from __future__ import annotations

import json
import types
from collections.abc import Mapping
from dataclasses import dataclass, field

from agent_sandbox.models import ConfigError

POLICY_VERSION = 1

# The v0.1 capability vocabulary (ARCHITECTURE section 12 / ADR-010
# capability model). Every capability a session may consult. Capabilities
# are dotted names: <domain>.<action>.<target>.
FILESYSTEM_CAPABILITIES = (
    "filesystem.read.workspace",   # read the workspace copy (S-028/S-029)
    "filesystem.write.workspace",  # write inside the workspace copy
)
PROCESS_CAPABILITIES = (
    "process.spawn",               # run a command / spawn a process
)
GIT_CAPABILITIES = (
    "git.read",                    # inspect repository state
    "git.commit",                  # create commits
    "git.push",                    # DENIED by default (ARCHITECTURE section 12)
)
NETWORK_CAPABILITIES = (
    "network.connect",             # outbound connections - deny by default
)
SECRET_CAPABILITIES = (
    "secrets.read",                # secret access - deny by default
)
PRIVILEGED_CAPABILITIES = (
    "privileged.exec",             # privileged operations - deny by default
)

ALL_CAPABILITIES = (
    FILESYSTEM_CAPABILITIES
    + PROCESS_CAPABILITIES
    + GIT_CAPABILITIES
    + NETWORK_CAPABILITIES
    + SECRET_CAPABILITIES
    + PRIVILEGED_CAPABILITIES
)

# The v0.1 default policy: exactly the behavior the verified v0.1 runtime
# provides (workspace RW, process execution, git read/commit; push,
# network, secrets and privileged operations denied by default). It is the
# policy a session uses when the caller supplies no policy document.
DEFAULT_CAPABILITIES = {
    "filesystem.read.workspace": True,
    "filesystem.write.workspace": True,
    "process.spawn": True,
    "git.read": True,
    "git.commit": True,
    "git.push": False,
    "network.connect": False,
    "secrets.read": False,
    "privileged.exec": False,
}

# Resource keys a policy may declare (mirrors config.py's vocabulary; the
# AUTHORITATIVE bounds/validation and enforcement live in
# RuntimeConfig.resources - ADR-007, single source of truth).
POLICY_RESOURCE_KEYS = (
    "cpu_seconds",
    "memory_mb",
    "disk_mb",
    "processes",
    "open_files",
    "output_mb",
    "wall_time_seconds",
    "cpu_quota_percent",
    "io_mbps",
)


class PolicyError(ConfigError):
    """A policy document rejected at the boundary. Message is deterministic
    and names the offending field (S-021)."""


@dataclass(frozen=True)
class PolicyDecision:
    """Outcome of a single policy decision (S-015: explicit, deterministic,
    machine-readable). ``allowed == False`` means the operation MUST NOT
    proceed through this capability."""

    capability: str
    allowed: bool
    reason: str

    def describe(self) -> str:
        verb = "allowed" if self.allowed else "DENIED"
        return f"policy: {self.capability} {verb} - {self.reason}"


@dataclass(frozen=True)
class Policy:
    """A validated, immutable capability policy (S-021/S-025/S-026).

    ``capabilities`` maps capability name -> allowed. Absent/unknown
    capabilities are denied by default. The mapping is a read-only proxy,
    so the policy cannot be mutated after validation.
    """

    version: int
    capabilities: Mapping[str, bool] = field(
        default_factory=lambda: types.MappingProxyType(dict(DEFAULT_CAPABILITIES)))
    resources: Mapping[str, int] | None = None

    # -- construction -----------------------------------------------------
    @classmethod
    def from_dict(cls, data) -> Policy:
        """Build + strictly validate a policy from a dict. Rejects unknown
        fields, unknown capabilities, malformed values and an unsupported
        version with a deterministic ``PolicyError`` naming the field
        (S-021 - never warn-and-continue for security-critical policy)."""
        if not isinstance(data, dict):
            raise PolicyError("policy must be a mapping (JSON object)")

        unknown = sorted(set(data) - {"version", "capabilities", "resources"})
        if unknown:
            raise PolicyError(
                f"policy: unknown field(s): {', '.join(unknown)} - "
                "security-critical policy fields must be explicit")

        version = data.get("version")
        if version != POLICY_VERSION:
            raise PolicyError(
                f"policy: unsupported version {version!r} (supported: "
                f"{POLICY_VERSION}) - policy must be versioned and explicit")

        caps_raw = data.get("capabilities")
        if caps_raw is None:
            caps_raw = {}
        if not isinstance(caps_raw, dict):
            raise PolicyError("policy: capabilities must be a mapping")

        capabilities: dict[str, bool] = {}
        for name, value in caps_raw.items():
            if not isinstance(name, str):
                raise PolicyError(
                    f"policy: capabilities key must be a string, got "
                    f"{name!r}")
            if name not in ALL_CAPABILITIES:
                raise PolicyError(
                    f"policy: unknown capability {name!r} - unknown "
                    "security-critical fields are rejected, not ignored "
                    f"(supported: {', '.join(ALL_CAPABILITIES)})")
            if not isinstance(value, bool):
                raise PolicyError(
                    f"policy: capabilities.{name} must be true/false, got "
                    f"{value!r}")
            capabilities[name] = value

        # Deny by default: every capability not explicitly declared is
        # absent -> decided DENIED.
        resources = _parse_policy_resources(data.get("resources"))

        return cls(version=version,
                   capabilities=types.MappingProxyType(capabilities),
                   resources=resources)

    @classmethod
    def default(cls) -> Policy:
        """The documented v0.1 default policy (deny by default except the
        workspace/process/git-read surface the runtime actually provides)."""
        return cls(version=POLICY_VERSION,
                   capabilities=types.MappingProxyType(dict(DEFAULT_CAPABILITIES)),
                   resources=None)

    # -- the single decision path (S-015) --------------------------------
    def decide(self, capability: str) -> PolicyDecision:
        """Decide one capability. Deterministic; unknown or absent
        capabilities are DENIED by default."""
        if not isinstance(capability, str):
            return PolicyDecision(capability=repr(capability), allowed=False,
                                  reason="capability name must be a string")
        allowed = self.capabilities.get(capability, False)
        if capability not in ALL_CAPABILITIES:
            return PolicyDecision(
                capability=capability, allowed=False,
                reason="unknown capability - denied by default")
        if allowed:
            return PolicyDecision(capability=capability, allowed=True,
                                  reason="explicitly allowed by policy")
        return PolicyDecision(capability=capability, allowed=False,
                              reason="denied by policy (explicit or default)")

    def require(self, *capabilities: str) -> PolicyDecision:
        """Decide a set of capabilities: the FIRST denial wins, or the
        allow decision if all are allowed. Used by operations that need
        several capabilities (e.g. command execution)."""
        for cap in capabilities:
            decision = self.decide(cap)
            if not decision.allowed:
                return decision
        return PolicyDecision(capability="+".join(capabilities) if capabilities
                              else "(none)", allowed=True,
                              reason="all required capabilities allowed")

    def to_dict(self) -> dict:
        """Machine-readable policy view (S-040: the active security
        configuration is observable). Only the validated capability map is
        exposed - never host paths or secrets."""
        return {
            "version": self.version,
            "capabilities": dict(self.capabilities),
        }


# ---------------------------------------------------------------------------
# Resource declarations (validated host-side; enforcement stays in
# RuntimeConfig.resources - ADR-007 single source of truth)
# ---------------------------------------------------------------------------

def _parse_policy_resources(value) -> Mapping[str, int] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise PolicyError("policy: resources must be a mapping")
    unknown = sorted(set(value) - set(POLICY_RESOURCE_KEYS))
    if unknown:
        raise PolicyError(
            f"policy: unknown resource limit(s): {', '.join(unknown)}")
    out: dict[str, int] = {}
    for key, v in value.items():
        if isinstance(v, bool) or not isinstance(v, int):
            raise PolicyError(
                f"policy: resources.{key} must be an integer, got {v!r}")
        if v < 1:
            raise PolicyError(
                f"policy: resources.{key} must be >= 1, got {v}")
        out[key] = v
    return types.MappingProxyType(out)


# ---------------------------------------------------------------------------
# Document loading (host-side, fail closed)
# ---------------------------------------------------------------------------

def load_policy_file(path: str) -> Policy:
    """Load + strictly validate a policy document from a JSON file. Any
    parse/validation failure raises PolicyError (fail closed - a malformed
    policy never starts a session, S-021)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise PolicyError(
            f"policy: cannot read policy file {path!r}: {e}") from e
    except ValueError as e:
        raise PolicyError(
            f"policy: malformed JSON in {path!r}: {e}") from e
    return Policy.from_dict(data)
