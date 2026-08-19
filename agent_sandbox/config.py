"""Runtime configuration - the explicit configuration boundary.

Rules:
- Configuration is DATA + VALIDATION only. No enforcement logic lives here
  (ARCHITECTURE.md section 12: policy/enforcement is separate).
- Configuration is TRUSTED and host-side; it is never writable by the
  workload (S-025, S-026) and never mounted into the sandbox.
- Validation is strict (SECURITY_SPEC.md S-021 spirit): unknown fields are
  rejected, not ignored - an unknown security-critical field must not
  silently change behavior.
- Instances are immutable (frozen): after validation the configuration
  cannot accidentally mutate.
- All validation errors are ``ConfigError`` with a deterministic message
  naming the offending field.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from agent_sandbox.models import ConfigError, SecurityMode

# v0.1 network posture: deny by construction (ARCHITECTURE.md section 8).
# "allowlist" is a v0.2 feature - rejecting it now keeps the boundary
# honest instead of accepting a value we cannot enforce.
SUPPORTED_NETWORK_MODES = frozenset({"deny"})

# Default environment allowlist (ARCHITECTURE.md section 11; S-034):
# the host environment is never inherited - only these are constructed,
# pointing inside the sandbox.
DEFAULT_ENV_ALLOWLIST = ("PATH", "HOME", "LANG", "LC_ALL", "TERM", "TMPDIR")

_RESOURCE_KEYS = (
    "cpu_seconds",
    "memory_mb",
    "disk_mb",
    "processes",
    "open_files",
    "output_mb",
    "wall_time_seconds",
)


@dataclass(frozen=True)
class ResourceLimits:
    """Explicit resource limits (ARCHITECTURE.md section 9; S-012/S-027).

    Every limit is enforced outside the workload and cannot be raised by
    it. All values must be positive (counts below 1 are usage errors).
    """

    cpu_seconds: int
    memory_mb: int
    disk_mb: int
    processes: int
    open_files: int
    output_mb: int
    wall_time_seconds: int


@dataclass(frozen=True)
class RuntimeConfig:
    """Validated, immutable runtime configuration."""

    mode: SecurityMode
    workspace: str
    network_mode: str = "deny"
    env_allowlist: tuple[str, ...] = DEFAULT_ENV_ALLOWLIST
    resources: ResourceLimits = field(default_factory=lambda: _default_limits())

    # -- construction -------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict) -> "RuntimeConfig":
        """Build + strictly validate from a dict. Rejects unknown fields,
        bad values, and unsupported modes with a deterministic
        ``ConfigError`` naming the offending field."""
        if not isinstance(data, dict):
            raise ConfigError("configuration must be a mapping")

        unknown = sorted(set(data) - {
            "mode", "workspace", "network_mode", "env_allowlist", "resources"})
        if unknown:
            raise ConfigError(
                f"unknown configuration field(s): {', '.join(unknown)} - "
                "security-critical fields must be explicit")

        mode = _parse_mode(data.get("mode"))
        workspace = _parse_workspace(data.get("workspace"))
        network_mode = _parse_network_mode(data.get("network_mode", "deny"))
        env_allowlist = _parse_env_allowlist(data.get("env_allowlist"))
        resources = _parse_resources(data.get("resources"))
        return cls(mode=mode, workspace=workspace, network_mode=network_mode,
                   env_allowlist=env_allowlist, resources=resources)

    # -- read-only accessors (no setters; immutability is structural) --
    @property
    def is_hardened(self) -> bool:
        return self.mode is SecurityMode.HARDENED


# ---------------------------------------------------------------------------
# Validation helpers (deterministic messages; every failure names the field)
# ---------------------------------------------------------------------------

def _parse_mode(value) -> SecurityMode:
    if isinstance(value, SecurityMode):
        return value
    if not isinstance(value, str):
        raise ConfigError(f"mode: expected a string, got {type(value).__name__}")
    try:
        return SecurityMode(value)
    except ValueError:
        valid = ", ".join(m.value for m in SecurityMode)
        raise ConfigError(
            f"mode: unsupported security mode {value!r} (supported: {valid}) - "
            "mode is explicit and never auto-downgraded") from None


def _parse_workspace(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("workspace: required, must be a non-empty path")
    if not os.path.isabs(value):
        raise ConfigError(f"workspace: must be an absolute path, got {value!r}")
    return value


def _parse_network_mode(value) -> str:
    if value not in SUPPORTED_NETWORK_MODES:
        raise ConfigError(
            f"network_mode: {value!r} is not supported in v0.1 "
            f"(supported: {', '.join(sorted(SUPPORTED_NETWORK_MODES))}) - "
            "network is deny by construction")
    return value


def _parse_env_allowlist(value) -> tuple[str, ...]:
    if value is None:
        return DEFAULT_ENV_ALLOWLIST
    if not isinstance(value, (list, tuple)):
        raise ConfigError("env_allowlist: expected a list of variable names")
    out = []
    for name in value:
        if not isinstance(name, str) or not name.strip():
            raise ConfigError("env_allowlist: entries must be non-empty strings")
        if any(ch.isspace() or ch == "=" for ch in name):
            raise ConfigError(f"env_allowlist: invalid variable name {name!r}")
        out.append(name)
    if len(out) != len(set(out)):
        raise ConfigError("env_allowlist: duplicate entries are not allowed")
    return tuple(out)


def _parse_resources(value) -> ResourceLimits:
    if value is None:
        return _default_limits()
    if not isinstance(value, dict):
        raise ConfigError("resources: expected a mapping of limits")
    unknown = sorted(set(value) - set(_RESOURCE_KEYS))
    if unknown:
        raise ConfigError(f"resources: unknown limit(s): {', '.join(unknown)}")
    kwargs = {}
    for key in _RESOURCE_KEYS:
        v = value.get(key)
        if v is None:
            raise ConfigError(f"resources: missing required limit {key}")
        if isinstance(v, bool) or not isinstance(v, int):
            raise ConfigError(f"resources: {key} must be an integer, got {v!r}")
        if v < 1:
            raise ConfigError(f"resources: {key} must be >= 1, got {v}")
        kwargs[key] = v
    return ResourceLimits(**kwargs)


def _default_limits() -> ResourceLimits:
    # ARCHITECTURE.md section 9 example defaults (design section 17)
    return ResourceLimits(
        cpu_seconds=300, memory_mb=4096, disk_mb=10240, processes=256,
        open_files=4096, output_mb=50, wall_time_seconds=900)
