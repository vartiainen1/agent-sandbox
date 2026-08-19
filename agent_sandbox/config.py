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

# cgroup policy keys (Phase 1 Step 10, ADR-007): optional in the resources
# dict with the documented defaults below (the approved policy definition -
# READING A: all four cgroup controllers are mandatory for HARDENED).
# cpu_quota_percent: percent of one CPU core (1..10000); the cpu.max quota
#   is cpu_quota_percent * 1000 us over a fixed 100000 us period.
# io_mbps: MiB/s rate limit for io.max (1..1048576) applied to the
#   workspace backing block device (resolved from kernel state).
_CGROUP_POLICY_KEYS = ("cpu_quota_percent", "io_mbps")
DEFAULT_CPU_QUOTA_PERCENT = 100
DEFAULT_IO_MBPS = 1024
_CPU_QUOTA_PERCENT_MIN, _CPU_QUOTA_PERCENT_MAX = 1, 10000
_IO_MBPS_MIN, _IO_MBPS_MAX = 1, 1048576


@dataclass(frozen=True)
class ResourceLimits:
    """Explicit resource limits (ARCHITECTURE.md section 9; S-012/S-027).

    Every limit is enforced outside the workload and cannot be raised by
    it. All values must be positive (counts below 1 are usage errors).

    cgroup policy (Phase 1 Step 10, ADR-007 - READING A, approved
    2026-08-19): ``cpu_quota_percent`` (percent of one core, default 100)
    maps to cpu.max = "{percent * 1000} 100000" (fixed 100000 us period);
    ``io_mbps`` (MiB/s, default 1024) maps to
    io.max = "{major}:{minor} rbps={mbps * MiB} wbps={mbps * MiB}" on the
    workspace backing block device (resolved from kernel state; an
    unresolvable device is a HARDENED refusal, never a skip). Both are
    optional in the resources dict and default to these documented
    values.
    """

    cpu_seconds: int
    memory_mb: int
    disk_mb: int
    processes: int
    open_files: int
    output_mb: int
    wall_time_seconds: int
    cpu_quota_percent: int = DEFAULT_CPU_QUOTA_PERCENT  # % of one core (cpu.max)
    io_mbps: int = DEFAULT_IO_MBPS                      # MiB/s (io.max on the backing device)


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
    unknown = sorted(set(value) - (set(_RESOURCE_KEYS) | set(_CGROUP_POLICY_KEYS)))
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
    # cgroup policy keys: optional, defaulted to the documented values.
    kwargs["cpu_quota_percent"] = _parse_bounded(
        "cpu_quota_percent", value.get("cpu_quota_percent"),
        DEFAULT_CPU_QUOTA_PERCENT, _CPU_QUOTA_PERCENT_MIN, _CPU_QUOTA_PERCENT_MAX)
    kwargs["io_mbps"] = _parse_bounded(
        "io_mbps", value.get("io_mbps"), DEFAULT_IO_MBPS,
        _IO_MBPS_MIN, _IO_MBPS_MAX)
    return ResourceLimits(**kwargs)


def _parse_bounded(key: str, value, default: int, lo: int, hi: int) -> int:
    """Parse an optional bounded integer with a documented default."""
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"resources: {key} must be an integer, got {value!r}")
    if not lo <= value <= hi:
        raise ConfigError(
            f"resources: {key} must be in [{lo}, {hi}], got {value}")
    return value


def _default_limits() -> ResourceLimits:
    # ARCHITECTURE.md section 9 example defaults (design section 17)
    return ResourceLimits(
        cpu_seconds=300, memory_mb=4096, disk_mb=10240, processes=256,
        open_files=4096, output_mb=50, wall_time_seconds=900)
