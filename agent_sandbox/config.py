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

from agent_sandbox.isolation.proxy import (  # SSRF classification (shared)
    is_allowed_allow_entry,
    is_ipv4_literal,
    validate_host,
)
from agent_sandbox.models import ConfigError, SecurityMode
from agent_sandbox.policy import Policy, PolicyError

# Network posture: deny by construction (v0.1) or allowlist via validating
# proxy (v0.2). The allowlist mode enables a veth-pair plumbing path to a
# host-side proxy that enforces destination restrictions; the sandbox itself
# never has direct external network access.
SUPPORTED_NETWORK_MODES = frozenset({"deny", "allowlist"})


@dataclass(frozen=True)
class NetworkAllow:
    """One allowlisted destination (v0.2 validating proxy, ARCHITECTURE.md
    section 8). ``host`` is a hostname or a strict IPv4 literal;
    ``port`` is 1..65535. ``allow_private`` opts this destination into
    RFC 1918/6598 private ranges - loopback, link-local, metadata and
    the other SSRF-blocked classes are NEVER relaxable (security spec
    section 13: private ranges are denied unless explicitly permitted,
    but the host itself and cloud metadata stay unreachable).

    The allowlist is TRUSTED host-side configuration: it is validated
    here, never mounted into the sandbox, and never writable by the
    workload (S-025/S-026). The proxy enforces it at connect time.
    """

    host: str
    port: int
    allow_private: bool = False

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
    # v0.2 validating proxy: the explicit destination allowlist. Only
    # meaningful when network_mode == "allowlist" (a deny session with
    # allowlist entries is rejected below); the proxy denies anything
    # not listed here (deny by default).
    network_allowlist: tuple[NetworkAllow, ...] = ()
    env_allowlist: tuple[str, ...] = DEFAULT_ENV_ALLOWLIST
    resources: ResourceLimits = field(default_factory=lambda: _default_limits())
    # Phase 4 (ADR-010, ARCHITECTURE section 12, S-015/S-021/S-025/S-026):
    # the validated, immutable capability policy. Defaults to the documented
    # v0.1 policy; when supplied it is validated here (host-side, before
    # any session) and its resource declarations must be consistent with
    # the config's resource limits (single source of truth - ADR-007).
    policy: Policy = field(default_factory=Policy.default)

    # -- construction -------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict) -> RuntimeConfig:
        """Build + strictly validate from a dict. Rejects unknown fields,
        bad values, and unsupported modes with a deterministic
        ``ConfigError`` naming the offending field."""
        if not isinstance(data, dict):
            raise ConfigError("configuration must be a mapping")

        unknown = sorted(set(data) - {
            "mode", "workspace", "network_mode", "network_allowlist",
            "env_allowlist", "resources", "policy"})
        if unknown:
            raise ConfigError(
                f"unknown configuration field(s): {', '.join(unknown)} - "
                "security-critical fields must be explicit")

        mode = _parse_mode(data.get("mode"))
        workspace = _parse_workspace(data.get("workspace"))
        network_mode = _parse_network_mode(data.get("network_mode", "deny"))
        network_allowlist = _parse_network_allowlist(
            data.get("network_allowlist"))
        # Deny-by-construction sessions cannot carry allowlisted
        # destinations: a non-empty allowlist under deny mode is a
        # contradiction rejected here (fail closed, never a silent
        # ignore of the allowlist).
        if network_mode == "deny" and network_allowlist:
            raise ConfigError(
                "network_allowlist: entries require network_mode=\"allowlist\" "
                "- a deny-by-construction session cannot have allowlisted "
                "destinations")
        env_allowlist = _parse_env_allowlist(data.get("env_allowlist"))
        resources = _parse_resources(data.get("resources"))
        policy = _parse_policy(data.get("policy"))
        _check_policy_resources_consistent(policy, resources)
        return cls(mode=mode, workspace=workspace, network_mode=network_mode,
                   network_allowlist=network_allowlist,
                   env_allowlist=env_allowlist, resources=resources,
                   policy=policy)

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
    if not isinstance(value, str):
        raise ConfigError(
            f"network_mode: expected a string, got {type(value).__name__} "
            "- network is deny by construction")
    if value not in SUPPORTED_NETWORK_MODES:
        raise ConfigError(
            f"network_mode: {value!r} is not supported "
            f"(supported: {', '.join(sorted(SUPPORTED_NETWORK_MODES))}) - "
            "network is deny by construction unless allowlist is selected")
    return value


def _parse_network_allowlist(value) -> tuple[NetworkAllow, ...]:
    """Strictly validate the destination allowlist (S-021: unknown fields
    are rejected, never ignored; malformed entries fail closed).

    Rules:
    - A list/tuple of mappings, each exactly {host, port, allow_private}.
    - host: a hostname or a strict IPv4 literal (shared grammar with the
      proxy). An IPv4 literal that the proxy would ALWAYS deny (loopback,
      link-local, metadata, multicast, ...) is rejected here - a dead
      allowlist entry is a configuration error, never a silent no-op.
      Private ranges are rejected unless ``allow_private`` is set (the
      proxy relaxes only that class; everything else stays denied).
    - port: an integer in [1, 65535].
    - Duplicate host+port entries are rejected (a duplicate cannot carry
      a different meaning).
    """
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise ConfigError(
            "network_allowlist: expected a list of destination entries")
    out: list[NetworkAllow] = []
    for i, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise ConfigError(
                f"network_allowlist[{i}]: expected a mapping with host, port "
                "and optional allow_private")
        unknown = sorted(set(entry) - {"host", "port", "allow_private"})
        if unknown:
            raise ConfigError(
                f"network_allowlist[{i}]: unknown field(s): "
                f"{', '.join(unknown)} - security-critical allowlist fields "
                "must be explicit")
        host = entry.get("host")
        if not isinstance(host, str) or not host.strip():
            raise ConfigError(
                f"network_allowlist[{i}]: host must be a non-empty string")
        host = host.strip()
        if not validate_host(host):
            raise ConfigError(
                f"network_allowlist[{i}]: malformed host {host!r} (a "
                "hostname or IPv4 literal is required)")
        port = entry.get("port")
        if isinstance(port, bool) or not isinstance(port, int):
            raise ConfigError(
                f"network_allowlist[{i}]: port must be an integer, got "
                f"{port!r}")
        if not 1 <= port <= 65535:
            raise ConfigError(
                f"network_allowlist[{i}]: port must be in [1, 65535], got "
                f"{port}")
        allow_private = entry.get("allow_private", False)
        if not isinstance(allow_private, bool):
            raise ConfigError(
                f"network_allowlist[{i}]: allow_private must be true/false, "
                f"got {allow_private!r}")
        blocked = is_allowed_allow_entry(host, allow_private)
        if blocked is not None:
            raise ConfigError(
                f"network_allowlist[{i}]: destination {host}:{port} can never "
                f"be forwarded - {blocked} (fail closed, no dead allowlist "
                "entries)")
        out.append(NetworkAllow(host=host, port=port,
                                allow_private=allow_private))
    seen = {
        (host.casefold() if not is_ipv4_literal(host) else host, e.port)
        for e in out for host in [e.host]
    }
    if len(seen) != len(out):
        raise ConfigError(
            "network_allowlist: duplicate host+port entries are not allowed")
    return tuple(out)


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
        # Step 11 policy (ARCHITECTURE.md section 11, ADR-009, S-034):
        # the six constructed variables are the COMPLETE v0.1 supported
        # environment set. Anything beyond them has no value source in
        # v0.1 (secret/environment-value injection is explicitly deferred),
        # so accepting the name would be a silent no-op - reject it.
        if name not in DEFAULT_ENV_ALLOWLIST:
            raise ConfigError(
                f"env_allowlist: {name!r} is not a supported v0.1 "
                "environment variable (only PATH, HOME, LANG, LC_ALL, TERM, "
                "TMPDIR are constructed; value injection is deferred)")
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


def _parse_policy(value) -> Policy:
    """Parse an optional policy document. None -> the documented v0.1
    default policy; a dict is validated strictly (PolicyError ->
    ConfigError with a deterministic message naming the field, S-021); an
    already-validated ``Policy`` (e.g. loaded by the CLI from a file) is
    passed through unchanged - the strongest accepted input form."""
    if value is None:
        return Policy.default()
    if isinstance(value, Policy):
        return value
    try:
        return Policy.from_dict(value)
    except PolicyError as e:
        raise ConfigError(str(e)) from None


def _check_policy_resources_consistent(policy: Policy,
                                       resources: ResourceLimits) -> None:
    """S-021/S-027: a policy may declare resource limits, but the
    AUTHORITATIVE enforcement stays in RuntimeConfig.resources (ADR-007).
    A policy declaring a limit that conflicts with the config's limits is
    REJECTED - never a silent override and never a second enforcement
    source. Only the declared (non-defaulted) keys are compared."""
    if policy.resources is None:
        return
    config_values = {
        "cpu_seconds": resources.cpu_seconds,
        "memory_mb": resources.memory_mb,
        "disk_mb": resources.disk_mb,
        "processes": resources.processes,
        "open_files": resources.open_files,
        "output_mb": resources.output_mb,
        "wall_time_seconds": resources.wall_time_seconds,
        "cpu_quota_percent": resources.cpu_quota_percent,
        "io_mbps": resources.io_mbps,
    }
    for key, value in policy.resources.items():
        if config_values.get(key) != value:
            raise ConfigError(
                f"policy: resources.{key} = {value} conflicts with the "
                f"configuration's resource limit {key} = "
                f"{config_values.get(key)} - resource enforcement is "
                "single-sourced (ADR-007); align the policy or the config")


def _default_limits() -> ResourceLimits:
    # ARCHITECTURE.md section 9 example defaults (design section 17)
    return ResourceLimits(
        cpu_seconds=300, memory_mb=4096, disk_mb=10240, processes=256,
        open_files=4096, output_mb=50, wall_time_seconds=900)
