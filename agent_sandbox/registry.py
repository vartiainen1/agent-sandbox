"""Host-side session registry for the CLI surface (Phase B).

One-shot CLI invocations cannot hold in-memory sessions, so ``create``
persists a validated session manifest under a caller-owned state
directory and ``exec``/``status``/``diff``/``logs``/``destroy`` re-open
it by session id. The manifest is the ONLY durable session state:

- It stores the validated, immutable configuration snapshot needed to
  rebuild the exact same ``RuntimeConfig`` (mode, workspace, network
  posture, env allowlist, resource limits, and the FROZEN policy
  document - S-025/S-026: the policy is re-loaded from the manifest, so
  a later edit of the source policy file cannot change a created
  session).
- Read-back is STRICT: the manifest is treated as untrusted input and
  re-validated through ``RuntimeConfig.from_dict`` (S-021) - a
  malformed or tampered manifest fails closed and never executes.
- ``last_execution`` records the most recent run's sandbox PID 1 and
  HARDENED cgroup path (observational lifecycle metadata) so ``destroy``
  can terminate + verify an orphaned sandbox via the existing
  ``lifecycle`` mechanism (S-038) if the caller's process was interrupted
  mid-run.

Trust boundary: this is TRUSTED supervisor-side state (the CLI is the
supervisor). It is the caller's own state (like ADR-012 audit files),
never mounted into the sandbox, and never reachable by the workload.
Secrets are never stored here; the policy/capability view is the
documented observable surface (S-040).

Import safety: stdlib only; nothing Linux-specific at import time.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from agent_sandbox.config import RuntimeConfig

SCHEMA = 1

# Session ids are the S-023 identity: a uuid4 hex string (32 lowercase
# hex chars). Anything else is rejected before any filesystem access -
# a session id is NEVER used as a path component without this check
# (defense against traversal in the caller-owned state directory).
_SESSION_ID_RE = re.compile(r"^[0-9a-f]{32}$")

# Manifest fields (schema 1). Unknown fields are rejected on read
# (security-critical state must be explicit, S-021 spirit) - never a
# silent ignore.
_MANIFEST_FIELDS = frozenset({
    "schema", "session_id", "created", "mode", "workspace",
    "network_mode", "env_allowlist", "resources", "policy",
    "last_execution",
})


class RegistryError(ValueError):
    """A session-state problem (unknown session, malformed manifest,
    registry I/O failure). Message is deterministic and user-facing."""


def state_base_dir() -> str:
    """The caller-owned state directory (default ~/.agent-sandbox;
    AGENT_SANDBOX_STATE_DIR overrides for tests and deployments)."""
    return os.environ.get("AGENT_SANDBOX_STATE_DIR") or os.path.join(
        os.path.expanduser("~"), ".agent-sandbox")


def is_valid_session_id(session_id: Any) -> bool:
    return (isinstance(session_id, str)
            and _SESSION_ID_RE.match(session_id) is not None)


def session_dir(base: str, session_id: str) -> str:
    return os.path.join(base, "sessions", session_id)


def manifest_path(base: str, session_id: str) -> str:
    return os.path.join(session_dir(base, session_id), "manifest.json")


def session_audit_path(base: str, session_id: str) -> str:
    """The per-session ADR-012 audit file (host-side, observational)."""
    return os.path.join(session_dir(base, session_id), "audit.jsonl")


def ensure_session_dir(base: str, session_id: str) -> None:
    """Create the session's state directory (0700 on POSIX). Fails
    closed on an invalid id - never a bare path join of caller input."""
    if not is_valid_session_id(session_id):
        raise RegistryError(
            f"session id {session_id!r} is invalid - expected a 32-hex "
            "uuid string (S-023 identity)")
    path = session_dir(base, session_id)
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
    except OSError as e:
        raise RegistryError(
            f"cannot create session state directory: {e}") from e


def _atomic_write(path: str, payload: dict) -> None:
    """Write the manifest atomically (tmp + os.replace) with 0600 on
    POSIX. A torn write must never leave a half-written manifest that a
    later exec could misread."""
    tmp = path + ".tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, sort_keys=True)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        os.replace(tmp, path)
    except OSError as e:
        raise RegistryError(
            f"cannot write session manifest: {e}") from e


def save_session(base: str, session_id: str, config: RuntimeConfig,
                 created: str,
                 last_execution: dict | None = None) -> None:
    """Persist a validated session (written by ``create``). The stored
    snapshot is exactly the validated configuration; the policy document
    is stored frozen (S-025/S-026 - re-opened sessions use the identical
    policy even if the source file changes later)."""
    ensure_session_dir(base, session_id)
    policy_doc: dict = {"version": config.policy.version,
                        "capabilities": dict(config.policy.capabilities)}
    if config.policy.resources is not None:
        policy_doc["resources"] = dict(config.policy.resources)
    manifest = {
        "schema": SCHEMA,
        "session_id": session_id,
        "created": created,
        "mode": config.mode.value,
        "workspace": config.workspace,
        "network_mode": config.network_mode,
        "env_allowlist": list(config.env_allowlist),
        "resources": {
            "cpu_seconds": config.resources.cpu_seconds,
            "memory_mb": config.resources.memory_mb,
            "disk_mb": config.resources.disk_mb,
            "processes": config.resources.processes,
            "open_files": config.resources.open_files,
            "output_mb": config.resources.output_mb,
            "wall_time_seconds": config.resources.wall_time_seconds,
            "cpu_quota_percent": config.resources.cpu_quota_percent,
            "io_mbps": config.resources.io_mbps,
        },
        "policy": policy_doc,
        "last_execution": last_execution,
    }
    _atomic_write(manifest_path(base, session_id), manifest)


def load_manifest(base: str, session_id: Any) -> dict | None:
    """Load + structurally validate a session manifest. Returns None for
    an unknown session; raises RegistryError for an invalid id or a
    structurally malformed manifest (fail closed - never executed)."""
    if not is_valid_session_id(session_id):
        raise RegistryError(
            f"session id {session_id!r} is invalid - expected a 32-hex "
            "uuid string")
    path = manifest_path(base, session_id)
    try:
        with open(path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise RegistryError(f"cannot read session manifest: {e}") from e
    except ValueError as e:
        raise RegistryError(
            f"session manifest for {session_id} is malformed (invalid "
            f"JSON): {e} - fail closed, never executed") from e
    if not isinstance(manifest, dict):
        raise RegistryError(
            f"session manifest for {session_id} is malformed (not an "
            "object) - fail closed, never executed")
    unknown = sorted(set(manifest) - _MANIFEST_FIELDS)
    if unknown:
        raise RegistryError(
            f"session manifest for {session_id} has unknown field(s): "
            f"{', '.join(unknown)} - fail closed, never executed")
    if manifest.get("schema") != SCHEMA:
        raise RegistryError(
            f"session manifest for {session_id} has unsupported schema "
            f"{manifest.get('schema')!r} - fail closed, never executed")
    if manifest.get("session_id") != session_id:
        raise RegistryError(
            f"session manifest for {session_id} does not match its "
            "stored identity - fail closed, never executed")
    return manifest


def config_from_manifest(manifest: dict) -> RuntimeConfig:
    """Rebuild the exact validated RuntimeConfig from a manifest. The
    manifest is treated as UNTRUSTED input and re-validated through the
    strict config validator (S-021): mode, workspace, network posture,
    env allowlist, resource limits and the frozen policy document. A
    malformed or tampered manifest raises ConfigError - fail closed,
    never a silent downgrade."""
    data: dict = {
        "mode": manifest.get("mode"),
        "workspace": manifest.get("workspace"),
        "network_mode": manifest.get("network_mode", "deny"),
        "env_allowlist": manifest.get("env_allowlist"),
        "resources": manifest.get("resources"),
        "policy": manifest.get("policy"),
    }
    return RuntimeConfig.from_dict(data)


def update_last_execution(base: str, session_id: str,
                          sandbox_pid1: int | None,
                          cgroup_path: str | None) -> bool:
    """Record the most recent run's sandbox identity (observational
    lifecycle metadata for destroy). Returns False if the session no
    longer exists (already destroyed) - the run already completed, so
    there is nothing left to persist."""
    try:
        manifest = load_manifest(base, session_id)
    except RegistryError:
        return False
    if manifest is None:
        return False
    last: dict | None = None
    if sandbox_pid1 is not None:
        last = {"sandbox_pid1": sandbox_pid1,
                "cgroup_path": cgroup_path}
    manifest["last_execution"] = last
    try:
        _atomic_write(manifest_path(base, session_id), manifest)
        return True
    except RegistryError:
        return False


def remove_session(base: str, session_id: str) -> None:
    """Remove a session's durable state (registry dir + audit file).
    Raises RegistryError on I/O failure (never silently claims removal)."""
    if not is_valid_session_id(session_id):
        raise RegistryError(f"session id {session_id!r} is invalid")
    import shutil
    path = session_dir(base, session_id)
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return
    except OSError as e:
        raise RegistryError(
            f"cannot remove session state for {session_id}: {e}") from e


# Re-export for the CLI's policy document handling (single import site).
__all__ = [
    "RegistryError", "SCHEMA", "config_from_manifest", "ensure_session_dir",
    "is_valid_session_id", "load_manifest", "manifest_path",
    "remove_session", "save_session", "session_audit_path", "session_dir",
    "state_base_dir", "update_last_execution",
]
