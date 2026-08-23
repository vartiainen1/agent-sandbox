"""Credential and socket isolation verification (Phase 1 Step 12,
ARCHITECTURE.md sections 7/11, ADR-009, S-003, S-004, T-016, T-019,
T-020, T-022).

Host credentials and control sockets are ABSENT BY CONSTRUCTION - the
mechanisms that make them absent are the boundary itself (fresh rootfs
with no host mounts, workspace as a copy, the approved six-variable
environment with no host values, seccomp denying the socket syscall
class). Step 12 VERIFIES that the boundary actually provides the
credential/socket isolation the architecture promises, and fails closed
on ANY exposure:

- credential paths and control-socket paths must NOT be reachable from
  the sandbox view (filesystem reachability, not just env-variable
  removal - S-003/S-004 "by construction");
- no socket/credential-related environment variable may survive (the
  Step 11 sanitized env has exactly the approved six - nothing more);
- a Unix-socket creation attempt inside the workload must be DENIED
  (seccomp denies the socket syscall class - socket/connect/bind are
  not in the derived 70-syscall allowlist, policy.md section 3).

Absence-by-boundary is the preferred property; this module's checks are
the verification of that property, never the enforcement themselves.
Secret injection remains explicitly OUT OF SCOPE for v0.1 (no value
source exists - config rejects anything beyond the six env vars).

The module is Windows import-safe; all filesystem/env access goes
through seams so tests can inject failures deterministically.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from agent_sandbox.isolation.errors import NamespaceSetupError

# Host credential paths that must NOT exist in the sandbox view. These
# are the canonical credential stores / control surfaces the architecture
# names (S-003/S-004, design section 14/16): SSH, cloud, K8s, agent and
# container-runtime sockets, credential managers. Capability-oriented:
# the assertion is absence/denial, not a particular runner's layout.
# The sandbox HOME is /home (Step 11) and the rootfs has no /root, /var
# or /run tree - so all of these resolve to nothing by construction.
CREDENTIAL_PATHS = (
    # SSH credentials / agent sockets
    "/home/.ssh", "/root/.ssh", "/etc/ssh",
    "/run/user/*/gnupg/S.gpg-agent.ssh", "/tmp/ssh-*",
    # cloud credentials
    "/home/.aws", "/root/.aws", "/home/.config",
    # Kubernetes
    "/home/.kube", "/root/.kube", "/etc/kubernetes",
    # container runtime / control sockets
    "/var/run/docker.sock", "/run/docker.sock",
    "/run/containerd/containerd.sock", "/var/run/containerd",
    # host control directories that must not exist as host mounts
    "/var/run", "/run", "/var/lib/docker", "/root",
)

# Environment variables that point at credentials or control sockets.
# The Step 11 sanitized environment contains EXACTLY the approved six
# variables - none of these can survive; the check is the verification
# (and a regression guard: if a future change ever reintroduced a host
# env value, this catches it).
SOCKET_ENV_NAMES = (
    "SSH_AUTH_SOCK", "SSH_AGENT_PID",
    "DOCKER_HOST", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY",
    "KUBECONFIG", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN", "AWS_SHARED_CREDENTIALS_FILE",
    "GITHUB_TOKEN", "GH_TOKEN", "GIT_ASKPASS", "GIT_SSH_COMMAND",
)


@dataclass(frozen=True)
class CredentialState:
    """Verified credential/socket isolation state (sandbox view)."""

    reachable: tuple[str, ...] = ()       # credential paths that exist
    socket_env: tuple[str, ...] = ()      # socket env vars that survived
    socket_creation_denied: bool = False  # seccomp denied socket(2)


# -- seams (patchable for deterministic failure injection) --------------

def _lexists_impl(path: str) -> bool:
    return os.path.lexists(path)


def _environ_impl() -> dict[str, str]:
    return dict(os.environ)


def _socket_creation_denied_impl() -> bool:
    """True iff creating a Unix socket is denied in this process.

    Under the Step 8 filter the socket syscall class is denied
    (RET_ERRNO|EPERM) - ``socket.socket(AF_UNIX)`` raises PermissionError
    before any connection can be attempted. On hosts without the filter
    (supervisor side) the creation succeeds and the check reports False
    for the workload view - the supervisor-side probe never installs the
    filter, so this check is meaningful only inside the sandbox.
    """
    try:
        import socket as _socket_mod
        s = _socket_mod.socket(_socket_mod.AF_UNIX, _socket_mod.SOCK_STREAM)
        s.close()
        return False  # socket creation SUCCEEDED - not denied
    except PermissionError:
        return True   # denied by seccomp - the enforced property
    except OSError:
        return True   # denied (no AF_UNIX support etc.) - still denied


# -- verification -------------------------------------------------------

def verify_no_credential_paths(paths: tuple[str, ...] = CREDENTIAL_PATHS
                               ) -> tuple[str, ...]:
    """Return the subset of ``paths`` REACHABLE in this process view.

    Any hit is a boundary violation (S-003/S-004): the sandbox must not
    be able to reach a host credential or control socket. Runs inside
    the sandbox (the workload view); the supervisor-side callers run it
    host-side only for the module's own seams/tests.
    """
    reachable = tuple(sorted({p for p in paths if _lexists_impl(p)}))
    if reachable:
        raise NamespaceSetupError(
            "credential/socket isolation violation: reachable host "
            f"path(s): {', '.join(reachable)} - fail closed, workload "
            "not executed")
    return ()


def verify_no_socket_env(env: dict[str, str] | None = None
                         ) -> tuple[str, str]:
    """Verify no socket/credential env variable survived sanitization.

    ``env`` defaults to the live process environment (for the workload
    view); the Step 11 sanitized env has exactly the six approved
    variables, so nothing here can be present. Returns the surviving
    names (empty on success). Raises NamespaceSetupError on any hit -
    fail closed.
    """
    live = env if env is not None else _environ_impl()
    hits = tuple(sorted(name for name in SOCKET_ENV_NAMES
                        if name in live and live[name] != ""))
    if hits:
        raise NamespaceSetupError(
            "credential/socket isolation violation: environment "
            f"variable(s) survived sanitization: {', '.join(hits)} - "
            "fail closed, workload not executed")
    return ()


def verify_socket_creation_denied() -> bool:
    """Verify Unix-socket creation is denied in this process view.

    Inside the sandbox the Step 8 filter denies the socket syscall class
    (EPERM) - this is the kernel-enforced property. Outside (probe,
    supervisor) the check reports the actual state without failing: the
    sandbox-internal tests assert the denied result. Returns whether
    creation was denied.
    """
    return _socket_creation_denied_impl()


def verify_credential_isolation(require_socket_denial: bool = False
                                ) -> CredentialState:
    """Full Step 12 verification for the workload view.

    - credential/control-socket paths must be unreachable (S-003/S-004);
    - no socket/credential env variable may survive (S-034, Step 11);
    - Unix-socket creation must be denied by the filter
      (``require_socket_denial`` - set True only inside the sandbox where
      the filter is installed).

    Any violation raises NamespaceSetupError with the precise reason;
    the returned state is the verified view.
    """
    reachable = verify_no_credential_paths()
    socket_env = verify_no_socket_env()
    denied = verify_socket_creation_denied()
    if require_socket_denial and not denied:
        raise NamespaceSetupError(
            "credential/socket isolation violation: Unix-socket creation "
            "was NOT denied inside the sandbox - the filter is not "
            "enforcing the socket class, fail closed")
    return CredentialState(reachable=reachable, socket_env=socket_env,
                           socket_creation_denied=denied)


def verify_isolated_env(env: dict[str, str]) -> CredentialState:
    """Probe-side verification: the CONSTRUCTED (sanitized) environment
    must contain no socket/credential variables. Used by the ENVIRONMENT
    probe (no filter, no boundary - the socket-creation and path checks
    are sandbox-internal). Returns the verified state (never raises for
    the absent-by-construction properties unless violated)."""
    socket_env = verify_no_socket_env(env)
    return CredentialState(socket_env=socket_env)
