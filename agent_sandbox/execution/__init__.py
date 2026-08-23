"""Execution request layer (ADR-013, interface phase sub-phase A).

The interfaces (CLI, later MCP) are THIN front-ends over the single
enforcement core. The only code path that touches the boundary is:

    RuntimeSession.execute(ExecutionRequest) -> run_in_sandbox(...)

Nothing here carries security policy or enforcement logic; nothing here
can bypass ``SecurityInitializer`` or the READY/REFUSED session state.

This module provides the two pieces the interfaces share:

- request validation (deterministic, no shell involvement: an
  ``ExecutionRequest`` is an ARGUMENT VECTOR passed verbatim into the
  sandbox - v0.1 never interprets a shell command string);
- the execve workload bridge: the CLI/MCP command is represented by a
  workload function that ``execve(2)``s the requested argv INSIDE the
  already-established sandbox (execve is in the 69-syscall allowlist;
  bare executable names resolve via ``execvpe`` against the
  sandbox-only sanitized PATH).
  stdout/stderr and exit status continue through the existing Step
  13-15 bounded-output, timeout, and process-tree machinery. There is
  NO host-side command execution fallback: an unavailable command is a
  deterministic in-sandbox failure (the execve raises, the workload
  reports ``FAIL workload: ...``, exit != 0) - the command is never
  executed outside the sandbox.

Import safety: imports only stdlib pieces available on every platform;
``os.execvpe`` is only ever called from inside the sandbox (child B).
"""

from __future__ import annotations

import os
from collections.abc import Callable

from agent_sandbox.models import ExecutionRequest

__all__ = ["command_workload", "validate_request"]


def validate_request(request: ExecutionRequest) -> ExecutionRequest:
    """Re-validate at the interface boundary (the request dataclass
    validates at construction too - this is the explicit gate the
    interfaces call). Returns the request unchanged; raises
    ``ExecutionRequestError`` with a deterministic reason on invalid
    input (empty command, non-string argv, NUL bytes). Never
    interprets shell metacharacters - argv is data, not a shell
    string."""
    # ExecutionRequest.__post_init__ already validated; constructing a
    # fresh instance is the deterministic re-check (frozen dataclass -
    # no post-hoc mutation possible).
    return ExecutionRequest(command=request.command)


def command_workload(request: ExecutionRequest) -> Callable:
    """The execve bridge: a workload function for ``run_in_sandbox``
    that execs the requested argv inside the boundary.

    The bridge runs in sandbox PID 1 AFTER every mandatory mechanism is
    established (Steps 2-15). ``os.execvpe`` replaces PID 1 with the
    command: its stdout/stderr flow through the bounded pipes (S-037),
    the external deadline applies (S-036), and its exit status
    propagates through the existing waitpid chain (S-014/S-038 cleanup
    still verifies absence afterwards). ``execvpe`` resolves bare
    executable names against PATH (the documented v0.1 argv-only
    contract: ``python3 -c '...'``, ``git init``, ``/bin/sh -c '...'``)
    - the PATH here is the sanitized sandbox-only
    ``/usr/local/bin:/usr/bin:/bin``, so resolution cannot reach a host
    path. If the executable does not exist or cannot be run, the
    workload reports a deterministic ``FAIL workload:`` failure - the
    command is NEVER executed on the host (no fallback, no subprocess,
    no shell).

    ``os.environ`` at this point IS the sanitized six-variable sandbox
    environment (Step 11 replaced it in PID 1 before the workload) - so
    the exec'd command inherits exactly the approved environment."""
    command = request.command

    def workload(state, fs):
        os.execvpe(command[0], list(command), os.environ)

    return workload
