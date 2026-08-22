"""External wall-clock timeout enforcement (Phase 1 Step 14, item 19).

Policy (S-036, ADR-011, ARCHITECTURE section 13): timeouts are enforced
EXTERNALLY by the supervisor and cannot be disabled by the workload.
The deadline lives entirely in the supervisor process (``time.monotonic``
+ ``select`` with the remaining time) - the workload has no shared
clock, no capability, and no channel to touch it, so it cannot evade or
reset the deadline.

Trust boundary: this module is SUPERVISOR-side (trusted). It combines
the Step 13 bounded output read with the wall-clock deadline in one
supervisor loop: output is read at most up to ``limit_bytes``, and the
wait for each chunk is bounded by the deadline. On deadline expiry the
supervisor terminates the session (closes the read end + kills the
controlled child) and reports the timeout state - expiration ABORTS the
session, it is never merely a status flag.

Import safety: imports only stdlib pieces available on every platform;
the Linux-only select/read behavior is exercised only when a caller
actually collects a session's output (never at import time).
"""

from __future__ import annotations

import os
import select
import time
from collections.abc import Callable

from agent_sandbox.isolation.output import SIGKILL

_DEFAULT_CHUNK = 64 * 1024


class TimeoutEnforcementError(RuntimeError):
    """Raised when the supervisor-side timer/collection itself fails
    (fail closed: a broken timer must never look like a clean run)."""


def timeout_notice(wall_time_seconds: int) -> str:
    """Deterministic timeout notice appended when the deadline expired
    (S-036): the caller can distinguish a timed-out run from a
    complete or truncated one."""
    return (f"\n[workload timed out after {wall_time_seconds} seconds - "
            "session terminated by the external supervisor timer (S-036)]\n")


def collect_session_output(
    read_fd: int,
    child_pid: int,
    limit_bytes: int | None,
    wall_time_seconds: int,
    chunk_size: int = _DEFAULT_CHUNK,
    clock_impl: Callable[[], float] = time.monotonic,
    select_impl: Callable = select.select,
    read_impl: Callable[[int, int], bytes] = os.read,
    kill_impl: Callable[[int, int], None] = os.kill,
) -> tuple[bytes, bool, bool]:
    """Supervisor-side session collection with an external deadline.

    Reads stdout/stderr up to ``limit_bytes`` (None = unbounded, for the
    legacy seam) while enforcing the wall-clock deadline: each wait for a
    chunk is bounded by the remaining time. Returns
    ``(data, truncated, timed_out)``:

    - ``truncated``  - the OUTPUT bound was hit first (S-037);
    - ``timed_out``  - the DEADLINE expired first (S-036);
    - both False     - EOF reached within the deadline (complete run).

    On truncation OR timeout the supervisor terminates the session:
    closes the read end (the workload's next write then fails with
    EPIPE/SIGPIPE) and kills the controlled child. The workload cannot
    evade the deadline - it lives entirely in this process.

    ``clock_impl``/``select_impl``/``read_impl``/``kill_impl`` are seams
    for host-side tests; the defaults are the real syscalls.
    """
    if wall_time_seconds < 1:
        raise TimeoutEnforcementError(
            f"timeout requires wall_time_seconds >= 1, got {wall_time_seconds}")
    if limit_bytes is not None and limit_bytes < 0:
        raise TimeoutEnforcementError(
            f"bounded read requires limit_bytes >= 0, got {limit_bytes}")
    if limit_bytes == 0:
        # Zero output bound: nothing may be captured - truncate now.
        _terminate_session(read_fd, child_pid, kill_impl)
        return b"", True, False

    deadline = clock_impl() + wall_time_seconds
    chunks: list[bytes] = []
    total = 0
    truncated = False
    timed_out = False
    while True:
        if limit_bytes is not None:
            remaining = limit_bytes + 1 - total
            if remaining <= 0:
                truncated = True
                break
            read_n = min(chunk_size, remaining)
        else:
            read_n = chunk_size
        left = deadline - clock_impl()
        if left <= 0:
            timed_out = True
            break
        try:
            ready, _, _ = select_impl([read_fd], [], [], left)
        except OSError as e:
            raise TimeoutEnforcementError(
                f"session collection failed: {e} - fail closed, the "
                "output channel is broken") from e
        if not ready:
            timed_out = True
            break
        try:
            chunk = read_impl(read_fd, read_n)
        except OSError as e:
            raise TimeoutEnforcementError(
                f"session collection failed: {e} - fail closed, the "
                "output channel is broken") from e
        if not chunk:
            break  # EOF - complete run within the deadline
        chunks.append(chunk)
        total += len(chunk)

    data = b"".join(chunks)
    if limit_bytes is not None:
        data = data[:limit_bytes]
    if truncated or timed_out:
        _terminate_session(read_fd, child_pid, kill_impl)
    return data, truncated, timed_out


def _terminate_session(read_fd: int, child_pid: int,
                       kill_impl: Callable[[int, int], None]) -> None:
    """Close the read end (further workload writes -> EPIPE/SIGPIPE) and
    kill the controlled child - the deterministic session termination.
    A child that already exited is tolerated (the boundary still holds)."""
    try:
        os.close(read_fd)
    except OSError:
        pass
    try:
        kill_impl(child_pid, SIGKILL)
    except OSError:
        # Already gone (ProcessLookupError on Linux; OSError on Windows
        # for an invalid pid) - the boundary still holds.
        pass
