"""Bounded stdout/stderr enforcement (Phase 1 Step 13, item 18).

Policy (S-037, ARCHITECTURE section 9, ADR-007): the workload must not
be able to generate unlimited output that exhausts host resources. The
supervisor reads stdout/stderr through a bounded pipe; after the limit
it terminates the session with a truncation notice.

Trust boundary: the bounded read is SUPERVISOR-side (trusted). The
workload never controls the pipe, the limit, or the termination. The
pipe is the only output channel into the supervisor, so the bound
cannot be bypassed by the workload - once the read end is closed past
the limit, any further write by the workload's process tree hits
EPIPE/SIGPIPE and is kernel-enforced.

Import safety: this module imports only stdlib pieces available on
every platform; the Linux-only behavior is exercised only when a
caller actually reads a pipe (never at import time).
"""

from __future__ import annotations

import os
import signal
from collections.abc import Callable

# KiB/MiB conversions kept explicit (no ambiguous "1024 vs 1000").
KIB = 1024
MIB = KIB * KIB

_DEFAULT_CHUNK = 64 * KIB

# POSIX SIGKILL; Windows has no such signal (the kill path is only ever
# taken on Linux - the fallback keeps module import and host-side tests
# safe on every platform).
SIGKILL = getattr(signal, "SIGKILL", 9)


class OutputLimitError(RuntimeError):
    """Raised when the bounded read itself fails (fail closed: a broken
    output channel must never look like a clean, complete run)."""


def truncation_notice(limit_mb: int) -> str:
    """Deterministic truncation notice appended when the bound was hit.

    S-037: after the limit the supervisor terminates the session with a
    truncation notice, so the caller can distinguish a truncated run
    from a complete one.
    """
    return (f"\n[output truncated: exceeded the {limit_mb} MiB output "
            "limit - session terminated with a truncation notice (S-037)]\n")


def read_bounded(read_fd: int, limit_bytes: int,
                 chunk_size: int = _DEFAULT_CHUNK,
                 read_impl: Callable[[int, int], bytes] = os.read
                 ) -> tuple[bytes, bool]:
    """Read at most ``limit_bytes`` from ``read_fd``.

    Returns ``(data, truncated)`` where ``truncated`` is True iff the
    limit was reached before EOF. The caller (supervisor) must then
    terminate the session - this function never silently drops output
    and never pretends a partial read is complete.

    ``read_impl`` is a seam for tests; the default is the real os.read.
    """
    if limit_bytes < 0:
        raise OutputLimitError(
            f"bounded read requires limit_bytes >= 0, got {limit_bytes}")
    if limit_bytes == 0:
        return b"", True
    # Read up to limit_bytes + 1: the extra byte is the EOF probe.
    # Exactly-at-limit with EOF (writer closed) is a COMPLETE run
    # (truncated=False); any data beyond the limit is truncation. The
    # probe is deterministic - no select/peek races on the read end.
    chunks: list[bytes] = []
    total = 0
    while True:
        remaining = limit_bytes + 1 - total
        if remaining <= 0:
            break  # read limit+1 bytes: strictly more than the limit
        try:
            chunk = read_impl(read_fd, min(chunk_size, remaining))
        except OSError as e:
            raise OutputLimitError(
                f"bounded read failed: {e} - fail closed, the output "
                "channel is broken") from e
        if not chunk:
            break  # EOF
        chunks.append(chunk)
        total += len(chunk)
    data = b"".join(chunks)[:limit_bytes]
    return data, total > limit_bytes


def collect_bounded(read_fd: int, child_pid: int, limit_bytes: int,
                    kill_impl: Callable[[int, int], None] = os.kill,
                    read_impl: Callable[[int, int], bytes] = os.read
                    ) -> tuple[bytes, bool]:
    """Supervisor-side bounded collection: read up to the limit, then
    terminate the session.

    On truncation the supervisor closes the read end and kills the
    controlled child (the workload's process tree). Closing the read end
    makes any further write by the workload hit EPIPE/SIGPIPE - the
    kernel enforces the bound; the workload cannot bypass it. The
    supervisor never keeps reading past the limit (that is exactly the
    resource exhaustion S-037 forbids).

    Returns ``(captured_bytes, truncated)``. The caller appends the
    truncation notice when ``truncated`` is True.
    """
    data, truncated = read_bounded(read_fd, limit_bytes, read_impl=read_impl)
    if truncated:
        # Terminate the session: the workload must not keep running with
        # an unreadable output channel. Closing the read end first makes
        # the next workload write fail (EPIPE/SIGPIPE); the kill is the
        # deterministic session termination.
        try:
            os.close(read_fd)
        except OSError:
            pass
        try:
            kill_impl(child_pid, SIGKILL)
        except ProcessLookupError:
            pass  # already gone - the boundary still holds
    return data, truncated
