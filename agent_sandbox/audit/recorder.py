"""Minimal host-side JSONL audit recorder (ADR-012, interface phase
sub-phase A).

Smallest useful ADR-012 recorder: session-correlated structured events
(S-022/S-023) covering at minimum session creation, the initialization
decision, the execution request, and the execution result or refusal.

Security properties:

- HOST-SIDE ONLY and OUTSIDE THE SANDBOX: the audit file is written by
  the supervisor/CLI process, never by the workload.
- NO audit file descriptor is ever open across the fork boundary:
  ``record()`` opens, appends one JSON line, and closes per event. The
  sandbox children (child A/B) therefore can never inherit an audit fd
  and can never tamper with or read the audit stream (ADR-012).
- OBSERVATION ONLY, NEVER ENFORCEMENT (S-024): ``record()`` never
  raises into the execution path. A recording failure is itself
  reported where possible (the caller may surface it), and execution
  continues - logging failure never equals protection failure. If a
  future policy makes audit availability MANDATORY for an operation,
  that policy must fail closed explicitly; no such policy exists in
  v0.1, so recorder failure is classified as observational.

Import safety: json/os/time are available on every platform; nothing
Linux-specific happens at import time.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

# Event names (ADR-012 design section 29 event classes, minimal set).
SESSION_CREATED = "session_created"          # session + mode
INIT_DECISION = "init_decision"              # ok / refused + stage + reason
POLICY_LOADED = "policy_loaded"              # policy version + capability count
POLICY_DECISION = "policy_decision"          # capability + allowed + reason (S-015)
EXECUTION_REQUEST = "execution_request"      # argv vector
EXECUTION_RESULT = "execution_result"        # exit code + enforcement state
EXECUTION_REFUSED = "execution_refused"      # refusal reason + state


class AuditRecorder:
    """Appends one JSON line per event to ``path``. Never raises on
    write failure (observational - S-024)."""

    def __init__(self, path: str):
        self._path = path

    @property
    def path(self) -> str:
        return self._path

    def record(self, session_id: str, event: str, **fields: Any) -> bool:
        """Append one structured event: ``{"ts", "session_id", "event",
        **fields}`` as a single JSONL line. Returns True on success,
        False on failure - NEVER raises (a recording failure must not
        create an alternate execution path or block enforcement)."""
        try:
            line = {
                "ts": time.time(),
                "session_id": session_id,
                "event": event,
            }
            line.update(fields)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(line, sort_keys=True) + "\n")
        except OSError:
            return False
        return True
