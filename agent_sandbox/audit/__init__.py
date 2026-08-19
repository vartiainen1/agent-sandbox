"""Structured audit events - host-side recorder, outside the sandbox.

Audit is observation, NOT enforcement (SECURITY_SPEC.md S-024): security
does not depend on logging. The recorder is part of the trusted host-side
surface; the workload can never write, truncate, or read the audit
stream. Implemented in Phase 7; the package exists now to keep the
security boundary unambiguous (audit is outside the sandbox by design).
"""
