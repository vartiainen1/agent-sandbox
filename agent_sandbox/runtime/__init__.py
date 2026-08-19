"""Runtime - the TRUSTED host-side supervisor (session ownership).

The supervisor is the only component that can touch the security boundary
(ARCHITECTURE.md section 3.1, 6). It creates the sandbox, owns the session
lifecycle, and is a separate process from the untrusted workload.
"""
