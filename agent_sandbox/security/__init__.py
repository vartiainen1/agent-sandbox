"""Security initialization and policy - TRUSTED host-side code.

This package is part of the trusted computing base (ARCHITECTURE.md
section 3.1). It runs BEFORE any untrusted code exists. The workload never
executes code from this package; it only ever runs inside the isolated
environment the security init establishes.
"""
