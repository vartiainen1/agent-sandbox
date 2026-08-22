"""Phase E (implementation.md Phase 15) deterministic fuzz harness package.

Stdlib-only by design (zero new dependencies - TCB rule): mutation-based,
fixed-seed, bounded-iteration fuzzing of the security-sensitive parsers and
interfaces. Host-side evidence: these targets exercise the validation and
protocol layers that run on the trusted side before any boundary work; the
kernel boundary remains covered by the native/adversarial suites.
"""
