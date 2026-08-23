# Release tooling — reproducibility + integrity

Implements RELEASE_CHECKLIST.md sections 11-12 (implementation.md section
24: "release artifacts reproducible where practical" and "release
integrity mechanisms configured"). Stdlib-only at runtime; zero new
dependencies (the PEP 517 backend is the setuptools already declared in
`pyproject.toml`).

## Commands

    python tools/release/build_release.py build            # deterministic sdist+wheel + SHA256SUMS into dist/
    python tools/release/build_release.py verify           # re-hash dist/ against SHA256SUMS (fail on mismatch)
    python tools/release/build_release.py reproducibility  # two clean builds must be byte-identical
    python tools/release/build_release.py sign             # detached-armor GPG signatures (fail closed w/o key)

Exit codes: `0` success; `1` build/verify/reproducibility failure;
`2` signing blocked (no key configured); `3` unexpected environment
failure. Every failure path is fail-closed - never a warning-and-continue.

## What "reproducible" means here

Two independent builds from two clean copies of the source tree must
produce **byte-identical** artifacts:

- The **wheel** is deterministic once `SOURCE_DATE_EPOCH` is pinned
  (setuptools/bdist_wheel honor it for zip timestamps) - verified by the
  reproducibility gate.
- The **sdist** embeds per-file pax mtime/atime/ctime records, uid/gid,
  uname/gname and a gzip header with the current wall clock; the build
  normalizes all of these (pinned epoch, uid=gid=0, empty names, pax
  records cleared, gzip mtime pinned, no gzip filename) so the released
  sdist is byte-identical across builds.

Builds always run on a **clean copy** of the tree (`.git`, `build/`,
`*.egg-info`, caches, `dist/`, `dont touch/` excluded) - the working tree
is never mutated and stale build residue can never leak into an artifact.

## Integrity

`build` writes GNU `sha256sum`-format `SHA256SUMS` plus per-artifact
`.sha256` files. `verify` re-hashes every artifact against the manifest
and FAILS (exit 1) on any missing artifact, hash mismatch, or tamper.

## Signing

`sign` produces detached-armor GPG signatures (`.asc`) per artifact. The
repository does **not** embed or fabricate signing credentials: the signer
must provide a maintainer-held GPG key id via `AGENT_SANDBOX_GPG_KEY`
(human-controlled release infrastructure, outside the repository). Without
it, `sign` fails closed (exit 2) with the blocker stated. The mechanism is
prepared and auditable; the credential is intentionally external.

## Tests

    python tools/release/test_release.py     # exit 0 = all pass

Covers: artifact set shape, metadata, install/import smoke test from the
built wheel, sdist contents + build-residue hygiene, honest-verify pass,
tamper detection, two-clean-builds byte-identity, `reproducibility` exit
0, and signing fail-closed without a key. The CI runs this as the
"Phase 20 - release reproducibility + integrity" step.
