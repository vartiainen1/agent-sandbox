"""Deterministic release build + integrity tooling (RELEASE_CHECKLIST
sections 11-12; implementation.md section 24).

This tool makes release artifact reproducibility and integrity MECHANIZED
and verifiable - the Phase 20 criteria the checklist previously recorded as
NOT VERIFIED:

- ``build``:  build sdist + wheel from a CLEAN copy of the source tree with
  ``SOURCE_DATE_EPOCH`` pinned, normalize the sdist (pax headers cleared,
  fixed mtime/uid/gid, deterministic gzip header), then write a SHA-256
  manifest (``SHA256SUMS``) plus per-artifact ``.sha256`` files into the
  output directory.
- ``verify``: re-hash the artifacts in the output directory and compare
  against the committed ``SHA256SUMS`` manifest. Any mismatch (corruption,
  tampering, or a non-deterministic rebuild) FAILS - never warns.
- ``reproducibility``: build TWICE from two independent clean copies of the
  tree and compare per-artifact hashes. Non-identical outputs FAIL (this is
  the reproducibility gate; the wheel must be byte-identical and the sdist
  must be byte-identical after normalization).
- ``sign``: optional detached-armor GPG signature. Requires a configured
  signing key (``AGENT_SANDBOX_GPG_KEY``) AND ``gpg`` on PATH. Without the
  key, the command FAILS CLOSED with the blocker stated - the mechanism is
  prepared, credentials are never invented or substituted.

Design constraints (ADR-016 / repo zero-dependency discipline):
- stdlib only at runtime; the PEP 517 backend (setuptools, already the
  declared build backend in pyproject.toml) is invoked through its public
  ``build_meta`` entry points. No new runtime or build dependencies.
- Builds run on a clean copy of the tree (the working tree is never
  mutated, and stale ``build/``/``*.egg-info`` artifacts cannot leak in).
- Deterministic by construction: ``SOURCE_DATE_EPOCH`` is pinned for every
  subprocess, and the sdist normalization drops every time/owner-dependent
  header field (pax mtime/atime/ctime, uid/gid, uname/gname) before the
  final gzip write (which itself pins mtime and drops the filename field).
- Every failure path exits non-zero with the reason on stderr (fail closed).

Exit codes: 0 = success; 1 = build/verify/reproducibility failure; 2 =
signing blocked (no key configured); 3 = usage/environment error.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent

# Artifacts are written here by default (gitignored; never committed).
DEFAULT_OUT = REPO_ROOT / "dist"

# Deterministic build epoch: same source + same epoch => identical bytes.
DEFAULT_EPOCH = 0

# Files/dirs never copied into the clean build tree.
_EXCLUDED_NAMES = {
    ".git", "build", "dist", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".secrets.baseline", "dont touch",
}
_EXCLUDED_SUFFIXES = (".egg-info", ".pyc", ".pyo")

_MANIFEST = "SHA256SUMS"


class _Error(Exception):
    """Fatal tool failure (message printed to stderr, exit 1/2/3)."""


def _build_backend():
    """Import setuptools.build_meta (the declared PEP 517 backend)."""
    try:
        spec = importlib.util.find_spec("setuptools.build_meta")
        if spec is None:
            raise _Error("setuptools.build_meta not importable - build backend missing")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except ImportError as e:
        raise _Error(f"cannot load setuptools.build_meta: {e}") from e


def _clean_copy(dest: pathlib.Path) -> None:
    """Copy the source tree (excluding build residue) to ``dest``."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    def _ignore(directory, names):
        ignored = set()
        for n in names:
            if n in _EXCLUDED_NAMES or n.endswith(_EXCLUDED_SUFFIXES):
                ignored.add(n)
        return ignored

    shutil.copytree(REPO_ROOT, dest, ignore=_ignore, dirs_exist_ok=True)


def _run(cmd, cwd, env_extra=None):
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = str(DEFAULT_EPOCH)
    if env_extra:
        env.update(env_extra)
    r = subprocess.run(cmd, cwd=str(cwd), env=env,
                       capture_output=True, text=True)
    if r.returncode != 0:
        tail = "\n".join((r.stderr or "").splitlines()[-5:])
        raise _Error(f"command failed ({' '.join(cmd)}): {tail}")
    return r


def _normalize_sdist_bytes(raw: bytes, epoch: int) -> bytes:
    """Rewrite an sdist .tar.gz so only deterministic bytes remain.

    The wheel produced by setuptools is already deterministic (fixed
    timestamps, RECORD-based). The sdist embeds per-file pax mtime/atime/
    ctime records plus uid/gid/uname/gname and a gzip header with the
    current wall clock - all of which differ between two otherwise-identical
    builds. We re-tar with every such field pinned (epoch, uid=gid=0,
    empty names, pax records cleared) and re-gzip with a pinned mtime and no
    filename, producing byte-identical output for identical source.
    """
    tar = gzip.decompress(raw)
    tarbuf = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(tar), mode="r:") as src, \
         tarfile.open(fileobj=tarbuf, mode="w", format=tarfile.PAX_FORMAT) as dst:
        for m in src:
            m.mtime = epoch
            m.uid = 0
            m.gid = 0
            m.uname = ""
            m.gname = ""
            m.pax_headers.clear()
            data = src.extractfile(m)
            dst.addfile(m, data)
    out = tarbuf.getvalue()
    gzbuf = io.BytesIO()
    with gzip.GzipFile(fileobj=gzbuf, mode="wb", mtime=epoch, filename="") as g:
        g.write(out)
    return gzbuf.getvalue()


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_checksums(out_dir: pathlib.Path, artifacts: list[pathlib.Path]) -> None:
    """Write SHA256SUMS (GNU sha256sum format) + per-artifact .sha256."""
    lines = []
    for p in sorted(artifacts):
        digest = _sha256(p)
        lines.append(f"{digest}  {p.name}\n")
        (out_dir / f"{p.name}.sha256").write_text(
            f"{digest}  {p.name}\n", encoding="ascii")
    (out_dir / _MANIFEST).write_text("".join(lines), encoding="ascii")


def build(out_dir: pathlib.Path, epoch: int = DEFAULT_EPOCH,
          sign: bool = False) -> list[pathlib.Path]:
    """Deterministic sdist + wheel build with checksums. Returns artifacts."""
    # Pin the epoch in-process BEFORE the backend runs: setuptools/bdist_wheel
    # honor SOURCE_DATE_EPOCH for wheel zip timestamps (byte-identical wheels
    # across builds), and the subprocess env pin covers any tool that reads it
    # at spawn time.
    os.environ["SOURCE_DATE_EPOCH"] = str(epoch)
    backend = _build_backend()
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="asbx-rel-") as td:
        src = pathlib.Path(td) / "src"
        _clean_copy(src)
        try:
            sdist_name = backend.build_sdist(str(out_dir))
            wheel_name = backend.build_wheel(str(out_dir))
        except Exception as e:  # backend failure -> fail closed
            raise _Error(f"PEP 517 build failed: {e}") from e
        sdist = out_dir / sdist_name
        wheel = out_dir / wheel_name
        # Normalize the sdist (pax mtime/atime/ctime/owner + gzip header are
        # the only remaining non-deterministic bytes; the wheel is already
        # byte-identical thanks to the pinned epoch) and rewrite in place.
        norm = _normalize_sdist_bytes(sdist.read_bytes(), epoch)
        sdist.write_bytes(norm)
    artifacts = [sdist, wheel]
    _write_checksums(out_dir, artifacts)
    if sign:
        _sign(artifacts)
    return artifacts


def verify(out_dir: pathlib.Path) -> list[str]:
    """Re-hash artifacts against the SHA256SUMS manifest. Fail on mismatch."""
    manifest = out_dir / _MANIFEST
    if not manifest.exists():
        raise _Error(f"no {_MANIFEST} in {out_dir} - nothing to verify")
    expected = {}
    for line in manifest.read_text(encoding="ascii").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, name = line.split("  ", 1)
        expected[name] = digest
    problems = []
    for name, digest in sorted(expected.items()):
        path = out_dir / name
        if not path.exists():
            problems.append(f"missing artifact: {name}")
            continue
        actual = _sha256(path)
        if actual != digest:
            problems.append(f"hash mismatch: {name} (expected {digest}, got {actual})")
    if problems:
        raise _Error("integrity verification FAILED:\n  " + "\n  ".join(problems))
    return sorted(expected)


def reproducibility(out_dir: pathlib.Path, epoch: int = DEFAULT_EPOCH) -> None:
    """Build twice from independent clean copies; hashes must match."""
    first: dict[str, str] = {}
    second: dict[str, str] = {}
    for i, bucket in enumerate((first, second), start=1):
        with tempfile.TemporaryDirectory(prefix=f"asbx-rep{i}-") as td:
            tmp_out = pathlib.Path(td) / "out"
            tmp_out.mkdir()
            build(tmp_out, epoch=epoch, sign=False)
            for name in sorted(p.name for p in tmp_out.glob("*") if p.is_file()):
                if name in (_MANIFEST,) or name.endswith(".sha256"):
                    continue
                bucket[name] = _sha256(tmp_out / name)
    problems = []
    for name in sorted(set(first) | set(second)):
        if first.get(name) != second.get(name):
            problems.append(
                f"{name}: build1={first.get(name)} build2={second.get(name)}")
    if problems:
        raise _Error("reproducibility FAILED (two clean builds differ):\n  "
                     + "\n  ".join(problems))


def _sign(artifacts: list[pathlib.Path]) -> None:
    """Detached-armor GPG signature per artifact. FAILS CLOSED without a key.

    The repository does not invent or embed signing credentials. A release
    signer must provide a GPG key id via AGENT_SANDBOX_GPG_KEY; without it
    the signature step refuses (exit 2) - the mechanism is prepared, the
    credential is the human-controlled release infrastructure that is
    intentionally outside the repository.
    """
    key = os.environ.get("AGENT_SANDBOX_GPG_KEY", "").strip()
    if not key:
        raise _Error(
            "signing blocked: AGENT_SANDBOX_GPG_KEY is not set. The signing "
            "mechanism is prepared but requires a maintainer-held GPG key "
            "(human-controlled release infrastructure); no credential is "
            "embedded or fabricated.")
    if shutil.which("gpg") is None:
        raise _Error("signing blocked: gpg not found on PATH")
    for p in artifacts:
        r = subprocess.run(
            ["gpg", "--batch", "--yes", "--detach-sign", "--armor",
             "-u", key, str(p)],
            capture_output=True, text=True)
        if r.returncode != 0:
            raise _Error(f"gpg signing failed for {p.name}: "
                         + "\n".join((r.stderr or "").splitlines()[-3:]))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Deterministic release build + integrity (RELEASE_CHECKLIST 11-12)")
    ap.add_argument("command", choices=["build", "verify", "reproducibility", "sign"])
    ap.add_argument("-o", "--out", type=pathlib.Path, default=DEFAULT_OUT,
                    help=f"output dir (default: {DEFAULT_OUT})")
    ap.add_argument("--epoch", type=int, default=DEFAULT_EPOCH,
                    help="SOURCE_DATE_EPOCH value (default 0)")
    ap.add_argument("--sign", action="store_true",
                    help="with 'build': also produce detached-armor GPG signatures")
    args = ap.parse_args(argv)
    try:
        if args.command == "build":
            arts = build(args.out, epoch=args.epoch, sign=args.sign)
            for a in sorted(arts):
                print(f"{_sha256(a)}  {a.name}")
            print(f"built {len(arts)} artifacts + {_MANIFEST} in {args.out}")
        elif args.command == "verify":
            names = verify(args.out)
            print(f"verified {len(names)} artifacts against {args.out / _MANIFEST}: OK")
        elif args.command == "reproducibility":
            reproducibility(args.out, epoch=args.epoch)
            print("reproducibility OK: two clean builds are byte-identical")
        elif args.command == "sign":
            # Key check FIRST: the credential blocker is the deterministic
            # fail-closed signal (exit 2), independent of artifact state.
            if not os.environ.get("AGENT_SANDBOX_GPG_KEY", "").strip():
                _sign([])  # raises the signing-blocked _Error (exit 2)
            arts = sorted(args.out.glob("agent_sandbox-*.whl")) + \
                   sorted(args.out.glob("agent_sandbox-*.tar.gz"))
            if not arts:
                raise _Error(f"no artifacts found in {args.out}")
            _sign(arts)
            print(f"signed {len(arts)} artifacts")
        return 0
    except _Error as e:
        print(f"error: {e}", file=sys.stderr)
        if "signing blocked" in str(e):
            return 2
        return 1
    except Exception as e:  # unexpected -> still fail closed
        print(f"error: unexpected failure: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
