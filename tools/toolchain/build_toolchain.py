#!/usr/bin/env python3
"""Build the curated v0.1 toolchain artifact (ADR-005 read-only system layers).

Assembles a minimal, reproducible toolchain tree from the BUILD HOST's
installed dpkg packages - the intended v0.1 workload contract
(docs/seccomp-derivation/methodology.md Tier 1: python3 + coreutils +
git + dash/sh) plus each binary's dynamic-linker closure and a minimal
sanitized /etc. The result is a self-contained tree with the merged-usr
layout that the sandbox bind-mounts READ-ONLY into the rootfs:

    <out>/usr/bin|lib|lib64|share     binaries, libs, python stdlib, git-core
    <out>/bin -> usr/bin              merged-usr symlinks (resolved by
    <out>/lib -> usr/lib              mount(2) when the layers are bound)
    <out>/lib64                       real dir holding the dynamic loader
    <out>/etc                         minimal sanitized passwd/group/nsswitch
    <out>/MANIFEST                    every copied path (audit)

Rules:
- NEVER copies the host filesystem wholesale: only the declared binaries
  (python3, git, dash/sh, the coreutils package set) + their ldd closure
  + the python stdlib + git-core exec dir + a minimal sanitized /etc.
  Every source is resolved to its realpath first so all content lands
  under usr/ (the merged-usr layout of modern Debian/Ubuntu).
- Deterministic given the same source packages (declared package files
  and the ldd closure are copied verbatim; the MANIFEST records every
  path).
- Fail-closed: any declared binary or dependency that cannot be resolved
  aborts with a precise reason - never a partial artifact.

Usage:  python3 build_toolchain.py --out <dir>
Requires: Linux with dpkg, ldd, and the packages python3, python3.12,
coreutils, git, dash installed (any Debian/Ubuntu-family host).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

# The declared v0.1 toolchain surface (methodology.md Tier 1). Entry
# points are resolved through symlinks; the coreutils set is taken from
# the coreutils dpkg package (its /usr/bin and /usr/lib files) so it is
# exactly that curated package, never the host's whole /usr.
ENTRY_BINARIES = (
    "/usr/bin/python3",
    "/usr/bin/git",
    "/bin/sh",          # merged-usr -> /usr/bin/dash
)
COREUTILS_PACKAGE = "coreutils"
# Phase 10 (v0.2 Step 4): the curated dependency installer. python3-pip
# on Debian/Ubuntu is self-contained: pip/_vendor carries its full
# dependency closure (requests/urllib3/certifi/idna/packaging/... incl.
# the CA bundle), so copying the package's own files is sufficient - no
# system certifi/urllib3/requests packages are needed (verified natively,
# Debian 13 / pip 25.1.1, 2026-08-23). The package must be installed on
# the build host; the build fails closed otherwise.
PIP_PACKAGE = "python3-pip"
PYTHON_STDLIB_DIRS = (
    "/usr/lib/python3.12",
)
GIT_CORE_DIR = "/usr/lib/git-core"
MINIMAL_ETC = {
    "passwd": "root:x:0:0:root:/root:/bin/sh\n"
              "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
    "group": "root:x:0:\nnogroup:x:65534:\n",
    "nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\n"
                     "hosts: files dns\nnetworks: files\nprotocols: db files\n"
                     "services: db files\n",
}


class BuildError(RuntimeError):
    pass


def _run(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError as e:
        raise BuildError(f"required tool missing: {e}") from e
    if proc.returncode != 0:
        raise BuildError(
            f"command failed ({' '.join(cmd)}): {proc.stderr.strip()}")
    return proc.stdout


def _resolve_chain(binary: str) -> list[str]:
    """The symlink chain from ``binary`` to its real file (e.g. /bin/sh ->
    dash via the merged-usr /bin symlink; /usr/bin/python3 -> python3.12).
    Entries are the link paths (in order) plus the final real file."""
    paths: list[str] = []
    cur = binary
    for _ in range(16):
        paths.append(cur)
        if not os.path.islink(cur):
            break
        nxt = os.readlink(cur)
        if not nxt.startswith("/"):
            nxt = os.path.join(os.path.dirname(cur), nxt)
        cur = os.path.normpath(nxt)
    if not paths or not os.path.isfile(paths[-1]):
        raise BuildError(f"cannot resolve binary {binary}")
    return paths


def _ldd_closure(binary: str) -> list[str]:
    """Every NEEDED shared object + the loader, resolved via ldd. Each
    dependency keeps its SYMLINK CHAIN (e.g. /lib/x86_64-linux-gnu/
    libz.so.1 -> libz.so.1.3): the loader resolves the SONAME symlink,
    so copying only the realpath would produce a broken artifact (the
    classic "error while loading shared libraries" at interpreter
    startup). A missing dependency aborts (fail closed - never a broken
    artifact)."""
    out = _run(["ldd", binary])
    deps: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if "=>" in line:
            dep = line.split("=>", 1)[1].split("(")[0].strip()
        elif line.startswith("/") and "(" in line:
            dep = line.rsplit("(", 1)[0].strip()
        else:
            continue
        if not dep:
            continue
        # The dep may be a symlink chain (SONAME -> versioned file).
        # Recreate every link in the chain plus the real file, exactly
        # like _resolve_chain does for the declared binaries.
        cur = dep
        for _ in range(16):
            if os.path.islink(cur):
                deps.append(cur)  # the symlink itself (copied as a link)
                nxt = os.readlink(cur)
                if not nxt.startswith("/"):
                    nxt = os.path.join(os.path.dirname(cur), nxt)
                cur = os.path.normpath(nxt)
            else:
                break
        if os.path.isfile(cur):
            deps.append(cur)
        elif not os.path.islink(dep):
            raise BuildError(
                f"unresolved dependency for {binary}: {dep}")
    if "not found" in out:
        raise BuildError(f"unresolved dependency for {binary}: {out.strip()}")
    return deps


def _coreutils_files() -> list[str]:
    out = _run(["dpkg", "-L", COREUTILS_PACKAGE])
    files = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith(("/usr/bin/", "/usr/lib/coreutils/")):
            files.append(line)
    if not files:
        raise BuildError(f"no binaries found for package {COREUTILS_PACKAGE}")
    return files


def _pip_files() -> list[str]:
    """Every file owned by the python3-pip package (Phase 10 curated
    dependency installer). Dirs are copied whole (the pip/_vendor tree),
    symlinks recreated, plain files copied. The /usr/bin/pip* console
    scripts are Python shebang scripts - their interpreter (python3) is
    already an entry binary, so no extra ldd closure is needed."""
    out = _run(["dpkg", "-L", PIP_PACKAGE])
    files = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("/usr/bin/") or line.startswith("/usr/lib/"):
            files.append(line)
    if not files:
        raise BuildError(
            f"no files found for package {PIP_PACKAGE} - is python3-pip "
            "installed on the build host? fail closed")
    return files


def _copy_real(src: str, out_root: str, manifest: list[str]) -> None:
    """Copy a real file/dir preserving its absolute path relative to ``/``
    under out_root (symlinks in the chain are recreated separately)."""
    rel = os.path.realpath(src).lstrip("/")
    dst = os.path.join(out_root, rel)
    if os.path.lexists(dst):
        return
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(os.path.realpath(src), dst)
    manifest.append(rel)


def _copy_symlink(src: str, out_root: str, manifest: list[str]) -> None:
    """Recreate a symlink at its absolute path (its target string is
    preserved; relative targets resolve within the artifact's own tree)."""
    rel = src.lstrip("/")
    dst = os.path.join(out_root, rel)
    if os.path.lexists(dst):
        return
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    os.symlink(os.readlink(src), dst)
    manifest.append(rel)


def _copy_tree(src: str, out_root: str, manifest: list[str]) -> None:
    rel = src.lstrip("/")
    dst = os.path.join(out_root, rel)
    if os.path.lexists(dst):
        return
    shutil.copytree(src, dst, symlinks=True)
    for dirpath, dirs, files in os.walk(src):
        for f in files + dirs:
            p = os.path.join(dirpath, f)
            manifest.append(os.path.relpath(p, "/").lstrip("/"))


def build(out_root: str) -> None:
    if os.path.exists(out_root):
        shutil.rmtree(out_root)
    os.makedirs(out_root)
    manifest: list[str] = []

    # 1. Merged-usr symlinks FIRST (bin/lib -> usr/*; lib64 is a REAL dir
    #    because the ELF loader is reached at the absolute path
    #    /lib64/ld-linux-x86-64.so.2, which must exist as a file).
    os.makedirs(os.path.join(out_root, "usr"), exist_ok=True)
    os.symlink("usr/bin", os.path.join(out_root, "bin"))
    os.symlink("usr/lib", os.path.join(out_root, "lib"))
    os.makedirs(os.path.join(out_root, "lib64"))
    manifest += ["bin", "lib", "lib64"]

    # 2. Declared entry binaries: recreate symlink chains, copy the real
    #    files. /bin/sh resolves through the merged-usr /bin symlink, so
    #    its chain entry lands at usr/bin/sh -> dash (exactly the host
    #    resolution) and the /bin entry itself is the merged-usr symlink.
    real_binaries: list[str] = []
    for entry in ENTRY_BINARIES:
        for p in _resolve_chain(entry):
            if os.path.islink(p):
                _copy_symlink(p, out_root, manifest)
            elif os.path.isfile(p):
                real_binaries.append(p)

    # 3. The coreutils package set.
    for p in _coreutils_files():
        if os.path.islink(p):
            _copy_symlink(p, out_root, manifest)
        elif os.path.isfile(p):
            real_binaries.append(p)

    # 3b. Phase 10 curated dependency installer (python3-pip): the package
    #     tree incl. pip/_vendor (self-contained) + the pip3 console
    #     scripts. Copied directly - no ldd closure (Python scripts).
    for p in _pip_files():
        if os.path.islink(p):
            _copy_symlink(p, out_root, manifest)
        elif os.path.isdir(p):
            _copy_tree(p, out_root, manifest)
        else:
            _copy_real(p, out_root, manifest)

    # 4. Copy every real binary + its ldd closure (symlink chains and
    #    real files: links are recreated as links, files copied).
    for binary in sorted(set(real_binaries)):
        _copy_real(binary, out_root, manifest)
        for dep in _ldd_closure(binary):
            if os.path.islink(dep):
                _copy_symlink(dep, out_root, manifest)
            else:
                _copy_real(dep, out_root, manifest)

    # 5. Python stdlib + git-core exec dir (whole curated dirs).
    for d in PYTHON_STDLIB_DIRS:
        if os.path.isdir(d):
            _copy_tree(d, out_root, manifest)
        else:
            raise BuildError(f"python stdlib dir missing: {d}")
    if os.path.isdir(GIT_CORE_DIR):
        _copy_tree(GIT_CORE_DIR, out_root, manifest)

    # 6. The dynamic loader at the absolute interpreter path
    #    /lib64/ld-linux-x86-64.so.2 (a real file - the ELF interpreter
    #    path is hardcoded and must resolve inside the sandbox rootfs).
    loader = os.path.realpath("/lib64/ld-linux-x86-64.so.2")
    if not os.path.isfile(loader):
        raise BuildError("dynamic loader missing: /lib64/ld-linux-x86-64.so.2")
    dst = os.path.join(out_root, "lib64/ld-linux-x86-64.so.2")
    if not os.path.lexists(dst):
        shutil.copy2(loader, dst)
        manifest.append("lib64/ld-linux-x86-64.so.2")

    # 7. Minimal sanitized /etc (no resolv.conf, no hosts content, no
    #    secrets - absence is the mechanism for network/credential state).
    etc = os.path.join(out_root, "etc")
    os.makedirs(etc, exist_ok=True)
    for name, content in MINIMAL_ETC.items():
        with open(os.path.join(etc, name), "w") as f:
            f.write(content)
        manifest.append(f"etc/{name}")

    # 8. MANIFEST (audit + determinism record).
    with open(os.path.join(out_root, "MANIFEST"), "w") as f:
        f.write("\n".join(sorted(set(manifest))) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True,
                        help="toolchain artifact directory (created fresh)")
    args = parser.parse_args()
    try:
        build(os.path.abspath(args.out))
    except BuildError as e:
        print(f"FATAL: {e}", file=sys.stderr)
        return 1
    print(f"toolchain built at {os.path.abspath(args.out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
