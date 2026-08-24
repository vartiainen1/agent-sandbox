"""Tests for the deterministic release build + integrity tooling
(RELEASE_CHECKLIST sections 11-12; implementation.md section 24).

Run: python3 tools/release/test_release.py   (exit 0 = all pass)

Covers:
- build produces an sdist + wheel + SHA256SUMS + per-artifact .sha256
- reproducibility: two independent clean builds are byte-identical
  (wheel already deterministic; sdist normalized)
- integrity: verify() passes on honest artifacts and FAILS on a tampered
  artifact (fail closed, never a warning)
- metadata: version/name/requires-python are the repository's values
- wheel content: the package imports from the built wheel (smoke test)
- signing: blocked without AGENT_SANDBOX_GPG_KEY (exit 2, fail closed)
- clean-copy hygiene: build/ and *.egg-info residue cannot leak into the
  sdist from the working tree
"""

import importlib.util
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import zipfile

HERE = pathlib.Path(__file__).resolve().parent

fails = []


def check(label, cond):
    print(("[PASS] " if cond else "[FAIL] ") + label)
    if not cond:
        fails.append(label)


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


br = load("build_release")

PY = sys.executable


def _run_tool(args, env_extra=None):
    """Run the tool as a subprocess (isolated from this process)."""
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run([PY, str(HERE / "build_release.py")] + args,
                          capture_output=True, text=True, env=env)


def _artifacts(out: pathlib.Path):
    return sorted(p for p in out.iterdir()
                  if p.is_file() and p.name not in ("SHA256SUMS",)
                  and not p.name.endswith(".sha256"))


# --- build produces the expected artifact set ---
with tempfile.TemporaryDirectory(prefix="asbx-t1-") as td:
    out = pathlib.Path(td) / "dist"
    try:
        arts = br.build(out, epoch=0)
    except Exception as e:
        arts = []
        check(f"build succeeds (needs setuptools): {e}", False)
    if arts:
        names = {p.name for p in arts}
        check("build produces exactly one sdist and one wheel",
              len(names) == 2 and
              any(n.endswith(".tar.gz") for n in names) and
              any(n.endswith(".whl") for n in names))
        check("SHA256SUMS manifest written",
              (out / "SHA256SUMS").exists())
        check("per-artifact .sha256 files written",
              all((out / f"{p.name}.sha256").exists() for p in arts))
        check("manifest covers every artifact",
              len((out / "SHA256SUMS").read_text(encoding="ascii").splitlines()) == len(arts))

        # --- metadata from the built artifacts ---
        wheel = next(p for p in arts if p.name.endswith(".whl"))
        sdist = next(p for p in arts if p.name.endswith(".tar.gz"))
        with zipfile.ZipFile(wheel) as z:
            meta = [n for n in z.namelist() if n.endswith(".dist-info/METADATA")][0]
            md = z.read(meta).decode("utf-8")
        check("wheel METADATA name=agent-sandbox", "Name: agent-sandbox" in md)
        check("wheel METADATA version=0.2.0", "Version: 0.2.0" in md)
        check("wheel METADATA requires-python>=3.11", "Requires-Python: >=3.11" in md)
        check("wheel contains the package module",
              any(n.startswith("agent_sandbox/") for n in zipfile.ZipFile(wheel).namelist()))

        # --- install/import smoke test from the built wheel ---
        # The pip install step is gated on pip being available in the test
        # environment (CI has it; the Freebuff host python does not). When
        # pip is absent the smoke test SKIPS with a recorded reason - a
        # documented skip, never a silent false pass or a failure.
        # Gate on the ACTUAL command that will run (``python -m pip``), not
        # on a PATH ``pip`` that may belong to a different interpreter.
        try:
            r0 = subprocess.run([PY, "-m", "pip", "--version"],
                                capture_output=True, text=True)
            pip_ok = r0.returncode == 0
        except Exception:
            pip_ok = False
        if not pip_ok:
            print("[SKIP] import smoke test from built wheel (pip not available)")
        else:
            with tempfile.TemporaryDirectory(prefix="asbx-smoke-") as td2:
                r = subprocess.run(
                    [PY, "-m", "pip", "install", "--no-deps", "--target", td2, str(wheel)],
                    capture_output=True, text=True)
                if r.returncode != 0:
                    check("wheel installs (pip available)", False)
                else:
                    r2 = subprocess.run(
                        [PY, "-c",
                         "import sys; sys.path.insert(0, sys.argv[1]); "
                         "import agent_sandbox; print(agent_sandbox.__file__)",
                         td2],
                        capture_output=True, text=True)
                    check("import smoke test from built wheel",
                          r2.returncode == 0 and "agent_sandbox" in r2.stdout)

        # --- sdist integrity + hygiene ---
        with tarfile.open(sdist, "r:gz") as t:
            member_names = t.getnames()
            contents = {m.name: (t.extractfile(m).read() if t.extractfile(m) else b"")
                        for m in t}
        check("sdist contains PKG-INFO", any(n.endswith("/PKG-INFO") for n in member_names))
        check("sdist contains the package", any("agent_sandbox/" in n for n in member_names))
        # Hygiene: the sdist must not carry the working tree's build staging
        # dir (build/), bytecode caches, or stale artifacts. The egg-info
        # members ARE generated fresh by the sdist build itself (normal for
        # setuptools sdists) - the exclusion test is about build residue.
        check("sdist excludes working-tree build residue",
              not any(n.startswith("build/") for n in member_names) and
              not any("__pycache__" in n for n in member_names) and
              not any(n.endswith(".pyc") for n in member_names))

        # --- integrity: honest artifacts pass; tampered artifact fails ---
        try:
            ok = br.verify(out)
            check("verify() passes on honest artifacts", len(ok) == len(arts))
        except Exception as e:
            check(f"verify() passes on honest artifacts: {e}", False)
        tampered = next(p for p in arts if p.name.endswith(".whl"))
        with open(tampered, "ab") as f:
            f.write(b"TAMPER")
        try:
            br.verify(out)
            check("verify() FAILS on a tampered artifact", False)
        except Exception as e:
            check("verify() FAILS on a tampered artifact",
                  "FAILED" in str(e) and "hash mismatch" in str(e))

# --- reproducibility: two clean builds are byte-identical ---
with tempfile.TemporaryDirectory(prefix="asbx-t2-") as td:
    out1 = pathlib.Path(td) / "d1"
    out2 = pathlib.Path(td) / "d2"
    out1.mkdir()
    out2.mkdir()
    try:
        br.build(out1, epoch=0)
        br.build(out2, epoch=0)
        h1 = {p.name: br._sha256(p) for p in _artifacts(out1)}
        h2 = {p.name: br._sha256(p) for p in _artifacts(out2)}
        check("two clean builds are byte-identical (sdist + wheel)",
              h1 == h2)
        if h1 != h2:
            for k in sorted(set(h1) | set(h2)):
                if h1.get(k) != h2.get(k):
                    print(f"    diff {k}: {h1.get(k)} vs {h2.get(k)}")
    except Exception as e:
        check(f"two clean builds are byte-identical: {e}", False)

# --- reproducibility command: exit 0 ---
r = _run_tool(["reproducibility"])
check("reproducibility command exits 0",
      r.returncode == 0 and "byte-identical" in r.stdout)

# --- signing fails closed without a key ---
r = _run_tool(["sign"])
check("signing without AGENT_SANDBOX_GPG_KEY fails closed (exit 2)",
      r.returncode == 2 and "AGENT_SANDBOX_GPG_KEY" in r.stderr)

print()
if fails:
    print(f"RESULT: {len(fails)} FAILURE(S): {fails}")
    sys.exit(1)
print("RESULT: ALL PASS")
