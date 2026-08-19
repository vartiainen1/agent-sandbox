"""Workload set for the seccomp syscall derivation exercise.

Tiers:
  Tier 0 - the absolute minimum the hardened runtime must execute
           (Phase 1 acceptance: `echo hello`-class).
  Tier 1 - the intended v0.1 toolchain surface (python3, coreutils, git).
           The supervisor and every agent-* tool are Python, so python3's
           full surface is part of the intended hardened runtime.

Each workload is a name -> argv list. The tracer runs each under strace -f
and emits the observed syscall set (see trace_workloads.py).
"""

WORKLOADS = {
    # ------------------------------------------------------------ Tier 0
    "t0_sh_echo": [
        "/bin/sh", "-c", "echo hello",
    ],
    "t0_sh_exit": [
        "/bin/sh", "-c", "exit 0",
    ],

    # ------------------------------------------------------------ Tier 1
    # coreutils: the file-operation surface (ls, mkdir, write, cat, cp, rm)
    "t1_sh_fileops": [
        "/bin/sh", "-c",
        "set -e; ls -la /tmp; mkdir -p /tmp/w; printf 'data\\n' > /tmp/w/f; "
        "cat /tmp/w/f; cp /tmp/w/f /tmp/w/g; rm -rf /tmp/w",
    ],
    # python3: interpreter startup + print (the minimum Python surface)
    "t1_python_hello": [
        "python3", "-c", "print('hi')",
    ],
    # python3: agent-ish pattern - json, tempfile, pathlib, subprocess
    "t1_python_agentish": [
        "python3", "-c",
        "import json, os, subprocess, tempfile, pathlib\n"
        "p = pathlib.Path(tempfile.mkdtemp()) / 'data.json'\n"
        "p.write_text(json.dumps({'k': [1, 2, 3]}))\n"
        "d = json.loads(p.read_text())\n"
        "r = subprocess.run(['/bin/echo', 'ok'], capture_output=True, text=True)\n"
        "assert r.stdout.strip() == 'ok' and d['k'] == [1, 2, 3]\n"
        "print('ok')",
    ],
    # git: init/status/add (the Phase 9 git surface, traced now so the
    # allowlist is informed by it; git is not part of the Phase 1 workload)
    "t1_git_basics": [
        "/bin/sh", "-c",
        "set -e; rm -rf /tmp/g; git init -q /tmp/g; "
        "git -C /tmp/g config user.email a@b.c; git -C /tmp/g config user.name n; "
        "printf 'x\\n' > /tmp/g/f; git -C /tmp/g add f; "
        "git -C /tmp/g -c core.pager=cat status --short",
    ],
}


def tier_of(name: str) -> str:
    return "Tier 0" if name.startswith("t0_") else "Tier 1"
