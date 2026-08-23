# Curated v0.1 Toolchain (ADR-005 system layers)

The sandbox rootfs is a minimal tree (empty `usr/bin`, `bin`, `lib`,
`etc` placeholders) — isolation by construction. The documented v0.1
workload contract (docs/seccomp-derivation/methodology.md Tier 1) is
**python3 + coreutils + git + dash/sh**: the seccomp allowlist was
derived from exactly those workloads. ADR-005 provides for this via
"read-only bind-mounted system layers... a curated (minimal toolchain
image)". This directory implements that missing artifact.

## What the artifact is

`build_toolchain.py` assembles a **curated** toolchain tree from the
build host's dpkg packages — never a wholesale copy of the host
filesystem:

- entry binaries: `python3` (+ its `python3.12` symlink chain), `git`,
  `dash`/`sh`, and the **coreutils package** binary set;
- **python3-pip** (Phase 10 curated dependency installer, v0.2 Step 4):
  the package's own files incl. `pip/_vendor` (self-contained -
  requests/urllib3/certifi/CA bundle vendored, verified natively on
  Debian 13 / pip 25.1.1) and the `pip3` console scripts, so
  `pip install --proxy http://10.255.254.0:8080 ...` runs through the
  validating proxy inside the sandbox. The build fails closed if
  `python3-pip` is not installed on the build host;
- each binary's **ldd closure** (glibc + every NEEDED shared object +
  the dynamic loader), copied to their real relative paths;
- the **python stdlib** (`/usr/lib/python3.12/`) and the **git-core**
  exec directory (`/usr/lib/git-core/`);
- a **minimal sanitized `/etc`** (`passwd`, `group`, `nsswitch.conf` —
  no `resolv.conf`, no secrets; absence is the mechanism);
- merged-usr symlinks `bin -> usr/bin`, `lib -> usr/lib`,
  `lib64 -> usr/lib64` (the layout modern Debian/Ubuntu uses);
- a `MANIFEST` listing every copied path (audit + determinism record).

Output layout:

```
<out>/usr/bin|lib|lib64|share    binaries, libs, stdlib, git-core
<out>/bin -> usr/bin             merged-usr symlinks
<out>/lib -> usr/lib
<out>/lib64 -> usr/lib64
<out>/etc                        minimal sanitized passwd/group/nsswitch
<out>/MANIFEST                   every copied path
```

## Build

```bash
python3 tools/toolchain/build_toolchain.py --out /opt/agent-sandbox-toolchain
```

Requires a Debian/Ubuntu-family host with `dpkg`, `ldd`, and the
packages `python3`, `python3.12`, `coreutils`, `git`, `dash`,
**`python3-pip`** (Phase 10) installed.
The build is deterministic given the same source packages (files are
copied verbatim; the MANIFEST is the record). It is fail-closed: any
unresolvable binary or dependency aborts — never a partial artifact.

## Runtime wiring

Set the host-side env var before creating sessions:

```bash
export AGENT_SANDBOX_TOOLCHAIN=/opt/agent-sandbox-toolchain
```

The sandbox supervisor reads it (host side only — the workload's
sanitized environment never contains it) and the filesystem stage
bind-mounts the layers read-only into the rootfs before `pivot_root`:

- `usr` → `/usr`, `bin` → `/bin`, `lib` → `/lib`, `lib64` → `/lib64`,
  `etc` → `/etc` (each bind + read-only remount, in the sandbox's
  private mount namespace — no propagation to the host);
- a configured-but-invalid path is a **refusal** (fail closed);
- unset keeps the empty-placeholder rootfs (workspace-executable
  workloads only, e.g. `/workspace/tool`).

The post-pivot verification requires `/usr/bin/python3` to be present
and executable and every layer to be a **read-only** mount — a writable
system layer would let the workload tamper its own toolchain.

## Security properties

- Read-only from the workload's perspective (bind + `MS_RDONLY`
  remount, verified from mountinfo).
- No host filesystem escape: the bind sources are the dedicated artifact
  dirs, never host `/usr`, `/bin`, `/lib`, `/etc` or any other host
  system directory.
- No credentials/environment leakage: the existing env sanitization
  (Step 11) and credential/socket isolation (Step 12) are unchanged.
- No new device or network exposure: `/dev` stays the six-node minimal
  inventory (ADR-015), `/sys` stays absent (ADR-005), the netns
  deny-by-construction is unchanged.
- No new syscalls: the allowlist was derived from these same
  python/coreutils/git workloads. (46 on x86_64 as of the documented
  2026-08-22 `+chdir` for the git closed set — see
  docs/seccomp-derivation/policy.md §5; the toolchain adds no syscalls
  itself.)
