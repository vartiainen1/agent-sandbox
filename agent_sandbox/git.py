"""Safe Git invocation model (Phase C, implementation.md Phase 9).

Git operates on a HOSTILE repository: every file, hook, ``.git/config``
value, ``.gitmodules`` entry, attribute and script is untrusted
(ARCHITECTURE section 3.2). The containment model has two layers:

1. CONFIGURATION CONTROL (defense in depth): git is invoked with a
   fixed, closed set of command-line ``-c`` overrides that neutralize
   the repository's ability to select executables, invoke helpers,
   enable credential access, or redirect operations. ``-c`` has the
   HIGHEST configuration precedence - above local, global and system
   config files, and above values pulled in via ``include.path`` /
   ``includeIf`` (empirically verified on git 2.55: an included
   ``core.fsmonitor`` is still overridden by ``-c core.fsmonitor=``).
   The exact dangerous surfaces (each empirically verified):

   - ``core.fsmonitor`` - executed by ``git status`` -> neutralized.
   - ``diff.external`` and ``diff.<driver>.textconv/.command`` -
     executed by ``git diff`` via config/attributes -> neutralized by
     ``-c diff.external=`` + the ``--no-ext-diff --no-textconv`` flags.
   - ``alias.<name>`` - git runs the BUILTIN when a same-name alias
     exists (verified: `alias.status = !...` does not shadow status);
     the exact operation words are additionally pinned with
     ``-c alias.<op>=<op>`` - a complete enumeration because the
     operation set is closed.
   - ``core.hooksPath`` / hooks - no hook-triggering operation exists
     in the set; neutralized anyway (belt and braces).
   - ``core.sshCommand``, ``credential.helper``/``interactive``,
     ``core.askPass`` - no network/credential operation exists in the
     set; neutralized anyway (no host credential can ever be consulted).
   - ``core.pager``/``pager.*``/``core.editor`` - git never pages on a
     pipe; neutralized anyway.
   - ``submodule.recurse``, ``protocol.file.allow`` - no submodule or
     protocol operation exists in the set; denied/disabled anyway.
   - ``GIT_*`` environment - none exists: the in-sandbox environment is
     the fixed six-variable sanitized set (S-034), so git cannot be
     steered by hostile environment variables.

2. SANDBOX BOUNDARY (the enforcement layer): git executes INSIDE the
   boundary - network deny-by-construction, zero capabilities,
   no_new_privs, seccomp, no host filesystem (rootfs copy + pivot),
   bounded output (S-037), external timeout (S-036), and process-tree
   containment + absence verification (S-038). Any residual helper,
   filter or hook execution is therefore CONTAINED to the disposable
   sandbox copy. This is the same trust model as the rest of the
   runtime (policy.py / ARCHITECTURE section 12: the OS boundary is
   the backstop).

The operation set is CLOSED and READ-ONLY. ``status``/``diff``/
``changed``/``untracked``/``deleted`` map to ``status``/``ls-files``
variants, ``base``/``current`` to ``merge-base``/``rev-parse``. No
commit/push/fetch/checkout/add/submodule operation exists in Phase C -
those trigger hooks, filters, network and write surfaces and are out of
scope; requesting them is a usage error (fail closed), never a silent
passthrough.

Trust boundary: this module is TRUSTED supervisor-side code (part of
the TCB, ADR-002). It builds ARGV ONLY - it never executes git itself,
never reads the repository, and never uses subprocess/os.system/execve.
"""

from __future__ import annotations

from typing import Iterable

# The closed, read-only Phase C operation set (implementation.md Phase 9).
# A request for anything else is a usage error - never a passthrough.
GIT_OPERATIONS = ("status", "diff", "changed", "untracked", "deleted",
                  "base", "current")

# operation -> the exact builtin command word(s) git must run. These are
# ALWAYS builtins (never aliases); the alias pin below forces the same
# even if a hostile config defines a same-name alias.
_OP_WORDS: dict[str, tuple[str, ...]] = {
    "status": ("status",),
    "diff": ("diff",),
    "changed": ("ls-files",),
    "untracked": ("ls-files",),
    "deleted": ("ls-files",),
    "base": ("merge-base",),
    "current": ("rev-parse",),
}

# Fixed flags appended per operation BEFORE any caller-supplied args.
# The diff flags are the empirically verified code-execution neutralizers
# (external diff drivers + textconv both execute repository-selected
# binaries on `git diff`).
_OP_FIXED_ARGS: dict[str, tuple[str, ...]] = {
    "status": ("--porcelain=v1",),
    "diff": ("--no-ext-diff", "--no-textconv"),
    "changed": ("--modified",),
    "untracked": ("--others", "--exclude-standard"),
    "deleted": ("--deleted",),
    "base": ("HEAD",),      # git merge-base HEAD <ref> (ref from caller)
    "current": ("HEAD",),   # git rev-parse HEAD
}

# Configuration control: every key that could select an executable,
# invoke a helper, enable credential access, or redirect an operation.
# ``-c`` has the highest precedence - these override any value in any
# config file (local .git/config included), empirically verified.
_SANITIZING_CONFIG: tuple[str, ...] = (
    "core.hooksPath=/nonexistent-hooks",  # hooks never run (no hook op)
    "core.fsmonitor=",                    # status must never run a monitor cmd
    "core.sshCommand=",                   # never select an ssh transport cmd
    "core.askPass=",                      # never prompt for credentials
    "core.pager=",                        # never spawn a pager
    "pager.diff=",
    "core.editor=",
    "diff.external=",                     # never use an external diff driver
    "credential.helper=",                 # never consult a credential helper
    "credential.interactive=never",
    "submodule.recurse=false",            # never recurse into submodules
    "protocol.file.allow=never",          # never allow file-protocol fetches
)

# The work tree is always pinned to the sandbox workspace. A hostile
# core.worktree in local config could only redirect INSIDE the sandbox
# (contained), but -C pins the canonical location regardless.
_WORK_TREE = "/workspace"


def sanitized_git_argv(operation: str,
                       args: Iterable[str] = (),
                       work_tree: str = _WORK_TREE) -> tuple[str, ...]:
    """Build the complete git argv for a Phase C operation.

    ARGV is the ONLY channel for configuration control - the in-sandbox
    environment is the fixed six-variable sanitized set (S-034), so no
    ``GIT_*`` variable can exist. Caller-supplied args are appended
    VERBATIM after the fixed flags (argv is data; never a shell string).
    ``work_tree`` pins the work tree (production default: the sandbox
    ``/workspace``; tests may point it at a fixture repository). Raises
    ``ValueError`` for any operation outside the closed set (fail
    closed - never a passthrough)."""
    if operation not in GIT_OPERATIONS:
        raise ValueError(
            f"git: unsupported operation {operation!r} - the Phase C "
            f"set is closed and read-only: {', '.join(GIT_OPERATIONS)}")
    argv: list[str] = ["git"]
    for word in _OP_WORDS[operation]:
        # Pin the exact builtin: even a hostile `alias.<word>` in local
        # config cannot redirect the operation (builtins win over
        # same-name aliases; this makes it explicit and complete).
        argv += ["-c", f"alias.{word}={word}"]
    for cfg in _SANITIZING_CONFIG:
        argv += ["-c", cfg]
    argv += ["-C", work_tree]
    argv += list(_OP_WORDS[operation])
    argv += list(_OP_FIXED_ARGS[operation])
    argv += list(args)
    return tuple(argv)
