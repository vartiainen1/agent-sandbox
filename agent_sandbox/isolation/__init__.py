"""Isolation mechanisms - namespaces, filesystem, network, resources.

Implemented in the mandated Phase 1 order (ARCHITECTURE.md section 21):
namespaces (Step 2), filesystem/rootfs (Steps 3-9), network (Step 10),
privileges (Steps 11-12), seccomp (Step 13), resources (Steps 14-15),
environment (Steps 16-17). Each mechanism registers its stage guard in
``agent_sandbox.security.init``; until then the fail-closed initializer
refuses HARDENED/RESTRICTED execution. No mechanism code exists yet in
Step 1 - an empty package is honest structure, not a stub.
"""
