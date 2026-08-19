"""Workload execution - bounded output, external timeout, process-tree
containment and cleanup (Phase 1 steps 18-20).

The runner executes the workload ONLY after security initialization
succeeded (the RuntimeSession gate). It runs in the TRUSTED supervisor
process; the workload it spawns is untrusted and fully contained.
"""
