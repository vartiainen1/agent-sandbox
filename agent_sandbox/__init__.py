"""agent-sandbox - security-first execution environment for autonomous AI agents.

The runtime is Linux-first and rootless. This package is the TRUSTED
host-side supervisor: everything in here runs before and outside the
sandbox boundary. Code executed by the workload never imports this
package - the workload runs inside the isolated environment (see
ARCHITECTURE.md, THREAT_MODEL.md).
"""

__version__ = "0.2.0"
