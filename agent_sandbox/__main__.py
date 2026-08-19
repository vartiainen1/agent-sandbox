"""``python -m agent_sandbox`` entry point (thin CLI front-end, ADR-013)."""

import sys

from agent_sandbox.cli import main

if __name__ == "__main__":
    sys.exit(main())
