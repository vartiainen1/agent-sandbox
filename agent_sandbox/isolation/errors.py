"""Deterministic isolation failures.

Every mechanism in this package fails closed with a ``NamespaceSetupError``
whose message names the exact step that failed. The fail-closed initializer
converts it into a ``StageCheck(ok=False)`` with that reason - never a raw
traceback, never a silent skip.
"""

from __future__ import annotations


class NamespaceSetupError(RuntimeError):
    """A mandatory isolation step could not be established or verified.
    The message is deterministic and names the failing step."""
