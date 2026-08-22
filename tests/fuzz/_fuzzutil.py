"""Deterministic mutation helpers for the Phase E fuzz harness.

Every mutation is driven by an explicit ``random.Random`` so the harness is
fully reproducible: same seed -> same mutation stream -> same results.
Budgets are fixed by the callers (the tests), never unbounded.
"""

from __future__ import annotations

import random
from typing import Any, Iterator


def mutate_bytes(rng: random.Random, data: bytes) -> bytes:
    """Byte-level mutations: flip / insert / delete / splice runs."""
    b = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        op = rng.randrange(4)
        if op == 0 and b:
            b[rng.randrange(len(b))] = rng.randrange(256)
        elif op == 1:
            b.insert(rng.randrange(len(b) + 1), rng.randrange(256))
        elif op == 2 and b:
            del b[rng.randrange(len(b))]
        elif op == 3:
            b[rng.randrange(len(b) + 1):rng.randrange(len(b) + 1)] = \
                b"x" * rng.randint(0, 3)
    return bytes(b)


def mutate_string(rng: random.Random, s: str) -> str:
    """Text mutation; the result may be invalid UTF-8 after re-decoding."""
    return mutate_bytes(rng, s.encode("utf-8", errors="replace")).decode(
        "utf-8", errors="replace")


_ATOMIC_SWAPS: tuple[Any, ...] = (
    True, False, None, 0, 1, -1, "", "x", "yes", "true", "1", "[]", "{}",
    [], {}, ["a"], {"a": 1}, 3.14, "\x00", "..", "../", "/etc/passwd", "a" * 1000,
)


def mutate_value(rng: random.Random, value: Any) -> Any:
    """Structural mutation of a JSON-compatible value (type swaps,
    key deletion/rename, value nesting)."""
    if isinstance(value, dict):
        op = rng.randrange(6)
        if not value:
            return value
        keys = list(value)
        if op == 0:  # delete a key
            d = dict(value)
            del d[rng.choice(keys)]
            return d
        if op == 1:  # add a mutated key
            d = dict(value)
            d[mutate_string(rng, rng.choice(keys) + str(rng.randint(0, 9)))] = \
                rng.choice(_ATOMIC_SWAPS)
            return d
        if op == 2:  # rename a key
            d = dict(value)
            k = rng.choice(keys)
            d[mutate_string(rng, k)] = d.pop(k)
            return d
        if op == 3:  # recurse into a value
            d = dict(value)
            d[rng.choice(keys)] = mutate_value(rng, value[rng.choice(keys)])
            return d
        if op == 4:  # type-swap a value
            d = dict(value)
            d[rng.choice(keys)] = rng.choice(_ATOMIC_SWAPS)
            return d
        return value
    if isinstance(value, list):
        if not value:
            return value
        out = list(value)
        out[rng.randrange(len(out))] = mutate_value(rng, out[rng.randrange(len(out))])
        return out
    return rng.choice(_ATOMIC_SWAPS)


def fuzz_stream(rng: random.Random, corpus: list[str], rounds: int,
                mutate) -> Iterator[str]:
    """Yield ``rounds`` mutated strings drawn from ``corpus``."""
    for _ in range(rounds):
        yield mutate(rng, rng.choice(corpus))
