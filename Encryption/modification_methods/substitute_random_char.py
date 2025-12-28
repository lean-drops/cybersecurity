# modification_methods/substitute_random_char.py
from __future__ import annotations

import random
from typing import Any, Dict

METHOD_ID = "substitute_random_char"
METHOD_NAME = "Substitute a random character in ciphertext string"
CONFIG_FIELDS = [
    {"key": "seed", "label": "PRNG seed (int)", "type": "int", "default": 1, "min": 0, "max": 2**31 - 1},
]

_ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"


def modify(record: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(record)
    s = str(out.get("ciphertext", ""))
    if not s:
        raise ValueError("Empty ciphertext")

    rng = random.Random(int(config.get("seed", 1)))
    i = rng.randrange(0, len(s))
    old = s[i]
    choices = [c for c in _ALPH if c != old]
    new = rng.choice(choices) if choices else old
    out["ciphertext"] = s[:i] + new + s[i + 1 :]
    return out
