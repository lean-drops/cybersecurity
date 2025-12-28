# encryption_methods/rail_fence.py
from __future__ import annotations

from typing import Any, Dict, List

METHOD_ID = "rail_fence"
METHOD_NAME = "Rail Fence (zigzag transposition)"
CONFIG_FIELDS = [
    {"key": "rails", "label": "Rails (>=2)", "type": "int", "default": 3, "min": 2, "max": 99},
]


def encrypt(plaintext: str, config: Dict[str, Any]) -> str:
    rails = int(config.get("rails", 2))
    if rails <= 1:
        return plaintext

    rows: List[List[str]] = [[] for _ in range(rails)]
    r = 0
    dr = 1
    for ch in plaintext:
        rows[r].append(ch)
        if r == 0:
            dr = 1
        elif r == rails - 1:
            dr = -1
        r += dr

    return "".join("".join(row) for row in rows)
