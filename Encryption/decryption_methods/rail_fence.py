# decryption_methods/rail_fence.py
from __future__ import annotations

from typing import Any, Dict, List

METHOD_ID = "rail_fence"
METHOD_NAME = "Rail Fence (zigzag transposition)"
CONFIG_FIELDS = [
    {"key": "rails", "label": "Rails (>=2)", "type": "int", "default": 3, "min": 2, "max": 99},
]


def decrypt(ciphertext: str, config: Dict[str, Any]) -> str:
    rails = int(config.get("rails", 2))
    if rails <= 1:
        return ciphertext

    n = len(ciphertext)
    pattern: List[int] = []
    r = 0
    dr = 1
    for _ in range(n):
        pattern.append(r)
        if r == 0:
            dr = 1
        elif r == rails - 1:
            dr = -1
        r += dr

    counts = [0] * rails
    for rr in pattern:
        counts[rr] += 1

    rails_data: List[List[str]] = [[] for _ in range(rails)]
    idx = 0
    for rr in range(rails):
        chunk = list(ciphertext[idx : idx + counts[rr]])
        rails_data[rr] = chunk
        idx += counts[rr]

    pos = [0] * rails
    out: List[str] = []
    for rr in pattern:
        out.append(rails_data[rr][pos[rr]])
        pos[rr] += 1

    return "".join(out)
