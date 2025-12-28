# modification_methods/truncate_ciphertext.py
from __future__ import annotations

from typing import Any, Dict

METHOD_ID = "truncate_ciphertext"
METHOD_NAME = "Truncate ciphertext suffix"
CONFIG_FIELDS = [
    {"key": "n", "label": "Remove last N characters (>=1)", "type": "int", "default": 4, "min": 1, "max": 10**9},
]


def modify(record: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(record)
    s = str(out.get("ciphertext", ""))
    n = int(config.get("n", 1))
    if n <= 0:
        return out
    if len(s) <= n:
        out["ciphertext"] = ""
        return out
    out["ciphertext"] = s[:-n]
    return out
