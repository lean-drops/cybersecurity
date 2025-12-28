# decryption_methods/caesar.py
from __future__ import annotations

from typing import Any, Dict

METHOD_ID = "caesar"
METHOD_NAME = "Caesar shift"
CONFIG_FIELDS = [
    {"key": "shift", "label": "Shift (0-25)", "type": "int", "default": 3, "min": 0, "max": 25},
]


def decrypt(ciphertext: str, config: Dict[str, Any]) -> str:
    shift = int(config.get("shift", 0)) % 26
    out = []
    for ch in ciphertext:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(65 + ((o - 65 - shift) % 26)))
        else:
            out.append(ch)
    return "".join(out)