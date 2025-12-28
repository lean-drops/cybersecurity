# decryption_methods/atbash.py
from __future__ import annotations

from typing import Any, Dict

METHOD_ID = "atbash"
METHOD_NAME = "Atbash (A<->Z)"
CONFIG_FIELDS = []


def decrypt(ciphertext: str, _config: Dict[str, Any]) -> str:
    # Atbash is its own inverse
    out = []
    for ch in ciphertext:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(65 + (25 - (o - 65))))
        else:
            out.append(ch)
    return "".join(out)
