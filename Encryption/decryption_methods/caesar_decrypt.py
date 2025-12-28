# decryption_methods/caesar_decrypt.py
from __future__ import annotations

from typing import Any, Dict, List

A_ORD = ord("A")

METHOD_ID = "caesar"
METHOD_NAME = "Caesar shift"

CONFIG_FIELDS: List[Dict[str, Any]] = [
    {
        "key": "shift",
        "label": "Shift (0-25)",
        "type": "int",
        "default": 3,
        "min": 0,
        "max": 25,
    }
]


def _get_shift(config: Dict[str, Any]) -> int:
    try:
        s = int(config.get("shift", 0))
    except Exception:
        s = 0
    return s % 26


def decrypt(ciphertext: str, config: Dict[str, Any]) -> str:
    shift = _get_shift(config)
    out: List[str] = []
    for ch in ciphertext:
        o = ord(ch)
        if A_ORD <= o <= A_ORD + 25:
            i = o - A_ORD
            out.append(chr(A_ORD + ((i - shift) % 26)))
        else:
            out.append(ch)
    return "".join(out)


if __name__ == "__main__":
    cfg = {"shift": 3}
    ct = "KHOOR ZRUOG"
    pt = decrypt(ct, cfg)
    print("ct:", ct)
    print("pt:", pt)
