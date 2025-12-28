# encryption_methods/vigenere.py
from __future__ import annotations

from typing import Any, Dict

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

METHOD_ID = "vigenere"
METHOD_NAME = "Vigenere (polyalphabetic)"
CONFIG_FIELDS = [
    {"key": "key", "label": "Key (letters)", "type": "str", "default": "LEMON"},
]


def _clean_key(k: str) -> str:
    k = "".join([c for c in (k or "").upper() if "A" <= c <= "Z"])
    return k


def encrypt(plaintext: str, config: Dict[str, Any]) -> str:
    key = _clean_key(str(config.get("key", "")))
    if not key:
        raise ValueError("Vigenere key must contain A-Z letters")

    out = []
    j = 0
    for ch in plaintext:
        o = ord(ch)
        if 65 <= o <= 90:
            ks = ord(key[j % len(key)]) - 65
            out.append(chr(65 + ((o - 65 + ks) % 26)))
            j += 1
        else:
            out.append(ch)
    return "".join(out)
