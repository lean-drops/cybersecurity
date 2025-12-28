# encryption_methods/substitution.py
from __future__ import annotations

from typing import Any, Dict

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

METHOD_ID = "substitution"
METHOD_NAME = "Monoalphabetic substitution"
CONFIG_FIELDS = [
    {
        "key": "key",
        "label": "Key (26 letters; mapping A->key[0], ...)",
        "type": "str",
        "default": "QWERTYUIOPASDFGHJKLZXCVBNM",
    },
]


def _clean_key(k: str) -> str:
    k = "".join([c for c in (k or "").upper() if "A" <= c <= "Z"])
    return k


def _validate_key(k: str) -> str:
    k = _clean_key(k)
    if len(k) != 26:
        raise ValueError("Key must have exactly 26 A-Z letters")
    if len(set(k)) != 26:
        raise ValueError("Key must be a permutation (no duplicates)")
    return k


def encrypt(plaintext: str, config: Dict[str, Any]) -> str:
    key = _validate_key(str(config.get("key", "")))
    trans = str.maketrans(ALPHABET, key)
    return plaintext.translate(trans)