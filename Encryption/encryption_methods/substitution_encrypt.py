# encryption_methods/substitution_encrypt.py
from __future__ import annotations

from typing import Any, Dict, List

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

METHOD_ID = "substitution"
METHOD_NAME = "Monoalphabetic substitution"

CONFIG_FIELDS: List[Dict[str, Any]] = [
    {
        "key": "mapping",
        "label": "Mapping (26 letters; plaintext A..Z -> ciphertext)",
        "type": "str",
        "default": "QWERTYUIOPASDFGHJKLZXCVBNM",
    }
]


def _normalize_mapping(s: str) -> str:
    s2 = "".join(ch for ch in str(s).upper() if "A" <= ch <= "Z")
    if len(s2) != 26:
        return ""
    if set(s2) != set(ALPHABET):
        return ""
    return s2


def encrypt(plaintext: str, config: Dict[str, Any]) -> str:
    mapping = _normalize_mapping(config.get("mapping", ""))
    if not mapping:
        mapping = ALPHABET  # identity fallback

    trans = str.maketrans(ALPHABET, mapping)
    return plaintext.translate(trans)


if __name__ == "__main__":
    cfg = {"mapping": "QWERTYUIOPASDFGHJKLZXCVBNM"}
    pt = "THIS IS A TEST MESSAGE"
    ct = encrypt(pt, cfg)
    print("pt:", pt)
    print("ct:", ct)
