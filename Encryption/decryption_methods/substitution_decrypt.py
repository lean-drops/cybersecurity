# decryption_methods/substitution_decrypt.py
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


def _invert_mapping(mapping: str) -> str:
    # mapping: plain->cipher, produce inv: cipher->plain (as 26-letter string aligned to ALPHABET)
    inv = ["?"] * 26
    for pi, pch in enumerate(ALPHABET):
        cch = mapping[pi]
        ci = ord(cch) - ord("A")
        inv[ci] = pch
    if "?" in inv:
        return ""
    return "".join(inv)


def decrypt(ciphertext: str, config: Dict[str, Any]) -> str:
    mapping = _normalize_mapping(config.get("mapping", ""))
    if not mapping:
        mapping = ALPHABET  # identity fallback

    inv = _invert_mapping(mapping)
    if not inv:
        inv = ALPHABET

    trans = str.maketrans(ALPHABET, inv)
    return ciphertext.translate(trans)


if __name__ == "__main__":
    cfg = {"mapping": "QWERTYUIOPASDFGHJKLZXCVBNM"}
    ct = "ZITL TL Q ZTLZ"
    pt = decrypt(ct, cfg)
    print("ct:", ct)
    print("pt:", pt)
