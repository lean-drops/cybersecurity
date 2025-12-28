# decryption_methods/columnar_transposition.py
from __future__ import annotations

from typing import Any, Dict, List, Tuple

METHOD_ID = "columnar"
METHOD_NAME = "Columnar transposition"
CONFIG_FIELDS = [
    {"key": "key", "label": "Key (letters/digits)", "type": "str", "default": "TOULOUSE"},
    {"key": "strip_pad", "label": "Strip pad char (0/1)", "type": "int", "default": 0, "min": 0, "max": 1},
    {"key": "pad_char", "label": "Pad char (single ASCII)", "type": "str", "default": "X"},
]


def _order_from_key(key: str) -> List[int]:
    key = str(key or "")
    pairs: List[Tuple[str, int]] = [(key[i], i) for i in range(len(key))]
    pairs.sort(key=lambda t: (t[0], t[1]))
    return [idx for _ch, idx in pairs]


def decrypt(ciphertext: str, config: Dict[str, Any]) -> str:
    key = str(config.get("key", "")).strip()
    if not key:
        raise ValueError("Columnar key is required")
    cols = len(key)

    if cols <= 0:
        return ciphertext
    if len(ciphertext) % cols != 0:
        raise ValueError("Ciphertext length must be a multiple of key length (padding expected)")

    rows = len(ciphertext) // cols
    order = _order_from_key(key)

    # Build empty matrix
    mat: List[List[str]] = [[""] * cols for _ in range(rows)]

    idx = 0
    for c in order:
        for r in range(rows):
            mat[r][c] = ciphertext[idx]
            idx += 1

    out: List[str] = []
    for r in range(rows):
        out.extend(mat[r])

    plain = "".join(out)

    strip_pad = int(config.get("strip_pad", 0)) == 1
    pad_char = str(config.get("pad_char", "X"))
    pad_char = pad_char[0] if pad_char else "X"
    if strip_pad:
        plain = plain.rstrip(pad_char)

    return plain
