# encryption_methods/columnar_transposition.py
from __future__ import annotations

from typing import Any, Dict, List, Tuple

METHOD_ID = "columnar"
METHOD_NAME = "Columnar transposition"
CONFIG_FIELDS = [
    {"key": "key", "label": "Key (letters/digits)", "type": "str", "default": "TOULOUSE"},
    {"key": "pad_char", "label": "Pad char (single ASCII)", "type": "str", "default": "X"},
]


def _order_from_key(key: str) -> List[int]:
    key = str(key or "")
    pairs: List[Tuple[str, int]] = [(key[i], i) for i in range(len(key))]
    pairs.sort(key=lambda t: (t[0], t[1]))
    return [idx for _ch, idx in pairs]


def encrypt(plaintext: str, config: Dict[str, Any]) -> str:
    key = str(config.get("key", "")).strip()
    if not key:
        raise ValueError("Columnar key is required")
    cols = len(key)

    pad_char = str(config.get("pad_char", "X"))
    pad_char = pad_char[0] if pad_char else "X"

    text = plaintext
    pad = (cols - (len(text) % cols)) % cols
    if pad:
        text = text + (pad_char * pad)

    rows = len(text) // cols
    order = _order_from_key(key)

    out: List[str] = []
    for c in order:
        for r in range(rows):
            out.append(text[r * cols + c])
    return "".join(out)
