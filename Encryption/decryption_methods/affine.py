# decryption_methods/affine.py
from __future__ import annotations

from typing import Any, Dict, Tuple

METHOD_ID = "affine"
METHOD_NAME = "Affine (a*x + b mod 26)"
CONFIG_FIELDS = [
    {"key": "a", "label": "a (must be coprime with 26)", "type": "int", "default": 5, "min": 1, "max": 25},
    {"key": "b", "label": "b (0..25)", "type": "int", "default": 8, "min": 0, "max": 25},
]


def _egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def _modinv(a: int, m: int) -> int:
    g, x, _y = _egcd(a, m)
    if g != 1 and g != -1:
        raise ValueError("No modular inverse")
    return x % m


def decrypt(ciphertext: str, config: Dict[str, Any]) -> str:
    a = int(config.get("a", 1))
    b = int(config.get("b", 0)) % 26
    inv = _modinv(a % 26, 26)

    out = []
    for ch in ciphertext:
        o = ord(ch)
        if 65 <= o <= 90:
            y = o - 65
            x = (inv * ((y - b) % 26)) % 26
            out.append(chr(65 + x))
        else:
            out.append(ch)
    return "".join(out)
