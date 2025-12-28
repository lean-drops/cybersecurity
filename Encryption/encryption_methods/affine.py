# encryption_methods/affine.py
from __future__ import annotations

from typing import Any, Dict

METHOD_ID = "affine"
METHOD_NAME = "Affine (a*x + b mod 26)"
CONFIG_FIELDS = [
    {"key": "a", "label": "a (must be coprime with 26)", "type": "int", "default": 5, "min": 1, "max": 25},
    {"key": "b", "label": "b (0..25)", "type": "int", "default": 8, "min": 0, "max": 25},
]


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def encrypt(plaintext: str, config: Dict[str, Any]) -> str:
    a = int(config.get("a", 1))
    b = int(config.get("b", 0)) % 26
    if _gcd(a, 26) != 1:
        raise ValueError("Affine 'a' must be coprime with 26")

    out = []
    for ch in plaintext:
        o = ord(ch)
        if 65 <= o <= 90:
            x = o - 65
            y = (a * x + b) % 26
            out.append(chr(65 + y))
        else:
            out.append(ch)
    return "".join(out)
