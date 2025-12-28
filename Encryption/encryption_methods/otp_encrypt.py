# encryption_methods/otp_encrypt.py
from __future__ import annotations

from typing import Any, Dict, List


METHOD_ID = "otp"
METHOD_NAME = "One-time pad (toy; requires fresh pad per message)"

CONFIG_FIELDS: List[Dict[str, Any]] = [
    {
        "key": "pad_hex",
        "label": "Pad (hex; MUST be >= message length in bytes; NEVER reuse)",
        "type": "str",
        "default": "",
    }
]


def _parse_hex(s: str) -> bytes:
    hs = "".join(ch for ch in str(s) if ch in "0123456789abcdefABCDEF")
    if len(hs) % 2 == 1:
        hs = "0" + hs
    if not hs:
        return b""
    return bytes.fromhex(hs)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(plaintext: str, config: Dict[str, Any]) -> str:
    """
    OTP (toy representation):
      m = ASCII bytes (non-ASCII becomes '?')
      pad must be secret, random, at least len(m), and used once.

    Output:
      c_hex
    """
    m = str(plaintext).encode("ascii", errors="replace")
    pad = _parse_hex(config.get("pad_hex", ""))
    if len(pad) < len(m):
        raise ValueError("pad_hex too short: need at least len(plaintext) bytes")
    c = _xor_bytes(m, pad[: len(m)])
    return c.hex()


if __name__ == "__main__":
    cfg = {"pad_hex": "00" * 64}
    print(encrypt("HELLO", cfg))
