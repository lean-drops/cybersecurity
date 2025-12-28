# decryption_methods/otp_decrypt.py
from __future__ import annotations

from typing import Any, Dict, List


METHOD_ID = "otp"
METHOD_NAME = "One-time pad (toy; requires same pad)"

CONFIG_FIELDS: List[Dict[str, Any]] = [
    {
        "key": "pad_hex",
        "label": "Pad (hex; MUST match sender; NEVER reuse)",
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


def decrypt(ciphertext: str, config: Dict[str, Any]) -> str:
    """
    Input: c_hex
    Decrypt: m = c XOR pad[:len(c)]
    """
    c = _parse_hex(str(ciphertext).strip())
    pad = _parse_hex(config.get("pad_hex", ""))
    if len(pad) < len(c):
        raise ValueError("pad_hex too short for this ciphertext")
    m = _xor_bytes(c, pad[: len(c)])
    return m.decode("ascii", errors="replace")


if __name__ == "__main__":
    cfg = {"pad_hex": "00" * 64}
    print(decrypt("48454c4c4f", cfg))
