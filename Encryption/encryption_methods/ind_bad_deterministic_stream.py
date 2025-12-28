# encryption_methods/ind_bad_deterministic_stream.py
from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict, List

METHOD_ID = "ind_bad_det_stream"
METHOD_NAME = "IND-CPA broken: deterministic XOR stream (do not use)"

CONFIG_FIELDS: List[Dict[str, Any]] = [
    {
        "key": "key_hex",
        "label": "Key (hex, 32 bytes recommended; demo only)",
        "type": "str",
        "default": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    }
]


def _parse_key_hex(s: str) -> bytes:
    s2 = "".join(ch for ch in str(s).strip() if ch in "0123456789abcdefABCDEF")
    if len(s2) < 32:
        raise ValueError("key_hex too short (need at least 16 bytes / 32 hex chars)")
    if len(s2) % 2 == 1:
        s2 = "0" + s2
    return bytes.fromhex(s2)


def _prg_stream(key: bytes, nonce: bytes, out_len: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < out_len:
        block = hmac.new(key, nonce + ctr.to_bytes(4, "big"), hashlib.sha256).digest()
        out.extend(block)
        ctr += 1
    return bytes(out[:out_len])


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _ascii_bytes(s: str) -> bytes:
    # Keep output ASCII-only. Non-ASCII becomes '?'.
    return str(s).encode("ascii", errors="replace")


def encrypt(plaintext: str, config: Dict[str, Any]) -> str:
    """
    BAD deterministic construction (breaks IND-CPA):
      s = PRG(key, nonce="")      (no randomness / no nonce)
      c = m XOR s
    Same plaintext => same ciphertext under the same key.
    Output format: hex(cipher_bytes)
    """
    key = _parse_key_hex(config.get("key_hex", ""))
    m = _ascii_bytes(plaintext)
    s = _prg_stream(key, b"", len(m))
    c = _xor_bytes(m, s)
    return c.hex()


if __name__ == "__main__":
    cfg = {"key_hex": CONFIG_FIELDS[0]["default"]}
    pt = "HELLO HELLO"
    ct1 = encrypt(pt, cfg)
    ct2 = encrypt(pt, cfg)
    print("ct1 == ct2 ?", ct1 == ct2)
    print("ct:", ct1)
