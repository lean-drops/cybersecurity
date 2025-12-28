# encryption_methods/ind_good_nonce_stream.py
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any, Dict, List

METHOD_ID = "ind_good_nonce_stream"
METHOD_NAME = "IND-CPA baseline: randomized nonce XOR stream (toy)"

CONFIG_FIELDS: List[Dict[str, Any]] = [
    {
        "key": "key_hex",
        "label": "Key (hex, 32 bytes recommended; demo only)",
        "type": "str",
        "default": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    },
    {
        "key": "nonce_len",
        "label": "Nonce length (bytes)",
        "type": "int",
        "default": 16,
        "min": 8,
        "max": 32,
    },
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
    return str(s).encode("ascii", errors="replace")


def encrypt(plaintext: str, config: Dict[str, Any]) -> str:
    """
    Randomized (toy) nonce-based stream encryption (IND-CPA-style baseline idea):
      nonce <- random
      s = PRG(key, nonce)
      c = m XOR s
      output = nonce_hex : c_hex

    With fresh random nonce each time, same plaintext encrypts to different ciphertexts.
    """
    key = _parse_key_hex(config.get("key_hex", ""))
    try:
        nlen = int(config.get("nonce_len", 16))
    except Exception:
        nlen = 16
    if nlen < 8:
        nlen = 8
    if nlen > 32:
        nlen = 32

    m = _ascii_bytes(plaintext)
    nonce = secrets.token_bytes(nlen)
    s = _prg_stream(key, nonce, len(m))
    c = _xor_bytes(m, s)
    return nonce.hex() + ":" + c.hex()


if __name__ == "__main__":
    cfg = {"key_hex": CONFIG_FIELDS[0]["default"], "nonce_len": 16}
    pt = "HELLO HELLO"
    ct1 = encrypt(pt, cfg)
    ct2 = encrypt(pt, cfg)
    print("ct1 == ct2 ?", ct1 == ct2)
    print("ct1:", ct1)
    print("ct2:", ct2)
