# decryption_methods/ind_cpa_stream.py
from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any, Dict

METHOD_ID = "ind_cpa"
METHOD_NAME = "IND-CPA (randomized PRF stream, HMAC-SHA256)"
CONFIG_FIELDS = [
    {
        "key": "passphrase",
        "label": "Passphrase (empty uses env IND_CPA_KEY)",
        "type": "str",
        "default": "SUMMER_NIGHT_TOULOUSE",
    }
]

_MAGIC = b"IC1"
_SHA = hashlib.sha256


def _get_key_bytes(config: Dict[str, Any]) -> bytes:
    pw = str(config.get("passphrase", "") or "").strip()
    if not pw:
        import os

        pw = str(os.environ.get("IND_CPA_KEY", "") or "").strip()
    if not pw:
        raise ValueError("Missing passphrase (set config.passphrase or env IND_CPA_KEY)")
    return _SHA(pw.encode("utf-8")).digest()  # 32 bytes


def _prf_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    ctr = counter.to_bytes(4, "big", signed=False)
    return hmac.new(key, nonce + ctr, _SHA).digest()  # 32 bytes


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])


def _keystream(key: bytes, nonce: bytes, nbytes: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        out.extend(_prf_block(key, nonce, counter))
        counter += 1
    return bytes(out[:nbytes])


def decrypt(ciphertext: str, config: Dict[str, Any]) -> str:
    key = _get_key_bytes(config)

    try:
        blob = base64.urlsafe_b64decode(ciphertext.encode("ascii"))
    except Exception as e:
        raise ValueError(f"Ciphertext is not valid base64: {e}")

    if len(blob) < 4 or blob[:3] != _MAGIC:
        raise ValueError("Ciphertext missing IC1 header (wrong method or corrupted data)")

    nonce_len = int(blob[3])
    if nonce_len < 8 or nonce_len > 32:
        raise ValueError("Invalid nonce length in ciphertext")

    if len(blob) < 4 + nonce_len:
        raise ValueError("Ciphertext too short")

    nonce = blob[4 : 4 + nonce_len]
    ct = blob[4 + nonce_len :]

    ks = _keystream(key, nonce, len(ct))
    pt = _xor_bytes(ct, ks)
    return pt.decode("utf-8", errors="replace")
