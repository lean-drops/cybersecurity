# encryption_methods/ind_cpa_stream.py
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Any, Dict

METHOD_ID = "ind_cpa"
METHOD_NAME = "IND-CPA (randomized PRF stream, HMAC-SHA256)"
CONFIG_FIELDS = [
    {
        "key": "passphrase",
        "label": "Passphrase (empty uses env IND_CPA_KEY)",
        "type": "str",
        "default": "SUMMER_NIGHT_TOULOUSE",
    },
    {"key": "nonce_len", "label": "Nonce length (8..32)", "type": "int", "default": 16, "min": 8, "max": 32},
]

_MAGIC = b"IC1"  # version tag
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


def encrypt(plaintext: str, config: Dict[str, Any]) -> str:
    # Randomized encryption: fresh nonce each call -> IND-CPA (assuming PRF security)
    key = _get_key_bytes(config)

    nonce_len = int(config.get("nonce_len", 16))
    if nonce_len < 8 or nonce_len > 32:
        raise ValueError("nonce_len must be in range 8..32")

    pt = plaintext.encode("utf-8")
    nonce = secrets.token_bytes(nonce_len)
    ks = _keystream(key, nonce, len(pt))
    ct = _xor_bytes(pt, ks)

    blob = _MAGIC + bytes([nonce_len]) + nonce + ct
    return base64.urlsafe_b64encode(blob).decode("ascii")
