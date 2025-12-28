# encryption_methods/aead_etm.py
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Any, Dict

METHOD_ID = "aead_etm"
METHOD_NAME = "AEAD (Encrypt-then-MAC, HMAC-SHA256)"
CONFIG_FIELDS = [
    {"key": "passphrase", "label": "Passphrase (empty uses env AEAD_KEY)", "type": "str", "default": "TOULOUSE_NIGHT_KEY"},
    {"key": "nonce_len", "label": "Nonce length (8..32)", "type": "int", "default": 16, "min": 8, "max": 32},
    {"key": "aad", "label": "AAD (authenticated, not encrypted)", "type": "str", "default": ""},
]

_MAGIC = b"AE1"
_SHA = hashlib.sha256
_TAG_LEN = 32


def _get_master_key(config: Dict[str, Any]) -> bytes:
    pw = str(config.get("passphrase", "") or "").strip()
    if not pw:
        import os

        pw = str(os.environ.get("AEAD_KEY", "") or "").strip()
    if not pw:
        raise ValueError("Missing passphrase (set config.passphrase or env AEAD_KEY)")
    return _SHA(pw.encode("utf-8")).digest()  # 32 bytes


def _derive_keys(master: bytes) -> tuple[bytes, bytes]:
    # Domain-separated key derivation from master key
    enc_key = hmac.new(master, b"ENC", _SHA).digest()
    mac_key = hmac.new(master, b"MAC", _SHA).digest()
    return enc_key, mac_key


def _prf_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    ctr = counter.to_bytes(4, "big", signed=False)
    return hmac.new(key, nonce + ctr, _SHA).digest()


def _keystream(key: bytes, nonce: bytes, nbytes: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        out.extend(_prf_block(key, nonce, counter))
        counter += 1
    return bytes(out[:nbytes])


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])


def encrypt(plaintext: str, config: Dict[str, Any]) -> str:
    master = _get_master_key(config)
    enc_key, mac_key = _derive_keys(master)

    nonce_len = int(config.get("nonce_len", 16))
    if nonce_len < 8 or nonce_len > 32:
        raise ValueError("nonce_len must be in range 8..32")

    aad = str(config.get("aad", "") or "").encode("utf-8")

    pt = plaintext.encode("utf-8")
    nonce = secrets.token_bytes(nonce_len)
    ks = _keystream(enc_key, nonce, len(pt))
    ct = _xor_bytes(pt, ks)

    # Encrypt-then-MAC over: MAGIC || nonce_len || nonce || aad_len || aad || ct
    aad_len = len(aad).to_bytes(4, "big", signed=False)
    mac_input = _MAGIC + bytes([nonce_len]) + nonce + aad_len + aad + ct
    tag = hmac.new(mac_key, mac_input, _SHA).digest()

    blob = _MAGIC + bytes([nonce_len]) + nonce + aad_len + aad + ct + tag
    return base64.urlsafe_b64encode(blob).decode("ascii")
