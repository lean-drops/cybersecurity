# decryption_methods/aead_etm.py
from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any, Dict

METHOD_ID = "aead_etm"
METHOD_NAME = "AEAD (Encrypt-then-MAC, HMAC-SHA256)"
CONFIG_FIELDS = [
    {"key": "passphrase", "label": "Passphrase (empty uses env AEAD_KEY)", "type": "str", "default": "TOULOUSE_NIGHT_KEY"},
    {"key": "aad", "label": "AAD (must match encryption AAD)", "type": "str", "default": ""},
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
    return _SHA(pw.encode("utf-8")).digest()


def _derive_keys(master: bytes) -> tuple[bytes, bytes]:
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


def decrypt(ciphertext: str, config: Dict[str, Any]) -> str:
    master = _get_master_key(config)
    enc_key, mac_key = _derive_keys(master)

    aad_cfg = str(config.get("aad", "") or "").encode("utf-8")

    try:
        blob = base64.urlsafe_b64decode(ciphertext.encode("ascii"))
    except Exception as e:
        raise ValueError(f"Ciphertext is not valid base64: {e}")

    if len(blob) < 3 + 1 + 1 + _TAG_LEN:
        raise ValueError("Ciphertext too short")

    if blob[:3] != _MAGIC:
        raise ValueError("Ciphertext missing AE1 header (wrong method or corrupted data)")

    nonce_len = int(blob[3])
    if nonce_len < 8 or nonce_len > 32:
        raise ValueError("Invalid nonce length in ciphertext")

    off = 4
    if len(blob) < off + nonce_len + 4 + _TAG_LEN:
        raise ValueError("Ciphertext too short for nonce/aad/tag")

    nonce = blob[off : off + nonce_len]
    off += nonce_len

    aad_len = int.from_bytes(blob[off : off + 4], "big", signed=False)
    off += 4

    if len(blob) < off + aad_len + _TAG_LEN:
        raise ValueError("Ciphertext too short for aad/tag")

    aad_in_msg = blob[off : off + aad_len]
    off += aad_len

    tag = blob[-_TAG_LEN:]
    ct = blob[off:-_TAG_LEN]

    # If user provided AAD in config, it must match what was used at encryption time.
    # (This also demonstrates associated data binding.)
    if aad_cfg != aad_in_msg:
        raise ValueError("AAD mismatch (config AAD does not match ciphertext AAD)")

    mac_input = _MAGIC + bytes([nonce_len]) + nonce + aad_len.to_bytes(4, "big", signed=False) + aad_in_msg + ct
    want_tag = hmac.new(mac_key, mac_input, _SHA).digest()

    if not hmac.compare_digest(tag, want_tag):
        raise ValueError("Authentication failed (tag mismatch)")

    ks = _keystream(enc_key, nonce, len(ct))
    pt = _xor_bytes(ct, ks)
    return pt.decode("utf-8", errors="replace")
