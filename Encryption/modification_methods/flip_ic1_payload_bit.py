# modification_methods/flip_ic1_payload_bit.py
from __future__ import annotations

import base64
from typing import Any, Dict

METHOD_ID = "flip_ic1_payload_bit"
METHOD_NAME = "Flip bit in IND-CPA (IC1) payload"
CONFIG_FIELDS = [
    {"key": "byte_offset", "label": "Byte offset into payload ciphertext (>=0)", "type": "int", "default": 0, "min": 0, "max": 10**9},
    {"key": "bit_index", "label": "Bit index (0..7)", "type": "int", "default": 0, "min": 0, "max": 7},
]

_MAGIC = b"IC1"


def modify(record: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(record)
    ct = str(out.get("ciphertext", ""))

    blob = base64.urlsafe_b64decode(ct.encode("ascii"))
    if len(blob) < 4 or blob[:3] != _MAGIC:
        raise ValueError("Not IC1 ciphertext (expected IND-CPA stream format)")

    nonce_len = int(blob[3])
    if nonce_len < 8 or nonce_len > 32:
        raise ValueError("Invalid nonce length")
    if len(blob) < 4 + nonce_len:
        raise ValueError("Too short")

    payload = bytearray(blob[4 + nonce_len :])
    off = int(config.get("byte_offset", 0))
    bit = int(config.get("bit_index", 0))
    if off < 0 or off >= len(payload):
        raise ValueError("byte_offset out of range for payload")
    if bit < 0 or bit > 7:
        raise ValueError("bit_index must be 0..7")

    payload[off] ^= (1 << bit)

    new_blob = blob[: 4 + nonce_len] + bytes(payload)
    out["ciphertext"] = base64.urlsafe_b64encode(new_blob).decode("ascii")
    return out
