# modification_methods/flip_ae1_tag_byte.py
from __future__ import annotations

import base64
from typing import Any, Dict

METHOD_ID = "flip_ae1_tag_byte"
METHOD_NAME = "Flip byte in AEAD (AE1) tag"
CONFIG_FIELDS = [
    {"key": "tag_offset", "label": "Tag byte offset (0..31)", "type": "int", "default": 0, "min": 0, "max": 31},
]

_MAGIC = b"AE1"
_TAG_LEN = 32


def modify(record: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(record)
    ct = str(out.get("ciphertext", ""))

    blob = base64.urlsafe_b64decode(ct.encode("ascii"))
    if len(blob) < 3 + 1 + 8 + 4 + _TAG_LEN or blob[:3] != _MAGIC:
        raise ValueError("Not AE1 ciphertext (expected AEAD-ETM format)")

    off = int(config.get("tag_offset", 0))
    if off < 0 or off >= _TAG_LEN:
        raise ValueError("tag_offset must be 0..31")

    b = bytearray(blob)
    b[-_TAG_LEN + off] ^= 0x01  # flip a bit
    out["ciphertext"] = base64.urlsafe_b64encode(bytes(b)).decode("ascii")
    return out
