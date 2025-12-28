# decryption_methods/ind_good_nonce_stream.py
from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict, List

METHOD_ID = "ind_good_nonce_stream"
METHOD_NAME = "IND-CPA baseline: randomized nonce XOR stream (toy)"

CONFIG_FIELDS: List[Dict[str, Any]] = [
    {
        "key": "key_hex",
        "label": "Key (hex, must match sender; demo only)",
        "type": "str",
        "default": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    },
    {
        "key": "nonce_len",
        "label": "Nonce length (bytes, must match sender)",
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


def decrypt(ciphertext: str, config: Dict[str, Any]) -> str:
    """
    Input format: nonce_hex : c_hex
    Decrypt:
      s = PRG(key, nonce)
      m = c XOR s
    """
    key = _parse_key_hex(config.get("key_hex", ""))

    parts = str(ciphertext).strip().split(":", 1)
    if len(parts) != 2:
        raise ValueError("ciphertext format must be nonce_hex:c_hex")

    nonce_hex, c_hex = parts[0].strip(), parts[1].strip()
    nonce = bytes.fromhex("".join(ch for ch in nonce_hex if ch in "0123456789abcdefABCDEF"))
    c = bytes.fromhex("".join(ch for ch in c_hex if ch in "0123456789abcdefABCDEF"))

    s = _prg_stream(key, nonce, len(c))
    m = _xor_bytes(c, s)
    return m.decode("ascii", errors="replace")


if __name__ == "__main__":
    cfg = {"key_hex": CONFIG_FIELDS[0]["default"], "nonce_len": 16}
    print(decrypt("00:00", cfg))
