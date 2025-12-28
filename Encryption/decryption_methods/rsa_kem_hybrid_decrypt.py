# decryption_methods/rsa_kem_hybrid_decrypt.py
from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict, List

METHOD_ID = "rsa_kem_hybrid"
METHOD_NAME = "RSA-KEM hybrid (toy; decrypt with private key)"

CONFIG_FIELDS: List[Dict[str, Any]] = [
    {
        "key": "n_hex",
        "label": "RSA modulus n (hex, must match sender)",
        "type": "str",
        "default": "",
    },
    {
        "key": "d_hex",
        "label": "RSA private exponent d (hex, secret)",
        "type": "str",
        "default": "",
    },
]


def _parse_int_hex(s: str, field_name: str) -> int:
    hs = "".join(ch for ch in str(s).strip() if ch in "0123456789abcdefABCDEF")
    if not hs:
        raise ValueError(field_name + " is empty")
    return int(hs, 16)


def _parse_hex_bytes(s: str) -> bytes:
    hs = "".join(ch for ch in str(s).strip() if ch in "0123456789abcdefABCDEF")
    if len(hs) % 2 == 1:
        hs = "0" + hs
    if not hs:
        return b""
    return bytes.fromhex(hs)


def _int_to_bytes(x: int, length: int) -> bytes:
    if length <= 0:
        return b""
    return int(x).to_bytes(length, "big", signed=False)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _kdf_session_from_r(r: int, n: int) -> bytes:
    n_len = (int(n).bit_length() + 7) // 8
    r_bytes = _int_to_bytes(r, n_len)
    return hashlib.sha256(b"RSA-KEM|" + r_bytes).digest()


def _derive_keys(session: bytes) -> tuple[bytes, bytes]:
    enc_key = hashlib.sha256(b"enc|" + session).digest()
    mac_key = hashlib.sha256(b"mac|" + session).digest()
    return enc_key, mac_key


def _prg_stream(key: bytes, nonce: bytes, out_len: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < out_len:
        out.extend(hmac.new(key, nonce + ctr.to_bytes(4, "big"), hashlib.sha256).digest())
        ctr += 1
    return bytes(out[:out_len])


def decrypt(ciphertext: str, config: Dict[str, Any]) -> str:
    """
    Input format:
      wrap_hex : nonce_hex : c_hex : tag_hex

    Steps:
      r = wrap^d mod n
      session = SHA256("RSA-KEM|" || I2OSP(r))
      verify tag, then m = c XOR PRG(enc_key, nonce)
    """
    n = _parse_int_hex(config.get("n_hex", ""), "n_hex")
    d = _parse_int_hex(config.get("d_hex", ""), "d_hex")

    parts = str(ciphertext).strip().split(":")
    if len(parts) != 4:
        raise ValueError("ciphertext format must be wrap_hex:nonce_hex:c_hex:tag_hex")

    wrap = _parse_int_hex(parts[0], "wrap_hex")
    nonce = _parse_hex_bytes(parts[1])
    c = _parse_hex_bytes(parts[2])
    tag = _parse_hex_bytes(parts[3])

    if n <= 0:
        raise ValueError("n must be > 0")
    if wrap <= 0 or wrap >= n:
        raise ValueError("wrap out of range")

    r = pow(wrap, d, n)
    session = _kdf_session_from_r(r, n)
    enc_key, mac_key = _derive_keys(session)

    exp_tag = hmac.new(mac_key, nonce + c, hashlib.sha256).digest()
    if not hmac.compare_digest(exp_tag, tag):
        raise ValueError("HMAC verify failed (wrong key or tampered ciphertext)")

    ks = _prg_stream(enc_key, nonce, len(c))
    m = _xor_bytes(c, ks)
    return m.decode("ascii", errors="replace")


if __name__ == "__main__":
    print("Need ciphertext + (n_hex, d_hex) to test.")
