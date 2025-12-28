# encryption_methods/rsa_kem_hybrid_encrypt.py
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any, Dict, List

METHOD_ID = "rsa_kem_hybrid"
METHOD_NAME = "RSA-KEM hybrid (toy; public key -> shared secret -> stream+HMAC)"

CONFIG_FIELDS: List[Dict[str, Any]] = [
    {
        "key": "n_hex",
        "label": "RSA modulus n (hex, public)",
        "type": "str",
        "default": "",
    },
    {
        "key": "e",
        "label": "RSA public exponent e",
        "type": "int",
        "default": 65537,
        "min": 3,
        "max": 2147483647,
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


def _parse_int_hex(s: str) -> int:
    hs = "".join(ch for ch in str(s).strip() if ch in "0123456789abcdefABCDEF")
    if not hs:
        raise ValueError("n_hex is empty")
    return int(hs, 16)


def _int_to_bytes(x: int, length: int) -> bytes:
    if length <= 0:
        return b""
    return int(x).to_bytes(length, "big", signed=False)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _gcd(a: int, b: int) -> int:
    a = abs(int(a))
    b = abs(int(b))
    while b:
        a, b = b, a % b
    return a


def _kdf_session_from_r(r: int, n: int) -> bytes:
    # RSA-KEM: derive symmetric session key from r (not from plaintext)
    n_len = (int(n).bit_length() + 7) // 8
    r_bytes = _int_to_bytes(r, n_len)
    return hashlib.sha256(b"RSA-KEM|" + r_bytes).digest()  # 32 bytes


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


def encrypt(plaintext: str, config: Dict[str, Any]) -> str:
    """
    Educational hybrid design (toy):
      - RSA-KEM: choose random r in Z_n*, wrap = r^e mod n
      - session = SHA256("RSA-KEM|" || I2OSP(r))
      - symmetric: c = m XOR PRG(enc_key, nonce), tag = HMAC(mac_key, nonce||c)

    Output format (ASCII):
      wrap_hex : nonce_hex : c_hex : tag_hex
    """
    n = _parse_int_hex(config.get("n_hex", ""))
    try:
        e = int(config.get("e", 65537))
    except Exception:
        e = 65537

    if n <= 0:
        raise ValueError("n must be > 0")
    if e <= 1 or e >= n:
        raise ValueError("e out of range")

    try:
        nonce_len = int(config.get("nonce_len", 16))
    except Exception:
        nonce_len = 16
    if nonce_len < 8:
        nonce_len = 8
    if nonce_len > 32:
        nonce_len = 32

    # Message as ASCII bytes to keep everything ASCII-safe end-to-end.
    m = str(plaintext).encode("ascii", errors="replace")

    # Sample r in Z_n* (gcd(r,n)=1) so RSA inversion behaves as expected.
    # Retry is fine for demo; for large RSA moduli it almost always succeeds quickly.
    while True:
        r = secrets.randbelow(n - 3) + 2  # [2, n-2]
        if _gcd(r, n) == 1:
            break

    wrap = pow(r, e, n)
    session = _kdf_session_from_r(r, n)
    enc_key, mac_key = _derive_keys(session)

    nonce = secrets.token_bytes(nonce_len)
    ks = _prg_stream(enc_key, nonce, len(m))
    c = _xor_bytes(m, ks)
    tag = hmac.new(mac_key, nonce + c, hashlib.sha256).digest()

    return f"{wrap:x}:{nonce.hex()}:{c.hex()}:{tag.hex()}"


if __name__ == "__main__":
    # This is only a smoke-test for formatting; you need a real RSA public key (n,e).
    print("Set n_hex (public modulus) to use this plugin.")
