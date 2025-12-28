# encryption_methods/dh_hybrid_encrypt.py
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any, Dict, List


METHOD_ID = "dh_hybrid"
METHOD_NAME = "DH shared secret -> stream + HMAC (toy; IND-CPA style)"

CONFIG_FIELDS: List[Dict[str, Any]] = [
    {
        "key": "recipient_pub_hex",
        "label": "Recipient public key (hex; B_pub)",
        "type": "str",
        "default": "",
    },
    {
        "key": "nonce_len",
        "label": "Nonce length (bytes)",
        "type": "int",
        "default": 16,
        "min": 8,
        "max": 32,
    },
    {
        "key": "ephemeral_bits",
        "label": "Ephemeral private bits (demo)",
        "type": "int",
        "default": 256,
        "min": 128,
        "max": 512,
    },
]

# RFC 3526 Group 14 (2048-bit MODP), generator g=2
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
_P = int(_P_HEX, 16)
_G = 2


def _parse_int_hex(s: str) -> int:
    hs = "".join(ch for ch in str(s).strip() if ch in "0123456789abcdefABCDEF")
    if not hs:
        raise ValueError("empty hex")
    return int(hs, 16)


def _int_to_bytes(x: int, length: int) -> bytes:
    return int(x).to_bytes(length, "big", signed=False)


def _kdf_sha256(shared_bytes: bytes) -> bytes:
    return hashlib.sha256(b"DH|" + shared_bytes).digest()


def _prg_stream(key: bytes, nonce: bytes, out_len: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < out_len:
        out.extend(hmac.new(key, nonce + ctr.to_bytes(4, "big"), hashlib.sha256).digest())
        ctr += 1
    return bytes(out[:out_len])


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(plaintext: str, config: Dict[str, Any]) -> str:
    """
    Hybrid (toy) using DH key agreement:
      B has (b_priv, B_pub = g^b mod p)
      A generates ephemeral a, computes A_pub = g^a mod p
      shared = (B_pub)^a mod p
      key = SHA256(shared_bytes)
      nonce = random
      c = m XOR PRG(key, nonce)
      tag = HMAC(SHA256(key||'mac'), nonce||c)

    Output format (ASCII):
      A_pub_hex : nonce_hex : c_hex : tag_hex
    """
    b_pub = _parse_int_hex(config.get("recipient_pub_hex", ""))
    if b_pub <= 1 or b_pub >= _P - 1:
        raise ValueError("recipient_pub_hex out of range")

    try:
        nonce_len = int(config.get("nonce_len", 16))
    except Exception:
        nonce_len = 16
    if nonce_len < 8:
        nonce_len = 8
    if nonce_len > 32:
        nonce_len = 32

    try:
        eph_bits = int(config.get("ephemeral_bits", 256))
    except Exception:
        eph_bits = 256
    if eph_bits < 128:
        eph_bits = 128
    if eph_bits > 512:
        eph_bits = 512

    m = str(plaintext).encode("ascii", errors="replace")

    a = secrets.randbits(eph_bits) % (_P - 2) + 1
    a_pub = pow(_G, a, _P)
    shared = pow(b_pub, a, _P)

    p_len = (_P.bit_length() + 7) // 8
    shared_bytes = _int_to_bytes(shared, p_len)
    key = _kdf_sha256(shared_bytes)
    mac_key = hashlib.sha256(key + b"|mac").digest()

    nonce = secrets.token_bytes(nonce_len)
    ks = _prg_stream(key, nonce, len(m))
    c = _xor_bytes(m, ks)

    tag = hmac.new(mac_key, nonce + c, hashlib.sha256).digest()

    return f"{a_pub:x}:{nonce.hex()}:{c.hex()}:{tag.hex()}"


if __name__ == "__main__":
    # demo requires a real recipient_pub_hex
    print("Set recipient_pub_hex to B_pub to test.")
