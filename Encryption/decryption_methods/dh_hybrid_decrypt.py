# decryption_methods/dh_hybrid_decrypt.py
from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict, List


METHOD_ID = "dh_hybrid"
METHOD_NAME = "DH shared secret -> stream + HMAC (toy; decrypt)"

CONFIG_FIELDS: List[Dict[str, Any]] = [
    {
        "key": "private_hex",
        "label": "Recipient private key (hex; b_priv)",
        "type": "str",
        "default": "",
    }
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


def _parse_int_hex(s: str) -> int:
    hs = "".join(ch for ch in str(s).strip() if ch in "0123456789abcdefABCDEF")
    if not hs:
        raise ValueError("empty hex")
    return int(hs, 16)


def _parse_hex_bytes(s: str) -> bytes:
    hs = "".join(ch for ch in str(s).strip() if ch in "0123456789abcdefABCDEF")
    if len(hs) % 2 == 1:
        hs = "0" + hs
    if not hs:
        return b""
    return bytes.fromhex(hs)


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


def decrypt(ciphertext: str, config: Dict[str, Any]) -> str:
    """
    Input: A_pub_hex : nonce_hex : c_hex : tag_hex
    shared = (A_pub)^b_priv mod p
    verify tag, then decrypt
    """
    b_priv = _parse_int_hex(config.get("private_hex", ""))
    if b_priv <= 0 or b_priv >= _P - 1:
        raise ValueError("private_hex out of range")

    parts = str(ciphertext).strip().split(":")
    if len(parts) != 4:
        raise ValueError("ciphertext format must be A_pub_hex:nonce_hex:c_hex:tag_hex")

    a_pub = _parse_int_hex(parts[0])
    nonce = _parse_hex_bytes(parts[1])
    c = _parse_hex_bytes(parts[2])
    tag = _parse_hex_bytes(parts[3])

    if a_pub <= 1 or a_pub >= _P - 1:
        raise ValueError("A_pub out of range")

    shared = pow(a_pub, b_priv, _P)
    p_len = (_P.bit_length() + 7) // 8
    shared_bytes = _int_to_bytes(shared, p_len)

    key = _kdf_sha256(shared_bytes)
    mac_key = hashlib.sha256(key + b"|mac").digest()

    exp_tag = hmac.new(mac_key, nonce + c, hashlib.sha256).digest()
    if not hmac.compare_digest(exp_tag, tag):
        raise ValueError("HMAC verify failed (wrong key or tampered ciphertext)")

    ks = _prg_stream(key, nonce, len(c))
    m = _xor_bytes(c, ks)
    return m.decode("ascii", errors="replace")


if __name__ == "__main__":
    print("Need a real ciphertext + private_hex to test.")

Wenn du das “public key encryption” (RSA/ECIES) zusaetzlich willst: in derselben Architektur am besten als hybrid (Public-Key verschluesselt nur einen zufaelligen Session-Key; Message laeuft ueber symmetrisch). Das ist die gleiche Einbettung wie bei DH oben, nur dass statt A_pub ein “wrapped session key” im Ciphertext-Header steht.
