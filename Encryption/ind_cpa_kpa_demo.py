# ind_cpa_kpa_demo.py
"""
Educational demo (toy crypto) for:
- Known-Plaintext Attack (KPA)
- Chosen-Plaintext Attack (CPA) and the IND-CPA game

WARNING: This is NOT real-world encryption. It is only for illustrating ideas.
Uses only the Python standard library.
"""

import hashlib
import hmac
import secrets
from typing import Callable, Tuple


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes: lengths must match")
    return bytes(x ^ y for x, y in zip(a, b))


def prg_stream(key: bytes, nonce: bytes, out_len: int) -> bytes:
    """
    Expand to out_len bytes using HMAC-SHA256 as a PRG:
        block_i = HMAC(key, nonce || counter_i)
    """
    out = bytearray()
    counter = 0
    while len(out) < out_len:
        ctr = counter.to_bytes(4, "big")
        out.extend(hmac.new(key, nonce + ctr, hashlib.sha256).digest())
        counter += 1
    return bytes(out[:out_len])


# --- Scheme A: BAD deterministic "stream cipher" (reuses keystream, no nonce/IV) ---

def enc_bad_det(key: bytes, m: bytes) -> bytes:
    # Deterministic keystream for each length -> breaks IND-CPA and is vulnerable under KPA/CPA
    ks = prg_stream(key, b"", len(m))
    return xor_bytes(m, ks)


def dec_bad_det(key: bytes, c: bytes) -> bytes:
    ks = prg_stream(key, b"", len(c))
    return xor_bytes(c, ks)


# --- Scheme B: Better nonce-based scheme (toy CTR-like): c = nonce || (m XOR ks(key, nonce)) ---

NONCE_LEN = 16

def enc_good_nonce(key: bytes, m: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_LEN)
    ks = prg_stream(key, nonce, len(m))
    return nonce + xor_bytes(m, ks)


def dec_good_nonce(key: bytes, c: bytes) -> bytes:
    if len(c) < NONCE_LEN:
        raise ValueError("ciphertext too short")
    nonce = c[:NONCE_LEN]
    body = c[NONCE_LEN:]
    ks = prg_stream(key, nonce, len(body))
    return xor_bytes(body, ks)


# --- Math explanation helpers (ASCII-only prints) ---

def explain_xor_math() -> None:
    print("=== Part 1: XOR math (bitwise addition mod 2) ===")
    print("Notation: XOR is ^")
    print("Key property: a ^ a = 0, and a ^ 0 = a")
    print("So if c = m ^ s, then m = c ^ s (because c ^ s = (m ^ s) ^ s = m ^ (s ^ s) = m ^ 0 = m)")
    print()

    m = b"HELLO"
    s = b"\x01\x02\x03\x04\x05"
    c = xor_bytes(m, s)
    m_rec = xor_bytes(c, s)

    print("Example:")
    print("  m      =", m)
    print("  s(hex) =", s.hex())
    print("  c(hex) =", c.hex())
    print("  m_rec  =", m_rec)
    print("  ok?    =", m_rec == m)
    print()


# --- KPA demo ---

def demo_kpa_on_bad_scheme() -> None:
    print("=== Part 2: KPA demo on bad deterministic scheme ===")
    key = secrets.token_bytes(32)

    # Two messages same length so they share the same reused keystream length
    m1 = b"KNOWN PLAINTEXT BLOCK........"  # 28 bytes
    m2 = b"SECRET MESSAGE BLOCK........"   # 28 bytes
    if len(m1) != len(m2):
        raise RuntimeError("demo messages must match length")

    c1 = enc_bad_det(key, m1)
    c2 = enc_bad_det(key, m2)

    print("Attacker knows one pair (m1, c1) and sees another ciphertext c2.")
    print("Because the scheme reuses the same keystream s, attacker can recover s = m1 ^ c1")
    s_recovered = xor_bytes(m1, c1)
    m2_recovered = xor_bytes(c2, s_recovered)

    print("  m1      =", m1)
    print("  c1(hex) =", c1.hex())
    print("  c2(hex) =", c2.hex())
    print("  rec m2  =", m2_recovered)
    print("  ok?     =", m2_recovered == m2)
    print()


# --- IND-CPA game simulation ---

EncryptOracle = Callable[[bytes], bytes]

def ind_cpa_challenge(enc_oracle: EncryptOracle, m0: bytes, m1: bytes) -> Tuple[int, bytes]:
    if len(m0) != len(m1):
        raise ValueError("IND-CPA game requires equal-length messages")
    b = secrets.randbelow(2)
    c_star = enc_oracle(m0 if b == 0 else m1)
    return b, c_star


def adv_compare_ciphertexts(enc_oracle: EncryptOracle, c_star: bytes) -> int:
    """
    Simple adversary:
    - chooses fixed m0, m1 (same length)
    - asks oracle for Enc(m0)
    - compares with challenge ciphertext
    Works perfectly if encryption is deterministic for same message.
    """
    m0 = b"A" * 32
    c0 = enc_oracle(m0)
    return 0 if c0 == c_star else 1


def simulate_ind_cpa(enc_oracle_factory: Callable[[], EncryptOracle], trials: int) -> float:
    wins = 0
    for _ in range(trials):
        enc_oracle = enc_oracle_factory()
        m0 = b"A" * 32
        m1 = b"B" * 32
        b, c_star = ind_cpa_challenge(enc_oracle, m0, m1)
        b_hat = adv_compare_ciphertexts(enc_oracle, c_star)
        if b_hat == b:
            wins += 1
    return wins / trials


def make_bad_oracle() -> EncryptOracle:
    key = secrets.token_bytes(32)
    return lambda m: enc_bad_det(key, m)


def make_good_oracle() -> EncryptOracle:
    key = secrets.token_bytes(32)
    return lambda m: enc_good_nonce(key, m)


def demo_ind_cpa() -> None:
    print("=== Part 3: IND-CPA game demo (baseline notion) ===")
    trials = 400

    rate_bad = simulate_ind_cpa(make_bad_oracle, trials)
    rate_good = simulate_ind_cpa(make_good_oracle, trials)

    print("Adversary strategy: query Enc(m0) and compare to challenge.")
    print("If scheme is IND-CPA secure, success should be about 0.5 (random guessing).")
    print()
    print("  trials =", trials)
    print("  bad deterministic scheme success rate  =", f"{rate_bad:.3f}")
    print("  good nonce-based scheme success rate   =", f"{rate_good:.3f}")
    print()


# --- Nonce reuse warning demo (why nonces must be unique) ---

def demo_nonce_reuse_problem() -> None:
    print("=== Part 4: Nonce reuse warning (even 'good' schemes break if nonce repeats) ===")
    key = secrets.token_bytes(32)
    nonce = b"\x00" * NONCE_LEN

    m1 = b"ATTACK AT DAWN.............."  # 28 bytes
    m2 = b"ATTACK AT DUSK.............."  # 28 bytes
    if len(m1) != len(m2):
        raise RuntimeError("demo messages must match length")

    # Force nonce reuse (this is exactly what you must NOT do in practice)
    ks = prg_stream(key, nonce, len(m1))
    c1_body = xor_bytes(m1, ks)
    c2_body = xor_bytes(m2, ks)

    # Attacker sees c1_body and c2_body (or full ciphertexts share same nonce).
    # Then: c1 ^ c2 = (m1 ^ ks) ^ (m2 ^ ks) = m1 ^ m2
    x = xor_bytes(c1_body, c2_body)
    x_expected = xor_bytes(m1, m2)

    print("If the same nonce (same keystream) is used twice:")
    print("  c1 ^ c2 = m1 ^ m2   (keystream cancels)")
    print("  (This leaks structure and can lead to plaintext recovery.)")
    print()
    print("  (c1 ^ c2)(hex) =", x.hex())
    print("  (m1 ^ m2)(hex) =", x_expected.hex())
    print("  matches?       =", x == x_expected)
    print()


def main() -> None:
    explain_xor_math()
    demo_kpa_on_bad_scheme()
    demo_ind_cpa()
    demo_nonce_reuse_problem()


if __name__ == "__main__":
    main()