# Defense/ind_cpa_kpa_demo_gui.py
"""
Toy crypto GUI demo with detailed math for:
- KPA (known-plaintext attack) on a bad deterministic XOR "stream cipher"
- CPA / IND-CPA game simulation (semantic security baseline)
- Nonce reuse problem (why nonces/IVs must be unique)

NOT real encryption. Educational only.
Standard library only. Tkinter GUI.

Key idea to remember:
  XOR "stream encryption": c = m XOR s
  If s repeats, XOR cancels and attacks become easy.
"""

import hashlib
import hmac
import secrets
import tkinter as tk
from tkinter import ttk
from typing import Callable, Tuple


# -----------------------------
# Byte / math helpers
# -----------------------------

def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes: lengths must match")
    return bytes(x ^ y for x, y in zip(a, b))


def to_hex(b: bytes, group: int = 2) -> str:
    h = b.hex()
    if group <= 0:
        return h
    return " ".join(h[i:i + group] for i in range(0, len(h), group))


def pad_to_equal(a: bytes, b: bytes, pad_byte: int = 0x2E) -> Tuple[bytes, bytes]:
    # pad_byte default '.' (0x2E)
    L = max(len(a), len(b))
    return a.ljust(L, bytes([pad_byte])), b.ljust(L, bytes([pad_byte]))


# -----------------------------
# Toy PRG and schemes
# -----------------------------

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


# Scheme A: BAD deterministic scheme
#   - no nonce/IV
#   - keystream depends only on (key, message_length)
#   - so encrypting the same message twice gives identical ciphertext
def enc_bad_det(key: bytes, m: bytes) -> bytes:
    s = prg_stream(key, b"", len(m))
    return xor_bytes(m, s)


def dec_bad_det(key: bytes, c: bytes) -> bytes:
    s = prg_stream(key, b"", len(c))
    return xor_bytes(c, s)


# Scheme B: nonce-based scheme (toy CTR-like)
#   c = nonce || (m XOR s(key, nonce))
NONCE_LEN = 16


def enc_good_nonce(key: bytes, m: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_LEN)
    s = prg_stream(key, nonce, len(m))
    return nonce + xor_bytes(m, s)


def dec_good_nonce(key: bytes, c: bytes) -> bytes:
    if len(c) < NONCE_LEN:
        raise ValueError("ciphertext too short")
    nonce = c[:NONCE_LEN]
    body = c[NONCE_LEN:]
    s = prg_stream(key, nonce, len(body))
    return xor_bytes(body, s)


# -----------------------------
# IND-CPA simulation (CPA model)
# -----------------------------

EncryptOracle = Callable[[bytes], bytes]


def ind_cpa_challenge(enc_oracle: EncryptOracle, m0: bytes, m1: bytes) -> Tuple[int, bytes]:
    """
    IND-CPA experiment:
      - attacker chooses m0, m1 of equal length
      - challenger samples b in {0,1}, returns c* = Enc(m_b)
      - attacker outputs guess b_hat

    Security: attacker should not do much better than 1/2.
    """
    if len(m0) != len(m1):
        raise ValueError("IND-CPA requires equal-length messages")
    b = secrets.randbelow(2)
    c_star = enc_oracle(m0 if b == 0 else m1)
    return b, c_star


def adv_compare_ciphertexts(enc_oracle: EncryptOracle, c_star: bytes, m0: bytes) -> int:
    """
    Very simple CPA attacker:
      - query Enc(m0) once to get c0
      - if c0 == c* guess b=0 else guess b=1

    This wins with probability ~1 when Enc is deterministic.
    It fails (goes to ~1/2) when Enc is properly randomized (fresh nonce).
    """
    c0 = enc_oracle(m0)
    return 0 if c0 == c_star else 1


def simulate_ind_cpa(enc_oracle_factory: Callable[[], EncryptOracle], trials: int) -> float:
    wins = 0
    m0 = b"A" * 32
    m1 = b"B" * 32
    for _ in range(trials):
        enc_oracle = enc_oracle_factory()
        b, c_star = ind_cpa_challenge(enc_oracle, m0, m1)
        b_hat = adv_compare_ciphertexts(enc_oracle, c_star, m0)
        if b_hat == b:
            wins += 1
    return wins / trials


def make_bad_oracle() -> EncryptOracle:
    key = secrets.token_bytes(32)
    return lambda m: enc_bad_det(key, m)


def make_good_oracle() -> EncryptOracle:
    key = secrets.token_bytes(32)
    return lambda m: enc_good_nonce(key, m)


# -----------------------------
# Detailed explanation builders
# -----------------------------

def explain_xor_core() -> str:
    lines = []
    lines.append("XOR BASICS (bitwise addition mod 2)")
    lines.append("")
    lines.append("XOR has two cancellation identities:")
    lines.append("  (1) x XOR x = 0")
    lines.append("  (2) x XOR 0 = x")
    lines.append("")
    lines.append("If a scheme encrypts by XORing with a keystream s:")
    lines.append("  c = m XOR s")
    lines.append("")
    lines.append("Then decryption is the same operation (XOR again with s):")
    lines.append("  c XOR s = (m XOR s) XOR s")
    lines.append("          = m XOR (s XOR s)")
    lines.append("          = m XOR 0")
    lines.append("          = m")
    lines.append("")
    m = b"HELLO"
    s = b"\x01\x02\x03\x04\x05"
    c = xor_bytes(m, s)
    m_rec = xor_bytes(c, s)
    lines.append("Tiny example (bytes shown as hex):")
    lines.append(f"  m      = {m!r}")
    lines.append(f"  s      = {to_hex(s)}")
    lines.append(f"  c=m^s  = {to_hex(c)}")
    lines.append(f"  m=c^s  = {m_rec!r}  (ok={m_rec==m})")
    lines.append("")
    return "\n".join(lines)


def build_kpa_demo(m1_text: str, m2_text: str) -> str:
    """
    KPA demo on the bad deterministic scheme.
    Attacker knows (m1, c1) and sees c2. Recovers m2.

    Math:
      c1 = m1 XOR s
      c2 = m2 XOR s
    Given m1,c1 => s = m1 XOR c1
    Then m2 = c2 XOR s
    """
    key = secrets.token_bytes(32)

    m1 = m1_text.encode("utf-8", errors="replace")
    m2 = m2_text.encode("utf-8", errors="replace")
    m1, m2 = pad_to_equal(m1, m2)

    c1 = enc_bad_det(key, m1)
    c2 = enc_bad_det(key, m2)

    # Attacker computation:
    s_rec = xor_bytes(m1, c1)
    m2_rec = xor_bytes(c2, s_rec)

    lines = []
    lines.append("KPA DEMO (Known-Plaintext Attack) on BAD deterministic XOR-stream scheme")
    lines.append("")
    lines.append("Bad scheme definition:")
    lines.append("  s = PRG(key, length)            (NO nonce/IV, deterministic)")
    lines.append("  c = m XOR s")
    lines.append("")
    lines.append("Attacker knowledge (KPA): knows ONE plaintext/ciphertext pair and sees another ciphertext.")
    lines.append("Here attacker knows (m1, c1) and sees c2. Goal: recover m2.")
    lines.append("")
    lines.append("Equations:")
    lines.append("  c1 = m1 XOR s")
    lines.append("  c2 = m2 XOR s")
    lines.append("")
    lines.append("Derivation:")
    lines.append("  s = m1 XOR c1        (because m1 XOR c1 = m1 XOR (m1 XOR s) = (m1 XOR m1) XOR s = 0 XOR s = s)")
    lines.append("  m2 = c2 XOR s")
    lines.append("")
    lines.append(f"Lengths: len(m1)=len(m2)={len(m1)} (we padded with '.' if needed)")
    lines.append("")
    lines.append("Values (hex):")
    lines.append(f"  m1       = {m1!r}")
    lines.append(f"  c1       = {to_hex(c1)}")
    lines.append(f"  c2       = {to_hex(c2)}")
    lines.append(f"  s_rec    = {to_hex(s_rec)}")
    lines.append("")
    lines.append("Recovered:")
    lines.append(f"  m2_rec   = {m2_rec!r}")
    lines.append(f"  m2_true  = {m2!r}")
    lines.append(f"  ok?      = {m2_rec == m2}")
    lines.append("")
    lines.append("Takeaway:")
    lines.append("  Deterministic keystream reuse makes KPA devastating: one known pair reveals the keystream.")
    lines.append("")
    return "\n".join(lines)


def build_ind_cpa_demo(trials: int) -> str:
    if trials <= 0:
        trials = 1

    rate_bad = simulate_ind_cpa(make_bad_oracle, trials)
    rate_good = simulate_ind_cpa(make_good_oracle, trials)

    # Advantage estimate: Adv ~ |Pr[win] - 1/2|
    adv_bad = abs(rate_bad - 0.5)
    adv_good = abs(rate_good - 0.5)

    lines = []
    lines.append("CPA / IND-CPA DEMO (semantic security baseline)")
    lines.append("")
    lines.append("CPA model: attacker can query Enc_k(m) on chosen messages (an 'encryption oracle').")
    lines.append("")
    lines.append("IND-CPA experiment:")
    lines.append("  1) Attacker chooses two equal-length messages m0, m1")
    lines.append("  2) Challenger picks random b in {0,1} and returns c* = Enc_k(m_b)")
    lines.append("  3) Attacker continues to query Enc_k(.) (still no decryption oracle)")
    lines.append("  4) Attacker outputs guess b_hat; wins if b_hat=b")
    lines.append("")
    lines.append("Security goal (informal):")
    lines.append("  Attacker cannot learn which message was encrypted; best is guessing.")
    lines.append("  So Pr[win] should be about 1/2, and advantage Adv = |Pr[win] - 1/2| should be small.")
    lines.append("")
    lines.append("Attacker used in this demo:")
    lines.append("  - Query Enc(m0) once to get c0")
    lines.append("  - If c0 == c* guess b=0 else b=1")
    lines.append("")
    lines.append("Why it works on deterministic encryption:")
    lines.append("  If Enc is deterministic, Enc(m0) is ALWAYS the same ciphertext.")
    lines.append("  So c0==c* exactly when b=0 -> attacker wins ~1.0.")
    lines.append("")
    lines.append("Why it fails on randomized (nonce-based) encryption:")
    lines.append("  If Enc uses a fresh random nonce each time, Enc(m0) changes each query.")
    lines.append("  Then c0 almost never equals c*, so attacker falls back to near-random guessing (~1/2).")
    lines.append("")
    lines.append(f"Results over {trials} trials:")
    lines.append(f"  BAD deterministic scheme:  Pr[win]={rate_bad:.3f}  Adv~{adv_bad:.3f}")
    lines.append(f"  GOOD nonce-based scheme:   Pr[win]={rate_good:.3f}  Adv~{adv_good:.3f}")
    lines.append("")
    lines.append("Takeaway:")
    lines.append("  IND-CPA (semantic security) requires encryption to be randomized (nonce/IV) and used correctly.")
    lines.append("")
    return "\n".join(lines)


def build_nonce_reuse_demo(m1_text: str, m2_text: str) -> str:
    """
    Show the classic stream/CTR nonce-reuse problem:
      c1 = m1 XOR s
      c2 = m2 XOR s
    => c1 XOR c2 = m1 XOR m2
    """
    key = secrets.token_bytes(32)
    nonce = b"\x00" * NONCE_LEN

    m1 = m1_text.encode("utf-8", errors="replace")
    m2 = m2_text.encode("utf-8", errors="replace")
    m1, m2 = pad_to_equal(m1, m2)

    s = prg_stream(key, nonce, len(m1))
    c1 = xor_bytes(m1, s)
    c2 = xor_bytes(m2, s)

    left = xor_bytes(c1, c2)
    right = xor_bytes(m1, m2)

    lines = []
    lines.append("NONCE REUSE DEMO (why repeating a nonce breaks stream/CTR-style encryption)")
    lines.append("")
    lines.append("Nonce-based XOR-stream encryption (toy CTR idea):")
    lines.append("  s = PRG(key, nonce, length)")
    lines.append("  c = m XOR s")
    lines.append("")
    lines.append("If the SAME nonce is reused for two encryptions, the SAME s is reused:")
    lines.append("  c1 = m1 XOR s")
    lines.append("  c2 = m2 XOR s")
    lines.append("")
    lines.append("XOR them together:")
    lines.append("  c1 XOR c2 = (m1 XOR s) XOR (m2 XOR s)")
    lines.append("            = m1 XOR m2 XOR (s XOR s)")
    lines.append("            = m1 XOR m2 XOR 0")
    lines.append("            = m1 XOR m2")
    lines.append("")
    lines.append("So the keystream cancels and the attacker learns m1 XOR m2.")
    lines.append("That leaks structure (and often enables recovering both messages with guesses/cribs).")
    lines.append("")
    lines.append(f"len(m1)=len(m2)={len(m1)} (padded with '.' if needed)")
    lines.append("Values (hex):")
    lines.append(f"  m1       = {m1!r}")
    lines.append(f"  m2       = {m2!r}")
    lines.append(f"  c1       = {to_hex(c1)}")
    lines.append(f"  c2       = {to_hex(c2)}")
    lines.append("")
    lines.append("Check the identity:")
    lines.append(f"  c1^c2    = {to_hex(left)}")
    lines.append(f"  m1^m2    = {to_hex(right)}")
    lines.append(f"  matches? = {left == right}")
    lines.append("")
    lines.append("Takeaway:")
    lines.append("  Nonces must be unique per key for stream/CTR-style encryption.")
    lines.append("")
    return "\n".join(lines)


# -----------------------------
# GUI widgets
# -----------------------------

class ScrolledText(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.text = tk.Text(self, wrap=tk.WORD)
        self.vsb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.text.yview)
        self.text.configure(yscrollcommand=self.vsb.set)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def set(self, s: str) -> None:
        self.text.delete("1.0", tk.END)
        self.text.insert(tk.END, s)
        self.text.see(tk.END)

    def append(self, s: str) -> None:
        self.text.insert(tk.END, s)
        if not s.endswith("\n"):
            self.text.insert(tk.END, "\n")
        self.text.see(tk.END)


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("KPA + CPA/IND-CPA Demo (Toy Crypto, with math)")
        self.geometry("1100x760")
        self._build()

    def _build(self) -> None:
        root = ttk.Frame(self, padding=10)
        root.pack(fill=tk.BOTH, expand=True)

        nb = ttk.Notebook(root)
        nb.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Concepts
        tab_concepts = ttk.Frame(nb, padding=10)
        nb.add(tab_concepts, text="1) XOR + Concepts")
        self.out_concepts = ScrolledText(tab_concepts)
        self.out_concepts.pack(fill=tk.BOTH, expand=True)
        self.out_concepts.set(
            "This GUI prints detailed math for the three topics.\n\n"
            "Use the other tabs to run interactive demos.\n\n"
            + explain_xor_core()
        )

        # Tab 2: KPA
        tab_kpa = ttk.Frame(nb, padding=10)
        nb.add(tab_kpa, text="2) KPA demo")
        self._build_kpa_tab(tab_kpa)

        # Tab 3: IND-CPA
        tab_cpa = ttk.Frame(nb, padding=10)
        nb.add(tab_cpa, text="3) CPA / IND-CPA")
        self._build_cpa_tab(tab_cpa)

        # Tab 4: Nonce reuse
        tab_nonce = ttk.Frame(nb, padding=10)
        nb.add(tab_nonce, text="4) Nonce reuse")
        self._build_nonce_tab(tab_nonce)

    def _build_kpa_tab(self, parent: ttk.Frame) -> None:
        top = ttk.Frame(parent)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Known plaintext m1:").grid(row=0, column=0, sticky="w")
        ttk.Label(top, text="Secret plaintext m2 (for demo):").grid(row=1, column=0, sticky="w")

        self.kpa_m1 = tk.StringVar(value="KNOWN PLAINTEXT BLOCK")
        self.kpa_m2 = tk.StringVar(value="SECRET MESSAGE BLOCK")

        ttk.Entry(top, textvariable=self.kpa_m1, width=70).grid(row=0, column=1, sticky="we", padx=8, pady=3)
        ttk.Entry(top, textvariable=self.kpa_m2, width=70).grid(row=1, column=1, sticky="we", padx=8, pady=3)

        ttk.Button(top, text="Run KPA demo", command=self.on_run_kpa).grid(row=0, column=2, rowspan=2, padx=8)

        top.columnconfigure(1, weight=1)

        self.out_kpa = ScrolledText(parent)
        self.out_kpa.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.out_kpa.set(build_kpa_demo(self.kpa_m1.get(), self.kpa_m2.get()))

    def _build_cpa_tab(self, parent: ttk.Frame) -> None:
        top = ttk.Frame(parent)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Trials:").pack(side=tk.LEFT)
        self.cpa_trials = tk.StringVar(value="800")
        ttk.Entry(top, textvariable=self.cpa_trials, width=10).pack(side=tk.LEFT, padx=8)

        ttk.Button(top, text="Run IND-CPA simulation", command=self.on_run_ind_cpa).pack(side=tk.LEFT, padx=8)
        ttk.Button(top, text="Clear output", command=lambda: self.out_cpa.set("")).pack(side=tk.LEFT, padx=8)

        self.out_cpa = ScrolledText(parent)
        self.out_cpa.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.out_cpa.set(build_ind_cpa_demo(self._safe_int(self.cpa_trials.get(), 800)))

    def _build_nonce_tab(self, parent: ttk.Frame) -> None:
        top = ttk.Frame(parent)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Message m1:").grid(row=0, column=0, sticky="w")
        ttk.Label(top, text="Message m2:").grid(row=1, column=0, sticky="w")

        self.nonce_m1 = tk.StringVar(value="ATTACK AT DAWN")
        self.nonce_m2 = tk.StringVar(value="ATTACK AT DUSK")

        ttk.Entry(top, textvariable=self.nonce_m1, width=70).grid(row=0, column=1, sticky="we", padx=8, pady=3)
        ttk.Entry(top, textvariable=self.nonce_m2, width=70).grid(row=1, column=1, sticky="we", padx=8, pady=3)

        ttk.Button(top, text="Run nonce-reuse demo", command=self.on_run_nonce_reuse).grid(row=0, column=2, rowspan=2, padx=8)

        top.columnconfigure(1, weight=1)

        self.out_nonce = ScrolledText(parent)
        self.out_nonce.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.out_nonce.set(build_nonce_reuse_demo(self.nonce_m1.get(), self.nonce_m2.get()))

    def _safe_int(self, s: str, default: int) -> int:
        try:
            v = int(s.strip())
            return v if v > 0 else default
        except Exception:
            return default

    # -----------------------------
    # Callbacks
    # -----------------------------

    def on_run_kpa(self) -> None:
        try:
            self.out_kpa.set(build_kpa_demo(self.kpa_m1.get(), self.kpa_m2.get()))
        except Exception as e:
            self.out_kpa.set(f"[error] {e}\n")

    def on_run_ind_cpa(self) -> None:
        try:
            trials = self._safe_int(self.cpa_trials.get(), 800)
            self.out_cpa.set(build_ind_cpa_demo(trials))
        except Exception as e:
            self.out_cpa.set(f"[error] {e}\n")

    def on_run_nonce_reuse(self) -> None:
        try:
            self.out_nonce.set(build_nonce_reuse_demo(self.nonce_m1.get(), self.nonce_m2.get()))
        except Exception as e:
            self.out_nonce.set(f"[error] {e}\n")


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()