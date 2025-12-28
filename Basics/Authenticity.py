# demo_authenticity.py
import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
import tkinter as tk
from tkinter import ttk


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def egcd(a: int, b: int):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m


def is_probable_prime(n: int, k: int = 16) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n % p == 0:
            return n == p

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True


def gen_prime(bits: int) -> int:
    while True:
        x = secrets.randbits(bits)
        x |= (1 << (bits - 1))
        x |= 1
        if is_probable_prime(x):
            return x


def rsa_generate_keypair(total_bits: int = 384):
    # Demo RSA (NO padding): educational only.
    e = 65537
    half = total_bits // 2
    while True:
        p = gen_prime(half)
        q = gen_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        try:
            d = modinv(e, phi)
            return {"n": n, "e": e}, {"n": n, "d": d}
        except ValueError:
            continue


def rsa_sign_sha256(priv: dict, message_bytes: bytes) -> bytes:
    h = hashlib.sha256(message_bytes).digest()
    m = int.from_bytes(h, "big") % priv["n"]
    s = pow(m, priv["d"], priv["n"])
    sig_len = (priv["n"].bit_length() + 7) // 8
    return s.to_bytes(sig_len, "big")


def rsa_verify_sha256(pub: dict, message_bytes: bytes, signature: bytes) -> bool:
    h = hashlib.sha256(message_bytes).digest()
    m = int.from_bytes(h, "big") % pub["n"]
    s = int.from_bytes(signature, "big")
    v = pow(s, pub["e"], pub["n"])
    return v == m


def build_glossary_text() -> dict:
    return {
        "Authenticity": (
            "NAME:\n"
            "  Authenticity\n\n"
            "MEANING:\n"
            "  Assurance that data really comes from the expected source (the claimed sender)\n"
            "  or that an entity identity is genuine.\n\n"
            "WHY IT MATTERS:\n"
            "  Without authenticity, an attacker can impersonate the sender.\n\n"
            "IN THIS DEMO:\n"
            "  Achieved with either HMAC (shared secret) or RSA signature (public key).\n"
        ),
        "Integrity": (
            "NAME:\n"
            "  Integrity\n\n"
            "MEANING:\n"
            "  Assurance that data has not been changed (tampered) after it was created.\n\n"
            "WHY IT MATTERS:\n"
            "  Without integrity, attackers can modify content while keeping the same identity.\n\n"
            "IN THIS DEMO:\n"
            "  The MAC/signature covers payload+ts+nonce+alg. Any change breaks verification.\n"
        ),
        "MAC (HMAC)": (
            "NAME:\n"
            "  MAC (Message Authentication Code) using HMAC-SHA256\n\n"
            "MEANING:\n"
            "  A short tag computed from (message, shared_secret). Receiver recomputes it.\n\n"
            "WHY IT MATTERS:\n"
            "  Provides authenticity+integrity for parties that share the same secret.\n\n"
            "IN THIS DEMO:\n"
            "  'Gen HMAC key' creates a 32-byte secret. 'Create Packet' adds HMAC as sig.\n"
        ),
        "Digital signature": (
            "NAME:\n"
            "  Digital signature (RSA-SHA256 in this demo)\n\n"
            "MEANING:\n"
            "  A value created with a private key. Anyone with the public key can verify.\n\n"
            "WHY IT MATTERS:\n"
            "  Provides authenticity+integrity without sharing a secret with all verifiers.\n\n"
            "IN THIS DEMO:\n"
            "  'Gen RSA keypair' makes (public, private). Create signs, Verify checks via public.\n"
            "  NOTE: RSA here is simplified (no padding). Educational only.\n"
        ),
        "Freshness": (
            "NAME:\n"
            "  Freshness\n\n"
            "MEANING:\n"
            "  Assurance that the message is recent (not an old valid message replayed later).\n\n"
            "WHY IT MATTERS:\n"
            "  A valid old signature/MAC can still be dangerous if an attacker replays it.\n\n"
            "IN THIS DEMO:\n"
            "  Freshness = timestamp window check + nonce replay cache.\n"
            "  'Freshness window (sec)' sets how old a packet may be.\n"
        ),
        "Timestamp (ts)": (
            "NAME:\n"
            "  Timestamp (ts)\n\n"
            "MEANING:\n"
            "  A time value attached to a message (here: Unix seconds).\n\n"
            "WHY IT MATTERS:\n"
            "  Lets the receiver reject messages that are too old.\n\n"
            "IN THIS DEMO:\n"
            "  Verify fails if age > window, or if ts is in the future.\n"
        ),
        "Nonce": (
            "NAME:\n"
            "  Nonce (number used once)\n\n"
            "MEANING:\n"
            "  A random value that should be unique per message.\n\n"
            "WHY IT MATTERS:\n"
            "  Blocks replay even inside the allowed timestamp window.\n\n"
            "IN THIS DEMO:\n"
            "  Nonce is random 16 bytes (base64). Verified nonces are stored in memory.\n"
        ),
        "Replay attack": (
            "NAME:\n"
            "  Replay attack\n\n"
            "MEANING:\n"
            "  Attacker captures a valid message and sends it again later.\n\n"
            "WHY IT MATTERS:\n"
            "  MAC/signature can still verify, so you need freshness protections.\n\n"
            "IN THIS DEMO:\n"
            "  Click Verify twice on the same packet: second time fails (nonce already seen).\n"
        ),
        "Shared secret": (
            "NAME:\n"
            "  Shared secret\n\n"
            "MEANING:\n"
            "  A secret key known by both sender and receiver.\n\n"
            "WHY IT MATTERS:\n"
            "  Anyone with this secret can create valid MACs (so protect distribution).\n\n"
            "IN THIS DEMO:\n"
            "  The app simulates both sides using the same in-memory HMAC key.\n"
        ),
        "Public key": (
            "NAME:\n"
            "  Public key\n\n"
            "MEANING:\n"
            "  A key that can be shared widely; used to verify signatures.\n\n"
            "WHY IT MATTERS:\n"
            "  Verifiers do not need the private key; they only need the public key.\n\n"
            "IN THIS DEMO:\n"
            "  RSA public key = (n, e). Verify uses it.\n"
        ),
        "Private key": (
            "NAME:\n"
            "  Private key\n\n"
            "MEANING:\n"
            "  A secret key held by the signer; used to create signatures.\n\n"
            "WHY IT MATTERS:\n"
            "  If stolen, attackers can impersonate the signer.\n\n"
            "IN THIS DEMO:\n"
            "  RSA private key contains d. Only Create Packet uses it.\n"
        ),
    }


def make_scrolled_text(parent, *, height, wrap, font, hscroll=False):
    container = ttk.Frame(parent)
    text = tk.Text(container, height=height, wrap=wrap, font=font, undo=False)
    vsb = ttk.Scrollbar(container, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=vsb.set)

    text.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")

    if hscroll:
        hsb = ttk.Scrollbar(container, orient="horizontal", command=text.xview)
        text.configure(xscrollcommand=hsb.set)
        hsb.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
    else:
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

    return container, text


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Authenticity Demo: HMAC / RSA + Freshness (ts+nonce)")

        self.hmac_key = None
        self.rsa_pub = None
        self.rsa_priv = None
        self.seen_nonces = set()

        self.glossary = build_glossary_text()

        self._apply_compact_style()
        self._build_ui_two_columns()
        self._init_demo_keys()

    def _apply_compact_style(self):
        style = ttk.Style()
        # Small, compact default font (helps on laptops).
        try:
            style.configure(".", font=("TkDefaultFont", 9))
            self.text_font = ("TkFixedFont", 9)
        except Exception:
            self.text_font = None

    def _init_demo_keys(self):
        self.hmac_key = secrets.token_bytes(32)
        self.set_status("Ready. HMAC key initialized. RSA keypair generating in background.")
        self.refresh_keys_display()
        self._gen_rsa_keypair_background()

    def _gen_rsa_keypair_background(self):
        def worker():
            try:
                pub, priv = rsa_generate_keypair(total_bits=384)
                self.after(0, lambda: self._set_rsa_keys(pub, priv))
            except Exception as e:
                self.after(0, lambda: self.set_status("RSA keygen failed: %s" % (str(e),)))

        threading.Thread(target=worker, daemon=True).start()

    def _build_ui_two_columns(self):
        self.geometry("1000x700")
        self.minsize(820, 580)

        root = ttk.Frame(self, padding=8)
        root.grid(row=0, column=0, sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        # Top: Goal + Controls (full width)
        goal = ttk.LabelFrame(root, text="Goal", padding=8)
        goal.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        goal.columnconfigure(0, weight=1)
        ttk.Label(
            goal,
            text=(
                "Verify: authenticity (who sent it) + integrity (unchanged) + freshness (recent, no replay).\n"
                "Packet = payload + ts + nonce + alg + sig (sig is MAC or signature over the other fields)."
            ),
            justify="left",
        ).grid(row=0, column=0, sticky="w")

        ctl = ttk.LabelFrame(root, text="Controls", padding=8)
        ctl.grid(row=1, column=0, sticky="ew", pady=(0, 6))

        ttk.Label(ctl, text="Mode:").grid(row=0, column=0, sticky="w")
        self.mode_var = tk.StringVar(value="HMAC")
        self.mode_box = ttk.Combobox(ctl, textvariable=self.mode_var, values=["HMAC", "RSA"], state="readonly", width=10)
        self.mode_box.grid(row=0, column=1, sticky="w", padx=(6, 12))

        ttk.Label(ctl, text="Freshness window (sec):").grid(row=0, column=2, sticky="w")
        self.window_var = tk.StringVar(value="30")
        ttk.Entry(ctl, textvariable=self.window_var, width=6).grid(row=0, column=3, sticky="w", padx=(6, 12))

        ttk.Button(ctl, text="Gen HMAC key", command=self.gen_hmac_key).grid(row=0, column=4, sticky="w", padx=(0, 6))
        ttk.Button(ctl, text="Gen RSA keypair", command=self.gen_rsa_keypair_threaded).grid(row=0, column=5, sticky="w", padx=(0, 6))
        ttk.Button(ctl, text="Clear nonce cache", command=self.clear_nonce_cache).grid(row=0, column=6, sticky="w")

        # Two-column area: resizable split pane
        pane = ttk.Panedwindow(root, orient="horizontal")
        pane.grid(row=2, column=0, sticky="nsew")
        root.rowconfigure(2, weight=1)
        root.columnconfigure(0, weight=1)

        left = ttk.Frame(pane, padding=0)
        right = ttk.Frame(pane, padding=0)
        pane.add(left, weight=3)
        pane.add(right, weight=2)

        # LEFT COLUMN: payload + packet + status
        left.columnconfigure(0, weight=1)
        left.rowconfigure(2, weight=1)

        pay = ttk.LabelFrame(left, text="Payload", padding=8)
        pay.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        pay.columnconfigure(0, weight=1)
        pay_container, self.payload_text = make_scrolled_text(
            pay, height=4, wrap="word", font=self.text_font, hscroll=False
        )
        pay_container.grid(row=0, column=0, sticky="ew")
        self.payload_text.insert("1.0", "Hello authenticity!")

        btns = ttk.Frame(left)
        btns.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        ttk.Button(btns, text="Create Packet", command=self.create_packet).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(btns, text="Verify Packet", command=self.verify_packet).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(btns, text="Tamper Packet", command=self.tamper_packet).grid(row=0, column=2)

        pkt = ttk.LabelFrame(left, text="Packet (JSON)", padding=8)
        pkt.grid(row=2, column=0, sticky="nsew", pady=(0, 6))
        pkt.columnconfigure(0, weight=1)
        pkt.rowconfigure(0, weight=1)
        pkt_container, self.packet_text = make_scrolled_text(
            pkt, height=14, wrap="none", font=self.text_font, hscroll=True
        )
        pkt_container.grid(row=0, column=0, sticky="nsew")

        st = ttk.LabelFrame(left, text="Status", padding=8)
        st.grid(row=3, column=0, sticky="ew")
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(st, textvariable=self.status_var).grid(row=0, column=0, sticky="w")

        # RIGHT COLUMN: glossary + keys (stacked, also resizable)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)

        r_pane = ttk.Panedwindow(right, orient="vertical")
        r_pane.grid(row=0, column=0, sticky="nsew")
        right.rowconfigure(0, weight=1)
        right.columnconfigure(0, weight=1)

        gl = ttk.LabelFrame(r_pane, text="Glossary (name / what / why / role here)", padding=8)
        kd = ttk.LabelFrame(r_pane, text="Keys (demo visibility)", padding=8)
        r_pane.add(gl, weight=3)
        r_pane.add(kd, weight=1)

        # Glossary content
        gl.columnconfigure(0, weight=1)
        gl.rowconfigure(1, weight=1)

        top_row = ttk.Frame(gl)
        top_row.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(top_row, text="Term:").grid(row=0, column=0, sticky="w")
        self.term_var = tk.StringVar(value="Authenticity")
        terms = list(self.glossary.keys())
        self.term_box = ttk.Combobox(top_row, textvariable=self.term_var, values=terms, state="readonly", width=22)
        self.term_box.grid(row=0, column=1, sticky="w", padx=(6, 0))
        self.term_box.bind("<<ComboboxSelected>>", lambda _e: self.update_glossary_text())

        gl_container, self.glossary_text = make_scrolled_text(
            gl, height=14, wrap="word", font=self.text_font, hscroll=False
        )
        gl_container.grid(row=1, column=0, sticky="nsew")
        self.glossary_text.configure(state="disabled")
        self.update_glossary_text()

        # Keys content
        kd.columnconfigure(0, weight=1)
        kd.rowconfigure(0, weight=1)
        kd_container, self.keys_text = make_scrolled_text(
            kd, height=6, wrap="word", font=self.text_font, hscroll=False
        )
        kd_container.grid(row=0, column=0, sticky="nsew")

        self.refresh_keys_display()

    def set_status(self, msg: str, focus_term: str = None):
        self.status_var.set(msg)
        if focus_term is not None:
            self.focus_glossary_term(focus_term)

    def focus_glossary_term(self, term: str):
        if term in self.glossary:
            self.term_var.set(term)
            self.update_glossary_text()

    def update_glossary_text(self):
        term = self.term_var.get()
        text = self.glossary.get(term, "No definition.")
        self.glossary_text.configure(state="normal")
        self.glossary_text.delete("1.0", "end")
        self.glossary_text.insert("1.0", text)
        self.glossary_text.configure(state="disabled")

    def refresh_keys_display(self):
        lines = []
        if self.hmac_key is None:
            lines.append("HMAC key: (not set)")
        else:
            lines.append("HMAC key (base64): " + b64e(self.hmac_key))

        if self.rsa_pub is None or self.rsa_priv is None:
            lines.append("RSA pub/priv: (not set yet; background gen may still run)")
        else:
            lines.append("RSA public: n(bits)=%d, e=%d" % (self.rsa_pub["n"].bit_length(), self.rsa_pub["e"]))
            lines.append("RSA private: d(bits)=%d" % (self.rsa_priv["d"].bit_length(),))

        lines.append("Seen nonces (replay cache): %d" % (len(self.seen_nonces),))

        self.keys_text.delete("1.0", "end")
        self.keys_text.insert("1.0", "\n".join(lines))

    def gen_hmac_key(self):
        self.hmac_key = secrets.token_bytes(32)
        self.set_status("Generated new HMAC key.", focus_term="Shared secret")
        self.refresh_keys_display()

    def gen_rsa_keypair_threaded(self):
        self.set_status("Generating RSA keypair (demo)...", focus_term="Digital signature")
        self.refresh_keys_display()

        def worker():
            try:
                pub, priv = rsa_generate_keypair(total_bits=384)
                self.after(0, lambda: self._set_rsa_keys(pub, priv))
            except Exception as e:
                self.after(0, lambda: self.set_status("RSA keygen failed: %s" % (str(e),)))

        threading.Thread(target=worker, daemon=True).start()

    def _set_rsa_keys(self, pub: dict, priv: dict):
        self.rsa_pub = pub
        self.rsa_priv = priv
        self.set_status("Generated RSA keypair.", focus_term="Public key")
        self.refresh_keys_display()

    def clear_nonce_cache(self):
        self.seen_nonces.clear()
        self.set_status("Nonce cache cleared.", focus_term="Nonce")
        self.refresh_keys_display()

    def _get_freshness_window(self) -> int:
        try:
            w = int(self.window_var.get().strip())
            return max(0, w)
        except Exception:
            return 30

    def _current_payload(self) -> str:
        return self.payload_text.get("1.0", "end").rstrip("\n")

    def create_packet(self):
        mode = self.mode_var.get()
        payload = self._current_payload()
        ts = int(time.time())
        nonce = b64e(secrets.token_bytes(16))

        base = {
            "payload": payload,
            "ts": ts,
            "nonce": nonce,
            "alg": "HMAC-SHA256" if mode == "HMAC" else "RSA-SHA256",
        }

        to_sign = canonical_bytes(base)

        if mode == "HMAC":
            if self.hmac_key is None:
                self.hmac_key = secrets.token_bytes(32)
            mac = hmac.new(self.hmac_key, to_sign, hashlib.sha256).digest()
            base["sig"] = b64e(mac)
            self.focus_glossary_term("MAC (HMAC)")
        else:
            if self.rsa_priv is None:
                self.set_status(
                    "RSA keys not set yet. Click 'Gen RSA keypair' or wait for background generation.",
                    focus_term="Digital signature",
                )
                return
            sig = rsa_sign_sha256(self.rsa_priv, to_sign)
            base["sig"] = b64e(sig)
            self.focus_glossary_term("Digital signature")

        self.packet_text.delete("1.0", "end")
        self.packet_text.insert("1.0", json.dumps(base, indent=2, sort_keys=True))
        self.set_status("Packet created: payload + ts + nonce + sig (MAC/signature).", focus_term="Integrity")
        self.refresh_keys_display()

    def _read_packet(self):
        raw = self.packet_text.get("1.0", "end").strip()
        if not raw:
            return None, "Packet is empty."
        try:
            pkt = json.loads(raw)
        except Exception as e:
            return None, "Invalid JSON: %s" % (str(e),)
        return pkt, None

    def verify_packet(self):
        pkt, err = self._read_packet()
        if err:
            self.set_status(err)
            return

        required = ["payload", "ts", "nonce", "alg", "sig"]
        for k in required:
            if k not in pkt:
                self.set_status("Missing field: %s" % (k,))
                return

        now = int(time.time())
        try:
            ts = int(pkt["ts"])
        except Exception:
            self.set_status("Bad ts (not int).", focus_term="Timestamp (ts)")
            return

        age = now - ts
        window = self._get_freshness_window()
        if age < 0:
            self.set_status("Freshness FAIL: ts is in the future (age=%ds)." % (age,), focus_term="Freshness")
            return
        if window > 0 and age > window:
            self.set_status("Freshness FAIL: too old (age=%ds, window=%ds)." % (age, window), focus_term="Freshness")
            return

        nonce = str(pkt["nonce"])
        if nonce in self.seen_nonces:
            self.set_status("Replay FAIL: nonce already seen.", focus_term="Replay attack")
            return

        alg = str(pkt["alg"])
        sig_b64 = str(pkt["sig"])

        base = {
            "payload": str(pkt["payload"]),
            "ts": ts,
            "nonce": nonce,
            "alg": alg,
        }
        to_verify = canonical_bytes(base)

        ok = False
        if alg == "HMAC-SHA256":
            if self.hmac_key is None:
                self.set_status("No HMAC key set in app. Generate one (must match sender).", focus_term="Shared secret")
                return
            try:
                mac = b64d(sig_b64)
            except Exception:
                self.set_status("Bad signature encoding (base64).", focus_term="MAC (HMAC)")
                return
            expected = hmac.new(self.hmac_key, to_verify, hashlib.sha256).digest()
            ok = hmac.compare_digest(mac, expected)
        elif alg == "RSA-SHA256":
            if self.rsa_pub is None:
                self.set_status("No RSA public key set yet. Generate/wait for it.", focus_term="Public key")
                return
            try:
                sig = b64d(sig_b64)
            except Exception:
                self.set_status("Bad signature encoding (base64).", focus_term="Digital signature")
                return
            ok = rsa_verify_sha256(self.rsa_pub, to_verify, sig)
        else:
            self.set_status("Unknown alg: %s" % (alg,))
            return

        if ok:
            self.seen_nonces.add(nonce)
            self.set_status(
                "OK: authenticity+integrity verified. Freshness OK (age=%ds). Nonce stored." % (age,),
                focus_term="Authenticity",
            )
        else:
            self.set_status("FAIL: authenticity/integrity check failed (bad MAC/signature).", focus_term="Integrity")

        self.refresh_keys_display()

    def tamper_packet(self):
        pkt, err = self._read_packet()
        if err:
            self.set_status(err)
            return
        if "payload" not in pkt:
            self.set_status("Cannot tamper: no payload field.")
            return
        pkt["payload"] = str(pkt["payload"]) + " [TAMPERED]"
        self.packet_text.delete("1.0", "end")
        self.packet_text.insert("1.0", json.dumps(pkt, indent=2, sort_keys=True))
        self.set_status("Packet tampered (payload changed, sig unchanged). Verify should fail.", focus_term="Integrity")


if __name__ == "__main__":
    app = App()
    app.mainloop()