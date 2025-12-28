# scripts/frequency_attack_analyzer.py
from __future__ import annotations

import json
import math
import queue
import random
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
A_ORD = ord("A")

GERMAN_FREQ: Dict[str, float] = {
    "A": 0.065,
    "B": 0.019,
    "C": 0.031,
    "D": 0.051,
    "E": 0.174,
    "F": 0.017,
    "G": 0.030,
    "H": 0.048,
    "I": 0.076,
    "J": 0.003,
    "K": 0.013,
    "L": 0.034,
    "M": 0.025,
    "N": 0.098,
    "O": 0.025,
    "P": 0.008,
    "Q": 0.0002,
    "R": 0.070,
    "S": 0.073,
    "T": 0.062,
    "U": 0.042,
    "V": 0.007,
    "W": 0.019,
    "X": 0.0003,
    "Y": 0.0001,
    "Z": 0.011,
}

COMMON_WORDS = {
    "DER",
    "DIE",
    "DAS",
    "UND",
    "IST",
    "NICHT",
    "ICH",
    "DU",
    "ER",
    "SIE",
    "ES",
    "WIR",
    "IHR",
    "EIN",
    "EINE",
    "ZU",
    "MIT",
    "AUF",
    "FUER",
    "NUR",
    "VIELE",
    "WENN",
    "KANN",
    "MAN",
    "TEXT",
    "TEXTE",
    "ALTE",
    "SHIFT",
    "CAESAR",
    "SUBSTITUTION",
    "MODERNE",
    "MUSTER",
    "ENDE",
    "BITTE",
    "DANN",
    "BIS",
    "WORT",
    "GRAMMATIK",
    "STATISTIK",
}

TRAINING_TEXT = (
    "DIE SPRACHE HAT VIELE REDUNDANTE MUSTER. WENN MAN VIEL TEXT HAT, "
    "KANN MAN HAEUFIGKEITEN VON BUCHSTABEN UND PAAREN SCHAETZEN. "
    "IN DER KRYPTOGRAPHIE IST SPRACHE NICHT ZUFAELLIG: GRAMMATIK UND WORTSCHATZ "
    "ERZEUGEN STARKEN STRUKTUR. DIESER TRAININGSTEXT ENTHAELT HAEUFIGE WOERTER WIE "
    "DER DIE DAS UND IST NICHT WENN DANN. HINZU KOMMEN PAARE WIE ER EN CH UN "
    "UND ENDUNGEN WIE EN ER E. "
    "DER ANGRIFF AUF EINE MONOALPHABETISCHE SUBSTITUTION NUTZT DIESE STATISTIK. "
    "MIT GENUG CIPHERTEXT KANN MAN DIE ZUORDNUNG ITERATIV VERBESSERN, "
    "BIS SINNVOLLE SPRACHE ENTSTEHT. "
)


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def data_dir() -> Path:
    d = project_root() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def channel_jsonl_path() -> Path:
    return data_dir() / "ab_channel.jsonl"


def channel_sqlite_path() -> Path:
    return data_dir() / "ab_channel.db"


@dataclass(frozen=True)
class Plugin:
    method_id: str
    method_name: str
    config_fields: List[Dict[str, Any]]
    decrypt_fn: Callable[[str, Dict[str, Any]], str]


def load_decrypt_plugins() -> Dict[str, Plugin]:
    plugins: Dict[str, Plugin] = {}
    plug_dir = project_root() / "decryption_methods"
    plug_dir.mkdir(parents=True, exist_ok=True)

    for p in sorted(plug_dir.glob("*.py")):
        if p.name.startswith("_"):
            continue
        try:
            plugin = load_decrypt_plugin_file(p)
            if plugin.method_id and plugin.method_id not in plugins:
                plugins[plugin.method_id] = plugin
        except Exception:
            continue
    return plugins


def load_decrypt_plugin_file(path: Path) -> Plugin:
    import importlib.util

    mod_name = f"dec_{path.stem}_{abs(hash(str(path)))}"
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load plugin spec")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore

    method_id = str(getattr(mod, "METHOD_ID", "")).strip()
    method_name = str(getattr(mod, "METHOD_NAME", "")).strip()
    config_fields = getattr(mod, "CONFIG_FIELDS", [])
    decrypt_fn = getattr(mod, "decrypt", None)

    if not method_id or not method_name or not isinstance(config_fields, list) or not callable(decrypt_fn):
        raise RuntimeError("Invalid plugin interface")

    return Plugin(
        method_id=method_id,
        method_name=method_name,
        config_fields=list(config_fields),
        decrypt_fn=decrypt_fn,
    )


def load_records() -> List[Dict[str, Any]]:
    dbp = channel_sqlite_path()
    if dbp.exists():
        con = sqlite3.connect(str(dbp))
        try:
            rows = con.execute(
                """
                SELECT id, ts_utc, sender, recipient, method_id, method_name, config_json, ciphertext
                FROM messages
                ORDER BY ts_utc ASC
                """
            ).fetchall()
        except Exception:
            rows = []
        finally:
            con.close()

        out: List[Dict[str, Any]] = []
        for r in rows:
            try:
                cfg = json.loads(r[6])
            except Exception:
                cfg = {}
            out.append(
                {
                    "id": r[0],
                    "ts_utc": r[1],
                    "from": r[2],
                    "to": r[3],
                    "method_id": r[4],
                    "method_name": r[5],
                    "config": cfg,
                    "ciphertext": r[7],
                }
            )
        return out

    # fallback JSONL
    jp = channel_jsonl_path()
    if not jp.exists():
        return []
    out2: List[Dict[str, Any]] = []
    with jp.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    out2.append(obj)
            except Exception:
                continue
    return out2


def letter_counts(text: str) -> Tuple[Dict[str, int], int]:
    counts = {ch: 0 for ch in ALPHABET}
    total = 0
    for ch in text:
        if ch in counts:
            counts[ch] += 1
            total += 1
    return counts, total


def top_letters(counts: Dict[str, int], n: int = 10) -> List[Tuple[str, int]]:
    return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:n]


def caesar_decrypt(cipher: str, shift: int) -> str:
    shift = shift % 26
    res: List[str] = []
    for ch in cipher:
        o = ord(ch)
        if A_ORD <= o <= A_ORD + 25:
            i = o - A_ORD
            res.append(chr(A_ORD + ((i - shift) % 26)))
        else:
            res.append(ch)
    return "".join(res)


def chi_squared(counts: Dict[str, int], total: int, expected: Dict[str, float]) -> float:
    if total <= 0:
        return 1e18
    chi = 0.0
    for ch in ALPHABET:
        obs = float(counts.get(ch, 0))
        exp = expected.get(ch, 0.0) * float(total)
        if exp > 0.0:
            diff = obs - exp
            chi += (diff * diff) / exp
    return chi


def word_score(text: str) -> float:
    tokens: List[str] = []
    cur: List[str] = []
    for ch in text:
        if "A" <= ch <= "Z":
            cur.append(ch)
        else:
            if cur:
                tokens.append("".join(cur))
                cur = []
    if cur:
        tokens.append("".join(cur))
    if not tokens:
        return 0.0
    hits = sum(1 for t in tokens if t in COMMON_WORDS)
    return float(hits) / float(len(tokens))


def crack_caesar(ciphertext: str) -> Tuple[int, str, float]:
    best_shift = 0
    best_plain = ciphertext
    best_score = -1e18
    for s in range(26):
        plain = caesar_decrypt(ciphertext, s)
        counts, total = letter_counts(plain)
        chi = chi_squared(counts, total, GERMAN_FREQ)
        ws = word_score(plain)
        score = (-chi) + (160.0 * ws)
        if score > best_score:
            best_score = score
            best_shift = s
            best_plain = plain
    return best_shift, best_plain, best_score


def text_to_letter_indices(text: str) -> List[int]:
    out: List[int] = []
    for ch in text:
        o = ord(ch)
        if A_ORD <= o <= A_ORD + 25:
            out.append(o - A_ORD)
        else:
            out.append(-1)
    return out


def build_trigram_logp(training: str) -> List[float]:
    size = 26 * 26 * 26
    counts = [1] * size

    p2 = -1
    p1 = -1
    for ch in training:
        o = ord(ch)
        if A_ORD <= o <= A_ORD + 25:
            c = o - A_ORD
            if p2 != -1:
                idx = ((p2 * 26) + p1) * 26 + c
                counts[idx] += 1
            p2, p1 = p1, c
        else:
            p2, p1 = -1, -1

    return [math.log(float(v)) for v in counts]


def trigram_score_indices(cipher_idxs: List[int], key_map: List[int], logp: List[float]) -> float:
    score = 0.0
    p2 = -1
    p1 = -1
    for ci in cipher_idxs:
        if ci == -1:
            p2, p1 = -1, -1
            continue
        pi = key_map[ci]
        if p2 != -1:
            idx = ((p2 * 26) + p1) * 26 + pi
            score += logp[idx]
        p2, p1 = p1, pi
    return score


def decrypt_substitution(ciphertext: str, key_map: List[int]) -> str:
    plain_letters = "".join(chr(A_ORD + pi) for pi in key_map)
    trans = str.maketrans(ALPHABET, plain_letters)
    return ciphertext.translate(trans)


def initial_key_from_frequency(ciphertext: str) -> List[int]:
    counts, _ = letter_counts(ciphertext)
    cipher_sorted = [c for c, _n in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)]
    german_sorted = [c for c, _n in sorted(GERMAN_FREQ.items(), key=lambda kv: kv[1], reverse=True)]
    key_map = [0] * 26
    for i in range(26):
        c = cipher_sorted[i]
        p = german_sorted[i]
        key_map[ord(c) - A_ORD] = ord(p) - A_ORD
    return key_map


def perturb_key_map(key_map: List[int], rng: random.Random, swaps: int) -> List[int]:
    km = list(key_map)
    for _ in range(swaps):
        a, b = rng.sample(range(26), 2)
        km[a], km[b] = km[b], km[a]
    return km


def anneal_key_map(
    cipher_idxs: List[int],
    logp: List[float],
    start_key_map: List[int],
    rng: random.Random,
    iterations: int,
    start_temp: float,
) -> Tuple[List[int], float]:
    cur = list(start_key_map)
    cur_score = trigram_score_indices(cipher_idxs, cur, logp)
    best = list(cur)
    best_score = cur_score

    for i in range(iterations):
        t = start_temp * (1.0 - (float(i) / float(iterations)))
        if t < 0.05:
            t = 0.05

        a, b = rng.sample(range(26), 2)
        cur[a], cur[b] = cur[b], cur[a]
        new_score = trigram_score_indices(cipher_idxs, cur, logp)
        delta = new_score - cur_score

        accept = delta >= 0.0 or (rng.random() < math.exp(delta / t))
        if accept:
            cur_score = new_score
            if new_score > best_score:
                best = list(cur)
                best_score = new_score
        else:
            cur[a], cur[b] = cur[b], cur[a]

    return best, best_score


def crack_substitution(ciphertext: str) -> Tuple[List[int], str, float]:
    cipher_idxs = text_to_letter_indices(ciphertext)
    logp = build_trigram_logp(TRAINING_TEXT)
    base = initial_key_from_frequency(ciphertext)

    rng = random.Random(7)
    best_key: Optional[List[int]] = None
    best_score = -1e18

    for restart in range(14):
        start = perturb_key_map(base, rng, swaps=28 + restart * 3)
        key, score = anneal_key_map(
            cipher_idxs=cipher_idxs,
            logp=logp,
            start_key_map=start,
            rng=rng,
            iterations=18000,
            start_temp=26.0,
        )
        if score > best_score:
            best_key = key
            best_score = score

    assert best_key is not None
    plain = decrypt_substitution(ciphertext, best_key)
    return best_key, plain, best_score


def run_gui() -> None:
    # Optional PySide6; fallback to Tkinter.
    try:
        from PySide6.QtCore import QTimer  # type: ignore
        from PySide6.QtWidgets import (  # type: ignore
            QApplication,
            QComboBox,
            QFormLayout,
            QHBoxLayout,
            QLabel,
            QListWidget,
            QListWidgetItem,
            QPushButton,
            QTextEdit,
            QVBoxLayout,
            QWidget,
        )

        class Main(QWidget):
            def __init__(self) -> None:
                super().__init__()
                self.setWindowTitle("HarborScope - frequency + decrypt + attacks")
                self.plugins = load_decrypt_plugins()
                self.records: List[Dict[str, Any]] = []
                self.work_q: "queue.Queue[Tuple[str, Any]]" = queue.Queue()

                layout = QVBoxLayout()

                top = QHBoxLayout()
                self.reload_btn = QPushButton("Reload")
                self.decrypt_btn = QPushButton("Decrypt (plugin)")
                self.freq_btn = QPushButton("Frequency (selected/all)")
                self.caesar_btn = QPushButton("Crack Caesar (selected)")
                self.subst_btn = QPushButton("Crack Substitution (all of method)")
                top.addWidget(self.reload_btn)
                top.addWidget(self.decrypt_btn)
                top.addWidget(self.freq_btn)
                top.addWidget(self.caesar_btn)
                top.addWidget(self.subst_btn)
                layout.addLayout(top)

                mid_row = QHBoxLayout()
                self.listw = QListWidget()
                mid_row.addWidget(self.listw, 1)

                right = QVBoxLayout()
                self.method_sel = QComboBox()
                for mid, pl in self.plugins.items():
                    self.method_sel.addItem(f"{pl.method_name} ({mid})", mid)
                right.addWidget(QLabel("Decryption plugin override"))
                right.addWidget(self.method_sel)

                self.info = QTextEdit()
                self.info.setReadOnly(True)
                right.addWidget(self.info, 1)

                mid_row.addLayout(right, 2)
                layout.addLayout(mid_row)

                self.setLayout(layout)

                self.reload_btn.clicked.connect(self._reload)
                self.decrypt_btn.clicked.connect(self._decrypt_selected)
                self.freq_btn.clicked.connect(self._freq)
                self.caesar_btn.clicked.connect(self._crack_caesar)
                self.subst_btn.clicked.connect(self._crack_subst)
                self.listw.currentRowChanged.connect(lambda _i: self._show_selected())

                self._timer = QTimer(self)
                self._timer.timeout.connect(self._poll_work)
                self._timer.start(120)

                self._reload()

            def _poll_work(self) -> None:
                while True:
                    try:
                        kind, payload = self.work_q.get_nowait()
                    except queue.Empty:
                        break
                    if kind == "subst_done":
                        self.info.append(payload)

            def _reload(self) -> None:
                self.records = load_records()
                self.listw.clear()
                for r in self.records:
                    mid = str(r.get("method_id", ""))
                    item = QListWidgetItem(f"{r.get('id')}  [{mid}]")
                    self.listw.addItem(item)
                self.info.setPlainText(f"Loaded {len(self.records)} records\n")

            def _selected(self) -> Optional[Dict[str, Any]]:
                i = self.listw.currentRow()
                if i < 0 or i >= len(self.records):
                    return None
                return self.records[i]

            def _show_selected(self) -> None:
                r = self._selected()
                if not r:
                    return
                self.info.setPlainText(json.dumps(r, ensure_ascii=True, indent=2))

            def _decrypt_selected(self) -> None:
                r = self._selected()
                if not r:
                    return
                mid = str(r.get("method_id", ""))
                cfg = r.get("config", {}) if isinstance(r.get("config", {}), dict) else {}
                ct = str(r.get("ciphertext", ""))

                use_mid = self.method_sel.currentData() or mid
                if use_mid in self.plugins:
                    pl = self.plugins[use_mid]
                    try:
                        pt = str(pl.decrypt_fn(ct, cfg))
                        self.info.append("\n[plugin decrypt]\n" + pt[:900])
                    except Exception as e:
                        self.info.append(f"\n[plugin decrypt failed] {e}")
                else:
                    self.info.append("\n[plugin decrypt] no plugin for method_id")

            def _freq(self) -> None:
                r = self._selected()
                if r:
                    ct = str(r.get("ciphertext", ""))
                    counts, total = letter_counts(ct)
                    self.info.append("\n[frequency selected]\n" + ", ".join(f"{c}:{n}" for c, n in top_letters(counts, 12)) + f"\nTOTAL={total}")
                all_ct = "\n".join(str(x.get("ciphertext", "")) for x in self.records)
                counts2, total2 = letter_counts(all_ct)
                self.info.append("\n[frequency all]\n" + ", ".join(f"{c}:{n}" for c, n in top_letters(counts2, 12)) + f"\nTOTAL={total2}")

            def _crack_caesar(self) -> None:
                r = self._selected()
                if not r:
                    return
                ct = str(r.get("ciphertext", ""))
                shift, pt, score = crack_caesar(ct)
                self.info.append(f"\n[crack caesar] best_shift={shift} score={score:.2f}\n{pt[:900]}")

            def _crack_subst(self) -> None:
                r = self._selected()
                if not r:
                    return
                mid = str(r.get("method_id", ""))
                # Aggregate ciphertext for this method_id to improve stats.
                agg = "\n".join(str(x.get("ciphertext", "")) for x in self.records if str(x.get("method_id", "")) == mid)
                if not agg.strip():
                    self.info.append("\n[crack substitution] nothing to crack")
                    return

                def worker() -> None:
                    key_map, pt, score = crack_substitution(agg)
                    mapping = " ".join(f"{ALPHABET[i]}->{chr(A_ORD + key_map[i])}" for i in range(26))
                    out = f"\n[crack substitution] score={score:.2f}\n{mapping}\n\n{pt[:900]}"
                    self.work_q.put(("subst_done", out))

                threading.Thread(target=worker, daemon=True).start()
                self.info.append("\n[crack substitution] running ...")

        app = QApplication([])
        w = Main()
        w.resize(1100, 740)
        w.show()
        app.exec()
        return

    except Exception:
        pass

    # Tkinter fallback
    import tkinter as tk
    from tkinter import ttk

    class TkMain:
        def __init__(self, root: tk.Tk) -> None:
            self.root = root
            self.root.title("HarborScope - frequency + decrypt + attacks [Tk fallback]")

            self.plugins = load_decrypt_plugins()
            self.records: List[Dict[str, Any]] = []
            self.work_q: "queue.Queue[Tuple[str, Any]]" = queue.Queue()

            self._build_style()
            self._build_ui()
            self._reload()

            self.root.after(120, self._poll_work)

        def _build_style(self) -> None:
            style = ttk.Style()
            try:
                style.theme_use("clam")
            except Exception:
                pass
            style.configure("TFrame", background="#06243b")
            style.configure("TLabel", background="#06243b", foreground="#e7f2ff")
            style.configure("TButton", padding=6)
            style.configure("TCombobox", fieldbackground="#0b3a5a", foreground="#e7f2ff")

        def _build_ui(self) -> None:
            top = ttk.Frame(self.root)
            top.pack(fill="both", expand=True)

            btns = ttk.Frame(top)
            btns.pack(fill="x", padx=10, pady=10)

            ttk.Button(btns, text="Reload", command=self._reload).pack(side="left")
            ttk.Button(btns, text="Decrypt (plugin)", command=self._decrypt_selected).pack(side="left", padx=8)
            ttk.Button(btns, text="Frequency (selected/all)", command=self._freq).pack(side="left", padx=8)
            ttk.Button(btns, text="Crack Caesar (selected)", command=self._crack_caesar).pack(side="left", padx=8)
            ttk.Button(btns, text="Crack Substitution (all of method)", command=self._crack_subst).pack(side="left", padx=8)

            mid = ttk.Frame(top)
            mid.pack(fill="both", expand=True, padx=10, pady=(0, 10))

            self.listbox = tk.Listbox(mid, width=42, bg="#0b3a5a", fg="#e7f2ff")
            self.listbox.pack(side="left", fill="y")
            self.listbox.bind("<<ListboxSelect>>", lambda _e: self._show_selected())

            right = ttk.Frame(mid)
            right.pack(side="left", fill="both", expand=True, padx=10)

            ttk.Label(right, text="Decryption plugin override").pack(anchor="w")
            self.method_var = tk.StringVar(value=next(iter(self.plugins.keys()), ""))
            self.method_cb = ttk.Combobox(
                right,
                textvariable=self.method_var,
                values=list(self.plugins.keys()),
                state="readonly",
                width=30,
            )
            self.method_cb.pack(anchor="w", pady=(0, 8))

            self.info = tk.Text(right, wrap="word", bg="#041a2b", fg="#e7f2ff", insertbackground="#e7f2ff")
            self.info.pack(fill="both", expand=True)

        def _poll_work(self) -> None:
            while True:
                try:
                    kind, payload = self.work_q.get_nowait()
                except queue.Empty:
                    break
                if kind == "subst_done":
                    self.info.insert("end", payload + "\n")
                    self.info.see("end")
            self.root.after(120, self._poll_work)

        def _reload(self) -> None:
            self.records = load_records()
            self.listbox.delete(0, "end")
            for r in self.records:
                mid = str(r.get("method_id", ""))
                self.listbox.insert("end", f"{r.get('id')}  [{mid}]")
            self.info.delete("1.0", "end")
            self.info.insert("end", f"Loaded {len(self.records)} records\n")

        def _selected(self) -> Optional[Dict[str, Any]]:
            sel = self.listbox.curselection()
            if not sel:
                return None
            i = int(sel[0])
            if i < 0 or i >= len(self.records):
                return None
            return self.records[i]

        def _show_selected(self) -> None:
            r = self._selected()
            if not r:
                return
            self.info.delete("1.0", "end")
            self.info.insert("end", json.dumps(r, ensure_ascii=True, indent=2))

        def _decrypt_selected(self) -> None:
            r = self._selected()
            if not r:
                return
            mid = str(r.get("method_id", ""))
            ct = str(r.get("ciphertext", ""))
            cfg = r.get("config", {}) if isinstance(r.get("config", {}), dict) else {}

            use_mid = self.method_var.get().strip() or mid
            self.info.insert("end", "\n\n[plugin decrypt]\n")
            if use_mid in self.plugins:
                pl = self.plugins[use_mid]
                try:
                    pt = str(pl.decrypt_fn(ct, cfg))
                    self.info.insert("end", pt[:1200] + "\n")
                except Exception as e:
                    self.info.insert("end", f"decrypt failed: {e}\n")
            else:
                self.info.insert("end", "no plugin for method_id\n")
            self.info.see("end")

        def _freq(self) -> None:
            r = self._selected()
            if r:
                ct = str(r.get("ciphertext", ""))
                counts, total = letter_counts(ct)
                s = ", ".join(f"{c}:{n}" for c, n in top_letters(counts, 12))
                self.info.insert("end", f"\n\n[frequency selected]\n{s}\nTOTAL={total}\n")
            all_ct = "\n".join(str(x.get("ciphertext", "")) for x in self.records)
            counts2, total2 = letter_counts(all_ct)
            s2 = ", ".join(f"{c}:{n}" for c, n in top_letters(counts2, 12))
            self.info.insert("end", f"\n[frequency all]\n{s2}\nTOTAL={total2}\n")
            self.info.see("end")

        def _crack_caesar(self) -> None:
            r = self._selected()
            if not r:
                return
            ct = str(r.get("ciphertext", ""))
            shift, pt, score = crack_caesar(ct)
            self.info.insert("end", f"\n\n[crack caesar] best_shift={shift} score={score:.2f}\n{pt[:1200]}\n")
            self.info.see("end")

        def _crack_subst(self) -> None:
            r = self._selected()
            if not r:
                return
            mid = str(r.get("method_id", ""))
            agg = "\n".join(str(x.get("ciphertext", "")) for x in self.records if str(x.get("method_id", "")) == mid)
            if not agg.strip():
                self.info.insert("end", "\n\n[crack substitution] nothing to crack\n")
                self.info.see("end")
                return

            def worker() -> None:
                key_map, pt, score = crack_substitution(agg)
                mapping = " ".join(f"{ALPHABET[i]}->{chr(A_ORD + key_map[i])}" for i in range(26))
                out = f"\n\n[crack substitution] score={score:.2f}\n{mapping}\n\n{pt[:1200]}\n"
                self.work_q.put(("subst_done", out))

            threading.Thread(target=worker, daemon=True).start()
            self.info.insert("end", "\n\n[crack substitution] running ...\n")
            self.info.see("end")

    root = tk.Tk()
    root.geometry("1200x760")
    TkMain(root)
    root.mainloop()


def main() -> None:
    run_gui()


if __name__ == "__main__":
    main()