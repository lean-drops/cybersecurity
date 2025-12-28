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
    hard = Path("/Users/python/Pycharm Projects/Cybersecurity/Encryption")
    if hard.exists():
        return hard
    # Fallback: scripts/.. as root
    return Path(__file__).resolve().parents[1]


def styles_qss_path() -> Path:
    # Requested: ab_style.qss
    return project_root() / "styles" / "ab_style.qss"


def decryption_plugin_dir() -> Path:
    # Required: EXACTLY root/decryption_methods
    root = project_root()
    p = root / "decryption_methods"
    p.mkdir(parents=True, exist_ok=True)
    return p


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


def load_decrypt_plugins() -> Dict[str, Plugin]:
    plugins: Dict[str, Plugin] = {}
    plug_dir = decryption_plugin_dir()
    for p in sorted(plug_dir.glob("*.py")):
        if p.name.startswith("_"):
            continue
        try:
            pl = load_decrypt_plugin_file(p)
            plugins[pl.method_id] = pl
        except Exception:
            continue
    return plugins


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


def _default_config(fields: List[Dict[str, Any]]) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    for f in fields:
        k = str(f.get("key", "")).strip()
        if not k:
            continue
        cfg[k] = f.get("default")
    return cfg


def run_gui() -> None:
    from PySide6.QtCore import Qt, QTimer  # type: ignore
    from PySide6.QtGui import QFont  # type: ignore
    from PySide6.QtWidgets import (  # type: ignore
        QApplication,
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QLabel,
        QListWidget,
        QListWidgetItem,
        QPushButton,
        QScrollArea,
        QSpinBox,
        QTabWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
        QLineEdit,
    )

    class Card(QFrame):
        def __init__(self, title: str) -> None:
            super().__init__()
            self.setObjectName("Card")
            outer = QVBoxLayout(self)
            outer.setContentsMargins(14, 14, 14, 14)
            outer.setSpacing(10)
            lbl = QLabel(title)
            lbl.setObjectName("CardTitle")
            outer.addWidget(lbl)
            self.body = QVBoxLayout()
            self.body.setSpacing(10)
            outer.addLayout(self.body)

    class Main(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self.setObjectName("AppWindow")
            self.setWindowTitle("HarborScope - frequency + decrypt + attacks")

            self.plugins: Dict[str, Plugin] = {}
            self.records: List[Dict[str, Any]] = []
            self.work_q: "queue.Queue[Tuple[str, Any]]" = queue.Queue()

            root = QVBoxLayout(self)
            root.setContentsMargins(16, 16, 16, 16)
            root.setSpacing(12)

            header = QFrame()
            header.setObjectName("HeaderBar")
            h = QHBoxLayout(header)
            h.setContentsMargins(16, 14, 16, 14)

            tcol = QVBoxLayout()
            title = QLabel("HarborScope")
            title.setObjectName("AppTitle")
            subtitle = QLabel("Records + dynamic decrypt plugins (decryption_methods)")
            subtitle.setObjectName("AppSubtitle")
            tcol.addWidget(title)
            tcol.addWidget(subtitle)
            h.addLayout(tcol, 1)

            hint = QLabel(f"Root: {str(project_root())} | Plugins: {str(decryption_plugin_dir())}")
            hint.setObjectName("Hint")
            h.addWidget(hint)

            root.addWidget(header)

            topbar = QHBoxLayout()
            topbar.setSpacing(10)

            self.reload_records_btn = QPushButton("Reload records")
            self.reload_records_btn.setObjectName("PrimaryButton")
            self.reload_plugins_btn = QPushButton("Reload plugins")
            self.reload_plugins_btn.setObjectName("GhostButton")

            self.freq_sel_btn = QPushButton("Frequency (selected)")
            self.freq_sel_btn.setObjectName("GhostButton")
            self.freq_all_btn = QPushButton("Frequency (all)")
            self.freq_all_btn.setObjectName("GhostButton")

            self.crack_caesar_btn = QPushButton("Crack Caesar (selected)")
            self.crack_caesar_btn.setObjectName("GhostButton")
            self.crack_subst_btn = QPushButton("Crack Substitution (method)")
            self.crack_subst_btn.setObjectName("GhostButton")

            topbar.addWidget(self.reload_records_btn)
            topbar.addWidget(self.reload_plugins_btn)
            topbar.addStretch(1)
            topbar.addWidget(self.freq_sel_btn)
            topbar.addWidget(self.freq_all_btn)
            topbar.addWidget(self.crack_caesar_btn)
            topbar.addWidget(self.crack_subst_btn)

            root.addLayout(topbar)

            body = QHBoxLayout()
            body.setSpacing(12)

            # Left: record list
            rec_card = Card("Records")
            self.rec_list = QListWidget()
            self.rec_list.setObjectName("List")
            rec_card.body.addWidget(self.rec_list)
            body.addWidget(rec_card, 2)

            # Center: tabs (ciphertext / plaintext / analysis)
            center_card = Card("Viewer")
            self.tabs = QTabWidget()
            self.tabs.setObjectName("Tabs")

            self.cipher_view = QTextEdit()
            self.cipher_view.setObjectName("TextArea")
            self.cipher_view.setReadOnly(True)

            self.plain_view = QTextEdit()
            self.plain_view.setObjectName("TextArea")
            self.plain_view.setReadOnly(True)

            self.analysis_view = QTextEdit()
            self.analysis_view.setObjectName("LogArea")
            self.analysis_view.setReadOnly(True)

            self.tabs.addTab(self.cipher_view, "Ciphertext")
            self.tabs.addTab(self.plain_view, "Plaintext")
            self.tabs.addTab(self.analysis_view, "Analysis")

            center_card.body.addWidget(self.tabs)
            body.addWidget(center_card, 4)

            # Right: dynamic plugin list + config + run
            plug_card = Card("Decrypt plugins")
            plug_top = QHBoxLayout()
            self.auto_pick_btn = QPushButton("Auto-pick by method_id")
            self.auto_pick_btn.setObjectName("GhostButton")
            self.use_record_cfg_btn = QPushButton("Use record config")
            self.use_record_cfg_btn.setObjectName("GhostButton")
            plug_top.addWidget(self.auto_pick_btn)
            plug_top.addWidget(self.use_record_cfg_btn)
            plug_card.body.addLayout(plug_top)

            self.plugin_list = QListWidget()
            self.plugin_list.setObjectName("List")
            self.plugin_list.setMinimumWidth(360)
            plug_card.body.addWidget(QLabel("Click a plugin (loaded from folder):"))
            plug_card.body.addWidget(self.plugin_list, 2)

            cfg_wrap = QFrame()
            cfg_wrap.setObjectName("ConfigPanel")
            cfg_layout = QVBoxLayout(cfg_wrap)
            cfg_layout.setContentsMargins(12, 12, 12, 12)
            cfg_layout.setSpacing(10)

            self.cfg_grid = QGridLayout()
            self.cfg_grid.setHorizontalSpacing(10)
            self.cfg_grid.setVerticalSpacing(10)
            cfg_layout.addLayout(self.cfg_grid)

            cfg_scroll = QScrollArea()
            cfg_scroll.setObjectName("ScrollArea")
            cfg_scroll.setWidgetResizable(True)
            cfg_scroll.setWidget(cfg_wrap)
            cfg_scroll.setMinimumHeight(160)

            plug_card.body.addWidget(QLabel("Plugin config:"))
            plug_card.body.addWidget(cfg_scroll)

            run_row = QHBoxLayout()
            self.run_decrypt_btn = QPushButton("Run decrypt")
            self.run_decrypt_btn.setObjectName("PrimaryButton")
            self.clear_plain_btn = QPushButton("Clear plaintext")
            self.clear_plain_btn.setObjectName("GhostButton")
            run_row.addWidget(self.run_decrypt_btn)
            run_row.addWidget(self.clear_plain_btn)
            plug_card.body.addLayout(run_row)

            body.addWidget(plug_card, 3)

            root.addLayout(body, 1)

            # state
            self.cfg_widgets: Dict[str, Tuple[str, Any]] = {}

            # hooks
            self.reload_records_btn.clicked.connect(self._reload_records)
            self.reload_plugins_btn.clicked.connect(self._reload_plugins)
            self.rec_list.currentRowChanged.connect(self._on_record_selected)
            self.plugin_list.currentRowChanged.connect(self._on_plugin_selected)

            self.run_decrypt_btn.clicked.connect(self._run_decrypt)
            self.clear_plain_btn.clicked.connect(lambda: self.plain_view.setPlainText(""))

            self.auto_pick_btn.clicked.connect(self._auto_pick_plugin)
            self.use_record_cfg_btn.clicked.connect(self._fill_cfg_from_record)

            self.freq_sel_btn.clicked.connect(self._freq_selected)
            self.freq_all_btn.clicked.connect(self._freq_all)
            self.crack_caesar_btn.clicked.connect(self._crack_caesar_selected)
            self.crack_subst_btn.clicked.connect(self._crack_subst_for_method)

            self.timer = QTimer(self)
            self.timer.timeout.connect(self._poll_work)
            self.timer.start(120)

            self._reload_plugins()
            self._reload_records()

        def _poll_work(self) -> None:
            while True:
                try:
                    kind, payload = self.work_q.get_nowait()
                except queue.Empty:
                    break
                if kind == "subst_done":
                    self.analysis_view.append(payload)
                    self.tabs.setCurrentWidget(self.analysis_view)

        def _reload_records(self) -> None:
            self.records = load_records()
            self.rec_list.clear()
            for r in self.records:
                mid = str(r.get("method_id", ""))
                rid = str(r.get("id", ""))
                ts = str(r.get("ts_utc", ""))
                it = QListWidgetItem(f"{rid}  [{mid}]  {ts}")
                it.setData(Qt.UserRole, r)
                self.rec_list.addItem(it)

            self.analysis_view.append(f"Loaded {len(self.records)} records")
            if self.rec_list.count() > 0 and self.rec_list.currentRow() < 0:
                self.rec_list.setCurrentRow(self.rec_list.count() - 1)

        def _reload_plugins(self) -> None:
            self.plugins = load_decrypt_plugins()
            self.plugin_list.clear()
            for mid, pl in sorted(self.plugins.items(), key=lambda kv: kv[0]):
                it = QListWidgetItem(f"{pl.method_name} ({mid})")
                it.setData(Qt.UserRole, mid)
                self.plugin_list.addItem(it)
            self.analysis_view.append(f"Loaded {len(self.plugins)} plugins from: {str(decryption_plugin_dir())}")
            if self.plugin_list.count() > 0 and self.plugin_list.currentRow() < 0:
                self.plugin_list.setCurrentRow(0)

        def _selected_record(self) -> Optional[Dict[str, Any]]:
            i = self.rec_list.currentRow()
            if i < 0:
                return None
            it = self.rec_list.item(i)
            r = it.data(Qt.UserRole)
            return r if isinstance(r, dict) else None

        def _selected_plugin_id(self) -> Optional[str]:
            i = self.plugin_list.currentRow()
            if i < 0:
                return None
            it = self.plugin_list.item(i)
            mid = it.data(Qt.UserRole)
            return str(mid) if mid is not None else None

        def _on_record_selected(self) -> None:
            r = self._selected_record()
            if not r:
                return
            ct = str(r.get("ciphertext", ""))
            meta = {
                "id": r.get("id"),
                "ts_utc": r.get("ts_utc"),
                "from": r.get("from"),
                "to": r.get("to"),
                "method_id": r.get("method_id"),
                "method_name": r.get("method_name"),
                "config": r.get("config", {}),
            }
            self.cipher_view.setPlainText(json.dumps(meta, ensure_ascii=True, indent=2) + "\n\n" + ct)
            self.tabs.setCurrentWidget(self.cipher_view)

        def _on_plugin_selected(self) -> None:
            self._rebuild_cfg_for_selected_plugin()

        def _clear_cfg_grid(self) -> None:
            while self.cfg_grid.count() > 0:
                item = self.cfg_grid.takeAt(0)
                w = item.widget()
                if w is not None:
                    w.deleteLater()
            self.cfg_widgets.clear()

        def _rebuild_cfg_for_selected_plugin(self) -> None:
            self._clear_cfg_grid()
            pid = self._selected_plugin_id()
            if not pid or pid not in self.plugins:
                return
            pl = self.plugins[pid]
            row = 0
            for f in pl.config_fields:
                key = str(f.get("key", "")).strip()
                label = str(f.get("label", key)).strip()
                ftype = str(f.get("type", "str")).strip()
                default = f.get("default")
                if not key:
                    continue

                lbl = QLabel(label)
                lbl.setObjectName("FieldLabel")

                if ftype == "int":
                    w = QSpinBox()
                    w.setObjectName("Input")
                    w.setRange(int(f.get("min", -10**9)), int(f.get("max", 10**9)))
                    if default is not None:
                        try:
                            w.setValue(int(default))
                        except Exception:
                            pass
                    self.cfg_grid.addWidget(lbl, row, 0)
                    self.cfg_grid.addWidget(w, row, 1)
                    self.cfg_widgets[key] = ("int", w)
                else:
                    w = QLineEdit("" if default is None else str(default))
                    w.setObjectName("Input")
                    self.cfg_grid.addWidget(lbl, row, 0)
                    self.cfg_grid.addWidget(w, row, 1)
                    self.cfg_widgets[key] = ("str", w)
                row += 1

            if row == 0:
                hint = QLabel("This plugin has no parameters.")
                hint.setObjectName("Hint")
                self.cfg_grid.addWidget(hint, 0, 0, 1, 2)

            # If a record is selected, prefer its config as initial values.
            self._fill_cfg_from_record()

        def _read_cfg(self) -> Dict[str, Any]:
            cfg: Dict[str, Any] = {}
            for key, (ftype, w) in self.cfg_widgets.items():
                if ftype == "int":
                    cfg[key] = int(w.value())
                else:
                    cfg[key] = str(w.text())
            return cfg

        def _fill_cfg_from_record(self) -> None:
            r = self._selected_record()
            pid = self._selected_plugin_id()
            if not r or not pid or pid not in self.plugins:
                return

            rec_cfg = r.get("config", {})
            if not isinstance(rec_cfg, dict):
                rec_cfg = {}

            pl = self.plugins[pid]
            defaults = _default_config(pl.config_fields)

            # merge: defaults then record overrides
            merged = dict(defaults)
            for k, v in rec_cfg.items():
                merged[str(k)] = v

            for key, (ftype, w) in self.cfg_widgets.items():
                if key not in merged:
                    continue
                val = merged[key]
                if ftype == "int":
                    try:
                        w.setValue(int(val))
                    except Exception:
                        pass
                else:
                    try:
                        w.setText("" if val is None else str(val))
                    except Exception:
                        pass

        def _auto_pick_plugin(self) -> None:
            r = self._selected_record()
            if not r:
                return
            want = str(r.get("method_id", "")).strip()
            if not want:
                return
            # find item in plugin list
            for i in range(self.plugin_list.count()):
                it = self.plugin_list.item(i)
                mid = it.data(Qt.UserRole)
                if str(mid) == want:
                    self.plugin_list.setCurrentRow(i)
                    self.analysis_view.append(f"Auto-picked plugin: {want}")
                    return
            self.analysis_view.append(f"No plugin found for method_id: {want}")

        def _run_decrypt(self) -> None:
            r = self._selected_record()
            pid = self._selected_plugin_id()
            if not r:
                self.analysis_view.append("No record selected")
                self.tabs.setCurrentWidget(self.analysis_view)
                return
            if not pid or pid not in self.plugins:
                self.analysis_view.append("No plugin selected")
                self.tabs.setCurrentWidget(self.analysis_view)
                return

            pl = self.plugins[pid]
            ct = str(r.get("ciphertext", ""))
            cfg = self._read_cfg()

            try:
                pt = str(pl.decrypt_fn(ct, cfg))
            except Exception as e:
                self.analysis_view.append(f"Decrypt failed: {e}")
                self.tabs.setCurrentWidget(self.analysis_view)
                return

            header = f"plugin={pl.method_name} ({pl.method_id})\nconfig={json.dumps(cfg, ensure_ascii=True)}\n\n"
            self.plain_view.setPlainText(header + pt)
            self.tabs.setCurrentWidget(self.plain_view)

        def _freq_selected(self) -> None:
            r = self._selected_record()
            if not r:
                return
            ct = str(r.get("ciphertext", ""))
            counts, total = letter_counts(ct)
            s = ", ".join(f"{c}:{n}" for c, n in top_letters(counts, 12))
            self.analysis_view.append(f"[frequency selected] {s} | TOTAL={total}")
            self.tabs.setCurrentWidget(self.analysis_view)

        def _freq_all(self) -> None:
            all_ct = "\n".join(str(x.get("ciphertext", "")) for x in self.records)
            counts, total = letter_counts(all_ct)
            s = ", ".join(f"{c}:{n}" for c, n in top_letters(counts, 12))
            self.analysis_view.append(f"[frequency all] {s} | TOTAL={total}")
            self.tabs.setCurrentWidget(self.analysis_view)

        def _crack_caesar_selected(self) -> None:
            r = self._selected_record()
            if not r:
                return
            ct = str(r.get("ciphertext", ""))
            shift, pt, score = crack_caesar(ct)
            self.analysis_view.append(f"[crack caesar] best_shift={shift} score={score:.2f}\n{pt[:1200]}")
            self.tabs.setCurrentWidget(self.analysis_view)

        def _crack_subst_for_method(self) -> None:
            r = self._selected_record()
            if not r:
                return
            mid = str(r.get("method_id", ""))
            agg = "\n".join(str(x.get("ciphertext", "")) for x in self.records if str(x.get("method_id", "")) == mid)
            if not agg.strip():
                self.analysis_view.append("[crack substitution] nothing to crack")
                self.tabs.setCurrentWidget(self.analysis_view)
                return

            self.analysis_view.append(f"[crack substitution] running for method_id={mid} ...")
            self.tabs.setCurrentWidget(self.analysis_view)

            def worker() -> None:
                key_map, pt, score = crack_substitution(agg)
                mapping = " ".join(f"{ALPHABET[i]}->{chr(A_ORD + key_map[i])}" for i in range(26))
                out = f"[crack substitution] score={score:.2f}\n{mapping}\n\n{pt[:1400]}"
                self.work_q.put(("subst_done", out))

            threading.Thread(target=worker, daemon=True).start()

    app = QApplication([])
    app.setApplicationName("HarborScope")

    f = QFont()
    f.setPointSize(10)
    app.setFont(f)

    qss = styles_qss_path()
    if qss.exists():
        try:
            app.setStyleSheet(qss.read_text(encoding="utf-8"))
        except Exception:
            pass

    w = Main()
    w.resize(1480, 860)
    w.show()
    app.exec()


def main() -> None:
    run_gui()


if __name__ == "__main__":
    main()