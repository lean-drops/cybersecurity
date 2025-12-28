# substitution_cipher_forest_app.py
import math
import os
import random
import string
from collections import Counter
from functools import partial

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QLinearGradient
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QTabWidget,
    QHeaderView,
)

ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"


def generate_monoalpha_key():
    alpha = string.ascii_uppercase
    sysrand = random.SystemRandom()

    perm = list(alpha)
    while True:
        sysrand.shuffle(perm)
        if perm != list(alpha):
            break

    key_str = "".join(perm)

    enc = {}
    dec = {}
    for p, c in zip(alpha, perm):
        enc[p] = c
        enc[p.lower()] = c.lower()
        dec[c] = p
        dec[c.lower()] = p.lower()

    return enc, dec, key_str


def apply_substitution(text, mapping):
    out = []
    for ch in text:
        out.append(mapping.get(ch, ch))
    return "".join(out)


def letter_frequencies(text):
    c = Counter()
    total = 0
    for ch in text:
        u = ch.upper()
        if "A" <= u <= "Z":
            c[u] += 1
            total += 1
    return c, total


def pct(count, total):
    if total <= 0:
        return 0.0
    return (100.0 * float(count)) / float(total)


def build_freq_suggestion(ct_freq):
    ranked = [k for (k, _) in ct_freq.most_common()]
    for i in range(26):
        L = chr(ord("A") + i)
        if L not in ranked:
            ranked.append(L)

    sugg = {}
    for i, c in enumerate(ranked):
        if i < len(ENGLISH_FREQ_ORDER):
            sugg[c] = ENGLISH_FREQ_ORDER[i]
        else:
            sugg[c] = ENGLISH_FREQ_ORDER[-1]
    return sugg, ranked


def sanitize_single_letter(s):
    if not s:
        return ""
    s = s.strip().upper()
    if len(s) == 0:
        return ""
    ch = s[0]
    if "A" <= ch <= "Z":
        return ch
    return ""


class ForestBackdrop(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ForestBackdrop")
        self.setAttribute(Qt.WA_StyledBackground, True)

    def paintEvent(self, event):
        w = max(1, self.width())
        h = max(1, self.height())

        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setRenderHint(QPainter.TextAntialiasing, True)

        g = QLinearGradient(0, 0, 0, h)
        g.setColorAt(0.00, QColor("#08160f"))
        g.setColorAt(0.35, QColor("#0b2617"))
        g.setColorAt(0.70, QColor("#0e2f1c"))
        g.setColorAt(1.00, QColor("#06110c"))
        p.fillRect(0, 0, w, h, g)

        mist = QLinearGradient(0, int(h * 0.20), 0, int(h * 0.65))
        mist.setColorAt(0.00, QColor(210, 230, 220, 28))
        mist.setColorAt(0.45, QColor(210, 230, 220, 52))
        mist.setColorAt(1.00, QColor(210, 230, 220, 10))
        p.fillRect(0, int(h * 0.18), w, int(h * 0.55), mist)

        p.setPen(Qt.NoPen)
        hill1 = QPainterPath()
        hill1.moveTo(0, int(h * 0.52))
        for x in range(0, w + 1, max(12, w // 60)):
            y = int(h * (0.52 + 0.02 * math.sin(x * 0.012) + 0.01 * math.sin(x * 0.031)))
            hill1.lineTo(x, y)
        hill1.lineTo(w, h)
        hill1.lineTo(0, h)
        hill1.closeSubpath()
        p.fillPath(hill1, QColor(10, 30, 18, 160))

        hill2 = QPainterPath()
        hill2.moveTo(0, int(h * 0.62))
        for x in range(0, w + 1, max(12, w // 55)):
            y = int(h * (0.62 + 0.025 * math.sin(x * 0.010 + 1.0) + 0.012 * math.sin(x * 0.027)))
            hill2.lineTo(x, y)
        hill2.lineTo(w, h)
        hill2.lineTo(0, h)
        hill2.closeSubpath()
        p.fillPath(hill2, QColor(6, 18, 11, 210))

        def draw_tree(x, base_y, height, width, color, alpha):
            p.setPen(Qt.NoPen)
            c = QColor(color)
            c.setAlpha(alpha)

            trunk_w = max(2, int(width * 0.18))
            trunk_h = max(6, int(height * 0.22))
            p.fillRect(int(x - trunk_w / 2), int(base_y - trunk_h), trunk_w, trunk_h, c)

            crown = QPainterPath()
            crown.moveTo(x, base_y - trunk_h - height)
            crown.lineTo(x - width, base_y - trunk_h)
            crown.lineTo(x + width, base_y - trunk_h)
            crown.closeSubpath()
            p.fillPath(crown, c)

            crown2 = QPainterPath()
            crown2.moveTo(x, base_y - trunk_h - int(height * 0.72))
            crown2.lineTo(x - int(width * 0.78), base_y - trunk_h + int(height * 0.08))
            crown2.lineTo(x + int(width * 0.78), base_y - trunk_h + int(height * 0.08))
            crown2.closeSubpath()
            p.fillPath(crown2, c)

        base = int(h * 0.66)
        for i in range(0, 34):
            t = float(i) / 33.0
            x = int(w * t)
            height = int(h * (0.10 + 0.12 * (0.5 + 0.5 * math.sin(7.0 * t + 0.8))))
            width = int(height * 0.40)
            draw_tree(x, base, height, width, "#07150e", 170)

        base2 = int(h * 0.74)
        for i in range(0, 26):
            t = float(i) / 25.0
            x = int(w * t + (w / 25.0) * 0.25 * math.sin(10.0 * t))
            height = int(h * (0.12 + 0.16 * (0.5 + 0.5 * math.sin(5.0 * t + 1.9))))
            width = int(height * 0.44)
            draw_tree(x, base2, height, width, "#050f0a", 220)

        vign = QLinearGradient(0, 0, w, 0)
        vign.setColorAt(0.00, QColor(0, 0, 0, 120))
        vign.setColorAt(0.15, QColor(0, 0, 0, 0))
        vign.setColorAt(0.85, QColor(0, 0, 0, 0))
        vign.setColorAt(1.00, QColor(0, 0, 0, 140))
        p.fillRect(0, 0, w, h, vign)

        vign2 = QLinearGradient(0, 0, 0, h)
        vign2.setColorAt(0.00, QColor(0, 0, 0, 140))
        vign2.setColorAt(0.20, QColor(0, 0, 0, 0))
        vign2.setColorAt(0.80, QColor(0, 0, 0, 0))
        vign2.setColorAt(1.00, QColor(0, 0, 0, 160))
        p.fillRect(0, 0, w, h, vign2)

        p.end()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Substitution Cipher - Forest/Wood Demo")
        self.setMinimumSize(QSize(1200, 780))

        self.enc_map = {}
        self.dec_map = {}
        self.key_str = ""

        self._ct_freq = Counter()
        self._ct_total = 0

        self._assign = {}      # cipher -> plain
        self._assign_inv = {}  # plain -> cipher
        self._locked = set()   # cipher letters locked/confirmed

        self._suggest = {}
        self._cipher_ranked = list(string.ascii_uppercase)
        self._row_for_cipher = {c: i for i, c in enumerate(self._cipher_ranked)}

        self.root = ForestBackdrop(self)
        self.setCentralWidget(self.root)

        self._build_ui()
        self._apply_default_demo()

    def _print(self, msg):
        print(msg)

    def _build_ui(self):
        outer = QVBoxLayout(self.root)
        outer.setContentsMargins(18, 18, 18, 18)
        outer.setSpacing(12)

        header = QFrame()
        header.setObjectName("HeaderBar")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(14, 12, 14, 12)
        hl.setSpacing(10)

        title = QLabel("Substitution Cipher")
        title.setObjectName("TitleLabel")
        title.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        self.key_label = QLabel("Key: (generate)")
        self.key_label.setObjectName("KeyLabel")
        self.key_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        hl.addWidget(title, 1)
        hl.addWidget(self.key_label, 0)
        outer.addWidget(header)

        controls = QFrame()
        controls.setObjectName("Panel")
        cl = QHBoxLayout(controls)
        cl.setContentsMargins(14, 12, 14, 12)
        cl.setSpacing(10)

        self.btn_gen = QPushButton("Generate Key")
        self.btn_enc = QPushButton("Encrypt ->")
        self.btn_dec = QPushButton("<- Decrypt")
        self.btn_an = QPushButton("Analyze")
        self.btn_reset = QPushButton("Reset Demo")

        self.btn_gen.clicked.connect(self.on_generate_key)
        self.btn_enc.clicked.connect(self.on_encrypt)
        self.btn_dec.clicked.connect(self.on_decrypt)
        self.btn_an.clicked.connect(self.on_analyze)
        self.btn_reset.clicked.connect(self._apply_default_demo)

        cl.addWidget(self.btn_gen)
        cl.addWidget(self.btn_enc)
        cl.addWidget(self.btn_dec)
        cl.addWidget(self.btn_an)
        cl.addStretch(1)
        cl.addWidget(self.btn_reset)
        outer.addWidget(controls)

        main_split = QSplitter(Qt.Vertical)
        main_split.setObjectName("MainVSplit")
        main_split.setChildrenCollapsible(False)

        text_split = QSplitter(Qt.Horizontal)
        text_split.setObjectName("TextSplit")
        text_split.setChildrenCollapsible(False)

        gb_plain = QGroupBox("Plaintext")
        gb_plain.setObjectName("WoodGroup")
        gp_l = QVBoxLayout(gb_plain)
        gp_l.setContentsMargins(12, 14, 12, 12)
        self.plain = QTextEdit()
        self.plain.setObjectName("TextWell")
        self.plain.setAcceptRichText(False)
        gp_l.addWidget(self.plain)

        gb_cipher = QGroupBox("Ciphertext")
        gb_cipher.setObjectName("WoodGroup")
        gc_l = QVBoxLayout(gb_cipher)
        gc_l.setContentsMargins(12, 14, 12, 12)
        self.cipher = QTextEdit()
        self.cipher.setObjectName("TextWell")
        self.cipher.setAcceptRichText(False)
        gc_l.addWidget(self.cipher)

        text_split.addWidget(gb_plain)
        text_split.addWidget(gb_cipher)
        text_split.setSizes([600, 600])

        main_split.addWidget(text_split)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("Tabs")
        self.tab_attack = QWidget()
        self.tab_freq = QWidget()
        self.tabs.addTab(self.tab_attack, "Attack")
        self.tabs.addTab(self.tab_freq, "Frequencies")

        self._build_attack_tab()
        self._build_freq_tab()

        main_split.addWidget(self.tabs)
        main_split.setSizes([280, 520])

        outer.addWidget(main_split, 1)

    def _build_attack_tab(self):
        root_l = QVBoxLayout(self.tab_attack)
        root_l.setContentsMargins(0, 0, 0, 0)
        root_l.setSpacing(10)

        attack_panel = QGroupBox("Frequency Attack Visualizer")
        attack_panel.setObjectName("WoodGroup")
        ap_l = QVBoxLayout(attack_panel)
        ap_l.setContentsMargins(12, 14, 12, 12)
        ap_l.setSpacing(10)

        topbar = QFrame()
        topbar.setObjectName("AttackTopBar")
        tb_l = QHBoxLayout(topbar)
        tb_l.setContentsMargins(10, 8, 10, 8)
        tb_l.setSpacing(10)

        self.attack_info = QLabel("Assign by clicking Suggest or typing 1 letter. Use Lock to confirm.")
        self.attack_info.setObjectName("AttackInfo")

        self.used_label = QLabel("Used: (none)")
        self.used_label.setObjectName("UsedLabel")

        self.locked_label = QLabel("Locked: 0")
        self.locked_label.setObjectName("LockedLabel")

        self.btn_auto = QPushButton("Auto-assign (respect locks)")
        self.btn_fill = QPushButton("Fill empty (respect locks)")
        self.btn_clear = QPushButton("Clear mapping (and locks)")

        self.btn_auto.clicked.connect(self.on_auto_assign_respect_locks)
        self.btn_fill.clicked.connect(self.on_fill_empty_with_suggest_respect_locks)
        self.btn_clear.clicked.connect(self.on_clear_mapping)

        tb_l.addWidget(self.attack_info, 1)
        tb_l.addWidget(self.used_label, 0)
        tb_l.addWidget(self.locked_label, 0)
        tb_l.addWidget(self.btn_auto, 0)
        tb_l.addWidget(self.btn_fill, 0)
        tb_l.addWidget(self.btn_clear, 0)
        ap_l.addWidget(topbar, 0)

        split = QSplitter(Qt.Horizontal)
        split.setObjectName("AttackHSplit")
        split.setChildrenCollapsible(False)

        left_box = QGroupBox("Mapping (cipher -> plain)")
        left_box.setObjectName("WoodGroupInner")
        lb_l = QVBoxLayout(left_box)
        lb_l.setContentsMargins(10, 12, 10, 10)
        lb_l.setSpacing(8)

        self.map_table = QTableWidget(26, 5)
        self.map_table.setObjectName("MapTable")
        self.map_table.setHorizontalHeaderLabels(["Cipher", "Count", "Suggest", "Assign", "Lock"])
        self.map_table.verticalHeader().setVisible(False)
        self.map_table.setAlternatingRowColors(True)
        self.map_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.map_table.setSelectionMode(QTableWidget.SingleSelection)
        self.map_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.map_table.setSortingEnabled(False)
        self.map_table.cellClicked.connect(self.on_map_table_clicked)

        hh = self.map_table.horizontalHeader()
        hh.setStretchLastSection(False)
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.Fixed)
        hh.setSectionResizeMode(4, QHeaderView.Fixed)
        self.map_table.setColumnWidth(3, 84)
        self.map_table.setColumnWidth(4, 64)

        vh = self.map_table.verticalHeader()
        vh.setDefaultSectionSize(24)
        vh.setMinimumSectionSize(22)

        self._map_edits = []
        self._lock_boxes = []
        for row in range(26):
            it_cipher = QTableWidgetItem("")
            it_cipher.setTextAlignment(int(Qt.AlignVCenter | Qt.AlignHCenter))
            it_count = QTableWidgetItem("0")
            it_count.setTextAlignment(int(Qt.AlignVCenter | Qt.AlignHCenter))
            it_sugg = QTableWidgetItem("")
            it_sugg.setTextAlignment(int(Qt.AlignVCenter | Qt.AlignHCenter))

            self.map_table.setItem(row, 0, it_cipher)
            self.map_table.setItem(row, 1, it_count)
            self.map_table.setItem(row, 2, it_sugg)

            edit = QLineEdit()
            edit.setObjectName("MapEdit")
            edit.setMaxLength(1)
            edit.setAlignment(Qt.AlignCenter)
            edit.textChanged.connect(partial(self.on_assign_edit_changed, row))
            self.map_table.setCellWidget(row, 3, edit)
            self._map_edits.append(edit)

            lock = QCheckBox("")
            lock.setObjectName("LockBox")
            lock.setTristate(False)
            lock.stateChanged.connect(partial(self.on_lock_changed, row))
            lock.setFocusPolicy(Qt.NoFocus)
            lock.setToolTip("Lock = confirmed (prevents changes and auto-overwrite)")
            lock_wrap = QWidget()
            lock_l = QHBoxLayout(lock_wrap)
            lock_l.setContentsMargins(0, 0, 0, 0)
            lock_l.setAlignment(Qt.AlignCenter)
            lock_l.addWidget(lock)
            self.map_table.setCellWidget(row, 4, lock_wrap)
            self._lock_boxes.append(lock)

        lb_l.addWidget(self.map_table, 1)

        hint = QLabel("Locked rows are highlighted and protected from Auto/Fill and edits.")
        hint.setObjectName("SmallHint")
        hint.setWordWrap(True)
        lb_l.addWidget(hint, 0)

        right_box = QGroupBox("Draft Decryption (unknown letters shown as '.')")
        right_box.setObjectName("WoodGroupInner")
        rb_l = QVBoxLayout(right_box)
        rb_l.setContentsMargins(10, 12, 10, 10)
        self.preview = QTextEdit()
        self.preview.setObjectName("PreviewWell")
        self.preview.setReadOnly(True)
        self.preview.setAcceptRichText(False)
        rb_l.addWidget(self.preview, 1)

        split.addWidget(left_box)
        split.addWidget(right_box)
        split.setSizes([420, 720])

        ap_l.addWidget(split, 1)
        root_l.addWidget(attack_panel, 1)

    def _build_freq_tab(self):
        root_l = QVBoxLayout(self.tab_freq)
        root_l.setContentsMargins(0, 0, 0, 0)
        root_l.setSpacing(10)

        freq_panel = QGroupBox("Frequency Analysis (A-Z)")
        freq_panel.setObjectName("WoodGroup")
        fp_l = QVBoxLayout(freq_panel)
        fp_l.setContentsMargins(12, 14, 12, 12)

        self.freq_table = QTableWidget(26, 5)
        self.freq_table.setObjectName("FreqTable")
        self.freq_table.setHorizontalHeaderLabels(["Letter", "PT Count", "PT %", "CT Count", "CT %"])
        self.freq_table.verticalHeader().setVisible(False)
        self.freq_table.setAlternatingRowColors(True)
        self.freq_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.freq_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.freq_table.setSelectionMode(QTableWidget.SingleSelection)
        self.freq_table.setSortingEnabled(False)

        hh = self.freq_table.horizontalHeader()
        hh.setStretchLastSection(True)
        for col in range(5):
            hh.setSectionResizeMode(col, QHeaderView.ResizeToContents)

        vh = self.freq_table.verticalHeader()
        vh.setDefaultSectionSize(22)
        vh.setMinimumSectionSize(20)

        fp_l.addWidget(self.freq_table, 1)
        root_l.addWidget(freq_panel, 1)

    def _update_labels(self):
        used = sorted(self._assign_inv.keys())
        self.used_label.setText("Used: (none)" if not used else ("Used: " + "".join(used)))
        self.locked_label.setText("Locked: {}".format(len(self._locked)))

    def _apply_lock_visuals_row(self, row, locked):
        # highlight first 3 cells (Cipher/Count/Suggest)
        bg = QColor(47, 107, 60, 60) if locked else QColor(0, 0, 0, 0)
        for col in (0, 1, 2):
            it = self.map_table.item(row, col)
            if it is not None:
                it.setBackground(bg)

        ed = self._map_edits[row]
        ed.setProperty("locked", bool(locked))
        ed.setReadOnly(bool(locked))
        ed.style().unpolish(ed)
        ed.style().polish(ed)

    def _sync_lock_boxes_from_state(self):
        for row in range(26):
            cipher = self._cipher_ranked[row]
            want = cipher in self._locked
            cb = self._lock_boxes[row]
            cb.blockSignals(True)
            cb.setChecked(want)
            cb.blockSignals(False)
            self._apply_lock_visuals_row(row, want)

    def on_generate_key(self):
        self.enc_map, self.dec_map, self.key_str = generate_monoalpha_key()
        alpha = string.ascii_uppercase
        self.key_label.setText("Key: " + alpha + " -> " + self.key_str)
        self._print("Generated key (monoalphabetic substitution).")

    def on_encrypt(self):
        if not self.enc_map:
            self.on_generate_key()
        pt = self.plain.toPlainText()
        ct = apply_substitution(pt, self.enc_map)
        self.cipher.setPlainText(ct)
        self._print("Encrypted plaintext -> ciphertext.")
        self.on_analyze()

    def on_decrypt(self):
        if not self.dec_map:
            self.on_generate_key()
        ct = self.cipher.toPlainText()
        pt = apply_substitution(ct, self.dec_map)
        self.plain.setPlainText(pt)
        self._print("Decrypted ciphertext -> plaintext.")
        self.on_analyze()

    def on_clear_mapping(self):
        self._assign = {}
        self._assign_inv = {}
        self._locked = set()
        self._sync_assign_edits_from_state()
        self._sync_lock_boxes_from_state()
        self._update_preview()
        self._print("Cleared mapping and locks.")

    def on_auto_assign_respect_locks(self):
        if not self._ct_freq:
            self.on_analyze()

        used_plain = set(self._assign_inv.keys())

        # Overwrite only unlocked rows
        for cipher in self._cipher_ranked:
            if cipher in self._locked:
                continue
            # clear old assignment (so overwrite is real)
            prev = self._assign.get(cipher, "")
            if prev:
                self._assign.pop(cipher, None)
                if self._assign_inv.get(prev) == cipher:
                    self._assign_inv.pop(prev, None)
                    used_plain.discard(prev)

        for cipher in self._cipher_ranked:
            if cipher in self._locked:
                continue
            target = self._suggest.get(cipher, "")
            if target and target not in used_plain:
                self._assign[cipher] = target
                self._assign_inv[target] = cipher
                used_plain.add(target)

        self._sync_assign_edits_from_state()
        self._sync_lock_boxes_from_state()
        self._update_preview()
        self._print("Auto-assign applied (respected locks).")

    def on_fill_empty_with_suggest_respect_locks(self):
        if not self._ct_freq:
            self.on_analyze()

        used_plain = set(self._assign_inv.keys())
        for cipher in self._cipher_ranked:
            if cipher in self._locked:
                continue
            if self._assign.get(cipher, ""):
                continue
            target = self._suggest.get(cipher, "")
            if target and target not in used_plain:
                self._assign[cipher] = target
                self._assign_inv[target] = cipher
                used_plain.add(target)

        self._sync_assign_edits_from_state()
        self._sync_lock_boxes_from_state()
        self._update_preview()
        self._print("Filled empty assigns (respected locks).")

    def on_lock_changed(self, row, state):
        cipher = self._cipher_ranked[row] if 0 <= row < len(self._cipher_ranked) else None
        if cipher is None:
            return

        # Only allow locking if there is an assignment.
        if state == Qt.Checked:
            if not self._assign.get(cipher, ""):
                cb = self._lock_boxes[row]
                cb.blockSignals(True)
                cb.setChecked(False)
                cb.blockSignals(False)
                self._apply_lock_visuals_row(row, False)
                self._update_labels()
                return
            self._locked.add(cipher)
            self._apply_lock_visuals_row(row, True)
        else:
            self._locked.discard(cipher)
            self._apply_lock_visuals_row(row, False)

        self._update_labels()
        self._print("Lock {} = {}".format(cipher, "ON" if cipher in self._locked else "OFF"))

    def on_assign_edit_changed(self, row, _):
        cipher = self._cipher_ranked[row] if 0 <= row < len(self._cipher_ranked) else None
        if cipher is None:
            return

        # If locked, revert UI to current state.
        if cipher in self._locked:
            self._sync_assign_edits_from_state()
            return

        edit = self._map_edits[row]
        raw = edit.text()
        val = sanitize_single_letter(raw)

        if raw != val:
            edit.blockSignals(True)
            edit.setText(val)
            edit.blockSignals(False)

        ok = self._set_assignment(cipher, val)
        if not ok:
            # revert if blocked by locked conflict
            self._sync_assign_edits_from_state()
        self._update_preview()

    def on_map_table_clicked(self, row, col):
        # Clicking Suggest copies suggestion to Assign for that cipher.
        if col != 2:
            return
        if not (0 <= row < 26):
            return
        cipher = self._cipher_ranked[row]
        if cipher in self._locked:
            return

        sugg_item = self.map_table.item(row, 2)
        if sugg_item is None:
            return
        target = sanitize_single_letter(sugg_item.text())
        if not target:
            return

        ok = self._set_assignment(cipher, target)
        if ok:
            self._sync_assign_edits_from_state()
            self._update_preview()
            self._print("Assign {} -> {} (from Suggest click)".format(cipher, target))
        else:
            self._sync_assign_edits_from_state()
            self._update_preview()

    def _set_assignment(self, cipher, plain):
        """
        Returns True if applied, False if blocked (typically due to locked conflict).
        """
        # If trying to change a locked cipher, block.
        if cipher in self._locked:
            return False

        # Remove previous mapping for this cipher
        prev = self._assign.get(cipher, "")
        if prev:
            self._assign.pop(cipher, None)
            if self._assign_inv.get(prev) == cipher:
                self._assign_inv.pop(prev, None)

        if not plain:
            # If cipher was locked (should not happen due to checks) we'd unlock, but we block earlier.
            return True

        # Uniqueness: if plain already used, decide based on whether the other cipher is locked.
        other_cipher = self._assign_inv.get(plain)
        if other_cipher and other_cipher != cipher:
            if other_cipher in self._locked:
                # Do not steal from locked/confirmed mapping.
                return False
            # Clear other (unlocked) cipher
            self._assign.pop(other_cipher, None)
            self._assign_inv.pop(plain, None)
            other_row = self._row_for_cipher.get(other_cipher)
            if other_row is not None and 0 <= other_row < 26:
                ed = self._map_edits[other_row]
                ed.blockSignals(True)
                ed.setText("")
                ed.blockSignals(False)

        self._assign[cipher] = plain
        self._assign_inv[plain] = cipher
        return True

    def _sync_assign_edits_from_state(self):
        for row in range(26):
            cipher = self._cipher_ranked[row]
            val = self._assign.get(cipher, "")
            ed = self._map_edits[row]
            ed.blockSignals(True)
            ed.setText(val)
            ed.blockSignals(False)

    def _current_attack_map(self):
        m = {}
        for i in range(26):
            c = chr(ord("A") + i)
            plain = self._assign.get(c, "")
            if plain:
                m[c] = plain
                m[c.lower()] = plain.lower()
            else:
                m[c] = "."
                m[c.lower()] = "."
        return m

    def _update_preview(self):
        ct = self.cipher.toPlainText()
        draft = apply_substitution(ct, self._current_attack_map())
        self.preview.setPlainText(draft)
        self._update_labels()

    def on_analyze(self):
        pt = self.plain.toPlainText()
        ct = self.cipher.toPlainText()

        pt_freq, pt_total = letter_frequencies(pt)
        ct_freq, ct_total = letter_frequencies(ct)

        self._ct_freq = ct_freq
        self._ct_total = ct_total
        self._suggest, ranked = build_freq_suggestion(ct_freq) if ct_total > 0 else ({}, list(string.ascii_uppercase))
        self._cipher_ranked = ranked
        self._row_for_cipher = {c: i for i, c in enumerate(self._cipher_ranked)}

        # Frequencies tab
        for i in range(26):
            letter = chr(ord("A") + i)
            pt_c = int(pt_freq.get(letter, 0))
            ct_c = int(ct_freq.get(letter, 0))

            items = [
                QTableWidgetItem(letter),
                QTableWidgetItem(str(pt_c)),
                QTableWidgetItem("{:.2f}%".format(pct(pt_c, pt_total))),
                QTableWidgetItem(str(ct_c)),
                QTableWidgetItem("{:.2f}%".format(pct(ct_c, ct_total))),
            ]
            for it in items:
                it.setTextAlignment(int(Qt.AlignVCenter | Qt.AlignHCenter))
            for col, it in enumerate(items):
                self.freq_table.setItem(i, col, it)

        # Attack table sorted by CT frequency
        for row in range(26):
            cipher = self._cipher_ranked[row]
            count = int(ct_freq.get(cipher, 0))
            sugg = self._suggest.get(cipher, "")

            it_cipher = self.map_table.item(row, 0)
            it_count = self.map_table.item(row, 1)
            it_sugg = self.map_table.item(row, 2)

            if it_cipher is not None:
                it_cipher.setText(cipher)
            if it_count is not None:
                it_count.setText(str(count))
            if it_sugg is not None:
                it_sugg.setText(sugg)

        self.freq_table.resizeColumnsToContents()
        self.map_table.resizeColumnsToContents()

        self._sync_assign_edits_from_state()
        self._sync_lock_boxes_from_state()
        self._update_preview()

        pt_profile = sorted([pt_freq.get(chr(ord("A") + i), 0) for i in range(26)], reverse=True)
        ct_profile = sorted([ct_freq.get(chr(ord("A") + i), 0) for i in range(26)], reverse=True)

        def top_profile_str(profile, n=12):
            return ", ".join(str(x) for x in profile[:n])

        self._print("Analyze:")
        self._print("  PT total letters: {}".format(pt_total))
        self._print("  CT total letters: {}".format(ct_total))
        self._print("  PT profile(top): " + top_profile_str(pt_profile))
        self._print("  CT profile(top): " + top_profile_str(ct_profile))
        self._print("")

    def _apply_default_demo(self):
        demo = (
            "Substitution cipher demo.\n\n"
            "A monoalphabetic substitution cipher replaces each letter with a different letter (a permutation).\n"
            "This leaks structure: ciphertext letter frequencies match plaintext frequencies (only relabeled).\n"
            "With enough ciphertext, frequency analysis can recover much of the mapping.\n\n"
            "Workflow:\n"
            "  1) Encrypt -> Analyze\n"
            "  2) Attack tab: click Suggest or type 1 letter in Assign\n"
            "  3) Lock the rows you are sure about (visible + protected)\n"
        )
        self.plain.setPlainText(demo)
        self.on_generate_key()
        self.on_encrypt()
        self.on_clear_mapping()
        self.on_analyze()
        self.tabs.setCurrentIndex(0)
        self._print("Demo loaded (forest/wood theme via sc_style.qss).")


def load_stylesheet(app):
    qss_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sc_style.qss")
    try:
        with open(qss_path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())
    except Exception:
        pass


def main():
    app = QApplication([])
    app.setApplicationName("Substitution Cipher Forest")

    base_font = QFont("Segoe UI")
    base_font.setPointSize(10)
    app.setFont(base_font)

    load_stylesheet(app)

    w = MainWindow()
    w.show()

    app.exec()


if __name__ == "__main__":
    main()
