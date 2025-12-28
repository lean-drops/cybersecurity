# kerckhoffs_demo_gui.py
import base64
import hashlib
import hmac
import os
import sys
import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QVBoxLayout,
    QWidget,
)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    n = min(len(a), len(b))
    return bytes([a[i] ^ b[i] for i in range(n)])


class ObscuritySubstCipher:
    """
    Security by obscurity demo:
    - No key.
    - A fixed, secret substitution table is the "secret".
    - If the table leaks, all past ciphertext can be decrypted.
    """

    def __init__(self) -> None:
        self._perm = self._build_perm()
        self._inv = self._invert_perm(self._perm)

    @staticmethod
    def _build_perm() -> bytes:
        seed = b"fixed-secret-permutation-seed-demo-only"
        pool = list(range(256))
        out = []
        state = seed
        for _ in range(256):
            state = hashlib.sha256(state).digest()
            idx = int.from_bytes(state[:4], "big") % len(pool)
            out.append(pool.pop(idx))
        return bytes(out)

    @staticmethod
    def _invert_perm(perm: bytes) -> bytes:
        inv = [0] * 256
        for i, v in enumerate(perm):
            inv[v] = i
        return bytes(inv)

    def encrypt(self, pt: bytes) -> bytes:
        return bytes([self._perm[x] for x in pt])

    def decrypt(self, ct: bytes) -> bytes:
        return bytes([self._inv[x] for x in ct])

    def leak_algorithm_details(self) -> dict:
        return {"perm_b64": b64e(self._perm), "inv_b64": b64e(self._inv)}


class KerckhoffsHmacCtrCipher:
    """
    Kerckhoffs demo:
    - Algorithm is assumed public (attacker knows it).
    - Only the key must remain secret.
    - Uses HMAC-SHA256 in counter mode to generate a keystream (demo, not library-grade).
    - Nonce is public and included with ciphertext.
    """

    NONCE_LEN = 8

    @staticmethod
    def _kdf_stream(key: bytes, nonce: bytes, nbytes: int) -> bytes:
        out = b""
        counter = 0
        while len(out) < nbytes:
            msg = nonce + counter.to_bytes(8, "big")
            block = hmac.new(key, msg, hashlib.sha256).digest()
            out += block
            counter += 1
        return out[:nbytes]

    def encrypt(self, key: bytes, pt: bytes) -> bytes:
        nonce = os.urandom(self.NONCE_LEN)
        ks = self._kdf_stream(key, nonce, len(pt))
        ct = xor_bytes(pt, ks)
        return nonce + ct

    def decrypt(self, key: bytes, blob: bytes) -> bytes:
        if len(blob) < self.NONCE_LEN:
            raise ValueError("ciphertext too short")
        nonce = blob[: self.NONCE_LEN]
        ct = blob[self.NONCE_LEN :]
        ks = self._kdf_stream(key, nonce, len(ct))
        return xor_bytes(ct, ks)


def json_pretty(obj: dict) -> str:
    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')

    def fmt(v, indent: int) -> str:
        sp = "  " * indent
        if isinstance(v, dict):
            ks = sorted(v.keys())
            parts = ["{"]
            for i, k in enumerate(ks):
                comma = "," if i < len(ks) - 1 else ""
                parts.append(
                    "\n" + sp + "  " + '"' + esc(str(k)) + '": ' + fmt(v[k], indent + 1) + comma
                )
            parts.append("\n" + sp + "}")
            return "".join(parts)
        if isinstance(v, list):
            parts = ["["]
            for i, x in enumerate(v):
                comma = "," if i < len(v) - 1 else ""
                parts.append("\n" + sp + "  " + fmt(x, indent + 1) + comma)
            parts.append("\n" + sp + "]")
            return "".join(parts)
        if isinstance(v, bool):
            return "true" if v else "false"
        if v is None:
            return "null"
        if isinstance(v, (int, float)):
            return str(v)
        return '"' + esc(str(v)) + '"'

    return fmt(obj, 0)


class AppWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Kerckhoffs principle demo (PySide)")
        self.resize(1200, 780)

        self.obsc = ObscuritySubstCipher()
        self.ker = KerckhoffsHmacCtrCipher()

        # History items: dict with fields: ts, mode, plaintext, ciphertext_b64, note
        self.history = []

        self._build_ui()
        self._log_intro()
        self._log_attacker_state()
        self._on_mode_changed()

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)

        outer = QVBoxLayout(root)
        outer.setContentsMargins(14, 14, 14, 14)
        outer.setSpacing(12)

        header = QFrame()
        header.setObjectName("HeaderCard")
        header.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        hbox = QVBoxLayout(header)
        hbox.setContentsMargins(14, 14, 14, 14)
        hbox.setSpacing(6)

        title = QLabel("Kerckhoffs principle: assume attacker knows the algorithm; only the key is secret.")
        title.setObjectName("TitleLabel")
        subtitle = QLabel(
            "Demo: compare a public-algorithm + secret-key scheme vs a no-key obscurity scheme that fails when leaked."
        )
        subtitle.setObjectName("SubtitleLabel")
        subtitle.setWordWrap(True)

        hbox.addWidget(title)
        hbox.addWidget(subtitle)
        outer.addWidget(header)

        controls = QFrame()
        controls.setObjectName("ControlCard")
        grid = QGridLayout(controls)
        grid.setContentsMargins(14, 14, 14, 14)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(10)

        grid.addWidget(QLabel("Mode"), 0, 0, Qt.AlignLeft)
        self.mode_box = QComboBox()
        self.mode_box.addItems(
            [
                "Kerckhoffs cipher (public algorithm + key)",
                "Obscurity cipher (no key; secret algorithm)",
            ]
        )
        self.mode_box.currentIndexChanged.connect(self._on_mode_changed)
        grid.addWidget(self.mode_box, 0, 1, 1, 1)

        grid.addWidget(QLabel("Key (Kerckhoffs only)"), 0, 2, Qt.AlignLeft)
        self.key_edit = QLineEdit("correct-horse-battery-staple")
        self.key_edit.setPlaceholderText("Enter key")
        grid.addWidget(self.key_edit, 0, 3, 1, 1)

        grid.addWidget(QLabel("Message"), 1, 0, Qt.AlignLeft)
        self.msg_edit = QLineEdit("hello defense in depth / kerckhoffs demo")
        self.msg_edit.setPlaceholderText("Type a message to encrypt")
        grid.addWidget(self.msg_edit, 1, 1, 1, 3)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        self.btn_send = QPushButton("Encrypt/Send")
        self.btn_send.clicked.connect(self.on_send)

        self.btn_recv = QPushButton("Decrypt as Receiver")
        self.btn_recv.clicked.connect(self.on_receiver_decrypt)

        self.btn_atk = QPushButton("Attacker attempt decrypt")
        self.btn_atk.clicked.connect(self.on_attacker_decrypt)

        self.btn_clear_log = QPushButton("Clear output log")
        self.btn_clear_log.clicked.connect(self.on_clear_log)

        self.btn_clear_hist = QPushButton("Clear history")
        self.btn_clear_hist.clicked.connect(self.on_clear_history)

        btn_row.addWidget(self.btn_send)
        btn_row.addWidget(self.btn_recv)
        btn_row.addWidget(self.btn_atk)
        btn_row.addSpacing(14)
        btn_row.addWidget(self.btn_clear_log)
        btn_row.addWidget(self.btn_clear_hist)
        btn_row.addStretch(1)

        grid.addLayout(btn_row, 2, 0, 1, 4)

        attacker = QGroupBox("Attacker knowledge toggles")
        attacker.setObjectName("AttackerGroup")
        abox = QVBoxLayout(attacker)
        abox.setContentsMargins(12, 12, 12, 12)
        abox.setSpacing(8)

        self.chk_alg_leaked = QCheckBox(
            "Algorithm leaked (Obscurity: attacker gets substitution table)"
        )
        self.chk_alg_leaked.toggled.connect(self._log_attacker_state)

        self.chk_key_stolen = QCheckBox(
            "Key stolen (Kerckhoffs: attacker gets the key)"
        )
        self.chk_key_stolen.toggled.connect(self._log_attacker_state)

        abox.addWidget(self.chk_alg_leaked)
        abox.addWidget(self.chk_key_stolen)

        grid.addWidget(attacker, 3, 0, 1, 4)

        outer.addWidget(controls)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setObjectName("MainSplitter")
        splitter.setChildrenCollapsible(False)

        left = QFrame()
        left.setObjectName("PaneCard")
        lv = QVBoxLayout(left)
        lv.setContentsMargins(14, 14, 14, 14)
        lv.setSpacing(10)

        left_title = QLabel("History (select one item, then decrypt)")
        left_title.setObjectName("PaneTitle")
        lv.addWidget(left_title)

        self.history_list = QListWidget()
        self.history_list.currentRowChanged.connect(self.on_select_history)
        lv.addWidget(self.history_list, 0)

        details_title = QLabel("Selected item details")
        details_title.setObjectName("PaneTitle")
        lv.addWidget(details_title)

        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        lv.addWidget(self.details, 1)

        right = QFrame()
        right.setObjectName("PaneCard")
        rv = QVBoxLayout(right)
        rv.setContentsMargins(14, 14, 14, 14)
        rv.setSpacing(10)

        right_title = QLabel("Log (step-by-step explanation per click)")
        right_title.setObjectName("PaneTitle")
        rv.addWidget(right_title)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        rv.addWidget(self.log, 1)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([520, 680])

        outer.addWidget(splitter, 1)

    def _scroll_to_end(self, edit: QPlainTextEdit) -> None:
        sb = edit.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _log(self, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self.log.appendPlainText("[%s] %s" % (ts, msg))
        self._scroll_to_end(self.log)

    def _log_json(self, label: str, obj: dict) -> None:
        try:
            pretty = json_pretty(obj)
        except Exception:
            pretty = str(obj)
        self._log(label + ":\n" + pretty)

    def _log_intro(self) -> None:
        self._log("Goal: show why 'security by obscurity' fails and why Kerckhoffs holds.")
        self._log("Kerckhoffs assumption: attacker knows the algorithm and can inspect your code/system.")
        self._log("Therefore: only a key (or secret parameter) should be required for confidentiality.")
        self._log("Try: send messages in both modes, then toggle attacker knowledge and decrypt.")

    def _log_attacker_state(self) -> None:
        self._log(
            "Attacker state: alg_leaked=%s, key_stolen=%s"
            % (self.chk_alg_leaked.isChecked(), self.chk_key_stolen.isChecked())
        )

    def on_clear_log(self) -> None:
        self.log.setPlainText("")
        self._log("Output log cleared.")

    def on_clear_history(self) -> None:
        self.history = []
        self.history_list.clear()
        self.details.setPlainText("")
        self._log("History cleared.")

    def _current_mode(self) -> str:
        return self.mode_box.currentText()

    def _key_bytes(self) -> bytes:
        return self.key_edit.text().encode("utf-8")

    def _selected_index(self):
        idx = int(self.history_list.currentRow())
        if idx < 0 or idx >= len(self.history):
            return None
        return idx

    def _refresh_details(self, idx: int) -> None:
        item = self.history[idx]

        parts = []
        parts.append("timestamp: %s" % item["ts"])
        parts.append("mode: %s" % item["mode"])
        parts.append("note: %s" % item.get("note", ""))
        parts.append("")
        parts.append("plaintext (utf-8):")
        parts.append(item["plaintext"])
        parts.append("")
        parts.append("ciphertext (base64):")
        parts.append(item["ciphertext_b64"])

        if item["mode"].startswith("Kerckhoffs"):
            try:
                blob = b64d(item["ciphertext_b64"])
                nonce = blob[: self.ker.NONCE_LEN]
                ct = blob[self.ker.NONCE_LEN :]
                parts.append("")
                parts.append("kerckhoffs internal:")
                parts.append("nonce (hex): %s" % nonce.hex())
                parts.append("ct_len: %d" % len(ct))
            except Exception:
                pass

        self.details.setPlainText("\n".join(parts))
        self._scroll_to_end(self.details)

    def on_select_history(self, _row: int) -> None:
        idx = self._selected_index()
        if idx is None:
            return
        self._refresh_details(idx)

    def _on_mode_changed(self) -> None:
        mode = self._current_mode()
        is_k = mode.startswith("Kerckhoffs")
        self.key_edit.setEnabled(is_k)
        if is_k:
            self.key_edit.setPlaceholderText("Key used for Kerckhoffs mode")
        else:
            self.key_edit.setPlaceholderText("Not used in Obscurity mode")

    def on_send(self) -> None:
        mode = self._current_mode()
        msg = self.msg_edit.text()
        pt = msg.encode("utf-8")

        self._log("CLICK Encrypt/Send")
        self._log("Plan:")
        self._log("  1) Take plaintext from Message field.")
        self._log("  2) Encrypt according to selected mode.")
        self._log("  3) Store ciphertext in History (this simulates 'past ciphertext exists').")
        self._log("  4) Attacker can later try to decrypt past ciphertext depending on what leaked.")

        if mode.startswith("Kerckhoffs"):
            key = self._key_bytes()
            self._log("Mode=Kerckhoffs: algorithm is public; secrecy must come from key.")
            self._log(
                "Encrypt details: nonce=random(8 bytes, public) + ct = pt XOR HMAC(key, nonce||counter) stream."
            )
            blob = self.ker.encrypt(key, pt)
            ct_b64 = b64e(blob)
            note = "nonce is public; confidentiality depends on secret key"
            short_mode = "Kerckhoffs"
        else:
            self._log("Mode=Obscurity: NO KEY. Secrecy depends on a hidden substitution table.")
            self._log("Encrypt details: ct = subst_table[pt_byte]. If table leaks, all past ct decrypts.")
            blob = self.obsc.encrypt(pt)
            ct_b64 = b64e(blob)
            note = "no key; secrecy depends on hidden table (bad)"
            short_mode = "Obscurity"

        item = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "mode": mode,
            "plaintext": msg,
            "ciphertext_b64": ct_b64,
            "note": note,
        }
        self.history.append(item)
        self.history_list.addItem("%s | %s | ct_b64_len=%d" % (item["ts"], short_mode, len(ct_b64)))

        last = len(self.history) - 1
        self.history_list.setCurrentRow(last)
        self._refresh_details(last)

        self._log("Stored in history. Now try: Attacker attempt decrypt, then toggle leaks and retry.")

    def on_receiver_decrypt(self) -> None:
        idx = self._selected_index()
        self._log("CLICK Decrypt as Receiver")
        self._log("Plan:")
        self._log("  1) Use selected history item ciphertext.")
        self._log("  2) Receiver has all legitimate secrets (key for Kerckhoffs; table for Obscurity).")
        self._log("  3) Decrypt and show plaintext match/mismatch.")

        if idx is None:
            self._log("No history item selected.")
            return

        item = self.history[idx]
        mode = item["mode"]
        try:
            blob = b64d(item["ciphertext_b64"])
        except Exception as e:
            self._log("Invalid base64 in history: %s" % str(e))
            return

        if mode.startswith("Kerckhoffs"):
            key = self._key_bytes()
            self._log("Receiver decrypt Kerckhoffs: needs the secret key. Algorithm assumed known.")
            try:
                pt = self.ker.decrypt(key, blob)
                out = pt.decode("utf-8", errors="replace")
            except Exception as e:
                self._log("Decrypt error: %s" % str(e))
                return
        else:
            self._log("Receiver decrypt Obscurity: uses the (secret) substitution inverse table.")
            pt = self.obsc.decrypt(blob)
            out = pt.decode("utf-8", errors="replace")

        self._log("Receiver plaintext: %s" % out)
        self._log("Matches stored plaintext: %s" % ("YES" if out == item["plaintext"] else "NO"))

    def on_attacker_decrypt(self) -> None:
        idx = self._selected_index()
        self._log("CLICK Attacker attempt decrypt")
        self._log("Plan:")
        self._log("  1) Attacker always knows the algorithm (Kerckhoffs assumption).")
        self._log("  2) If Kerckhoffs mode: attacker also needs key; only works if 'Key stolen' is ON.")
        self._log("  3) If Obscurity mode: attacker needs the hidden table; only works if 'Algorithm leaked' is ON.")
        self._log("  4) Show whether attacker can read current + past ciphertext.")

        if idx is None:
            self._log("No history item selected.")
            return

        item = self.history[idx]
        mode = item["mode"]
        try:
            blob = b64d(item["ciphertext_b64"])
        except Exception as e:
            self._log("Invalid base64 in history: %s" % str(e))
            return

        if mode.startswith("Kerckhoffs"):
            self._log("Attacker vs Kerckhoffs:")
            self._log("  - Algorithm known: yes.")
            self._log("  - Key stolen toggle: %s" % ("ON" if self.chk_key_stolen.isChecked() else "OFF"))
            if not self.chk_key_stolen.isChecked():
                self._log("Result: attacker FAILS (missing key). This is Kerckhoffs in action.")
                return
            key = self._key_bytes()
            try:
                pt = self.ker.decrypt(key, blob)
                out = pt.decode("utf-8", errors="replace")
            except Exception as e:
                self._log("Decrypt error: %s" % str(e))
                return
            self._log("Result: attacker SUCCESS (key stolen). Plaintext: %s" % out)
            return

        self._log("Attacker vs Obscurity:")
        self._log("  - There is no key.")
        self._log("  - Security depends on hiding the substitution table in the system.")
        self._log("  - Algorithm leaked toggle: %s" % ("ON" if self.chk_alg_leaked.isChecked() else "OFF"))
        if not self.chk_alg_leaked.isChecked():
            self._log("Result: attacker FAILS FOR NOW (table not leaked). But this is fragile.")
            self._log("Try turning 'Algorithm leaked' ON: then attacker can decrypt ALL past messages.")
            return

        leak = self.obsc.leak_algorithm_details()
        self._log("Simulating leak: attacker obtained substitution tables (perm+inv).")
        self._log(
            "Leaked metadata: perm_b64_len=%d inv_b64_len=%d"
            % (len(leak["perm_b64"]), len(leak["inv_b64"]))
        )

        pt = self.obsc.decrypt(blob)
        out = pt.decode("utf-8", errors="replace")
        self._log("Result: attacker SUCCESS. Plaintext: %s" % out)
        self._log("Now the key point: attacker can also decrypt ALL stored Obscurity ciphertext. Demonstrating...")

        count = 0
        for it in self.history:
            if not it["mode"].startswith("Obscurity"):
                continue
            try:
                b = b64d(it["ciphertext_b64"])
                p = self.obsc.decrypt(b).decode("utf-8", errors="replace")
                count += 1
                self._log("  past[%d] ts=%s plaintext=%s" % (count, it["ts"], p))
                if count >= 5:
                    self._log("  ... (showing first 5)")
                    break
            except Exception:
                pass

        if count == 0:
            self._log("  (no past obscurity messages found)")

        self._log("Conclusion: Obscurity breaks catastrophically when the algorithm/tables leak.")


def _load_qss() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "kh_style.qss")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    qss = _load_qss()
    if qss:
        app.setStyleSheet(qss)

    w = AppWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()