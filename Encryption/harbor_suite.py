# harbor_suite.py
from __future__ import annotations

import importlib
import importlib.util
import json
import queue
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

DEFAULT_SAMPLE_TEXT_PATH = Path("/Users/python/Pycharm Projects/Cybersecurity/sample_text.txt")


def _here() -> Path:
    return Path(__file__).resolve().parent


def _read_default_sample_text() -> str:
    try:
        if DEFAULT_SAMPLE_TEXT_PATH.exists():
            return DEFAULT_SAMPLE_TEXT_PATH.read_text(encoding="utf-8", errors="replace")
    except Exception:
        pass
    return "SAMPLE TEXT FILE NOT FOUND:\n" + str(DEFAULT_SAMPLE_TEXT_PATH) + "\n"


def _load_module(prefer_import: str, fallback_path: Path, alias: str):
    try:
        return importlib.import_module(prefer_import)
    except Exception:
        spec = importlib.util.spec_from_file_location(alias, str(fallback_path))
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Cannot load module: {prefer_import} from {fallback_path}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        return mod


def _load_deps():
    base = _here()

    ab_path = (base / "scripts" / "ab_send_messages.py") if (base / "scripts" / "ab_send_messages.py").exists() else (base / "ab_send_messages.py")
    fa_path = (base / "scripts" / "frequency_attack_analyzer.py") if (base / "scripts" / "frequency_attack_analyzer.py").exists() else (base / "frequency_attack_analyzer.py")
    mod_path = (base / "scripts" / "modification_attack_tool.py") if (base / "scripts" / "modification_attack_tool.py").exists() else (base / "modification_attack_tool.py")

    ab = _load_module("scripts.ab_send_messages", ab_path, "ab_send_messages")
    fa = _load_module("scripts.frequency_attack_analyzer", fa_path, "frequency_attack_analyzer")
    mm = _load_module("scripts.modification_attack_tool", mod_path, "modification_attack_tool")
    return ab, fa, mm


def _load_style(app) -> None:
    qss = _here() / "style.qss"
    if qss.exists():
        try:
            app.setStyleSheet(qss.read_text(encoding="utf-8"))
        except Exception:
            pass


@dataclass
class FieldWidget:
    ftype: str
    widget: Any


class ConfigPanel:
    def __init__(
        self,
        grid_layout,
        label_factory: Callable[[str], Any],
        make_input_str: Callable[[str], Any],
        make_input_int: Callable[[], Any],
    ):
        self._grid = grid_layout
        self._label_factory = label_factory
        self._make_input_str = make_input_str
        self._make_input_int = make_input_int
        self.widgets: Dict[str, FieldWidget] = {}

    def clear(self) -> None:
        while self._grid.count() > 0:
            item = self._grid.takeAt(0)
            w = item.widget()
            if w is not None:
                try:
                    w.deleteLater()
                except Exception:
                    pass
        self.widgets.clear()

    def build(self, config_fields) -> None:
        self.clear()
        row = 0
        for f in config_fields or []:
            key = str(f.get("key", "")).strip()
            if not key:
                continue
            label = str(f.get("label", key)).strip()
            ftype = str(f.get("type", "str")).strip()
            default = f.get("default")

            lbl = self._label_factory(label)

            if ftype == "int":
                w = self._make_input_int()
                try:
                    w.setRange(int(f.get("min", -10**9)), int(f.get("max", 10**9)))
                except Exception:
                    pass
                if default is not None:
                    try:
                        w.setValue(int(default))
                    except Exception:
                        pass
                self._grid.addWidget(lbl, row, 0)
                self._grid.addWidget(w, row, 1)
                self.widgets[key] = FieldWidget("int", w)
            else:
                w = self._make_input_str("" if default is None else str(default))
                self._grid.addWidget(lbl, row, 0)
                self._grid.addWidget(w, row, 1)
                self.widgets[key] = FieldWidget("str", w)
            row += 1

        if row == 0:
            lbl = self._label_factory("This plugin has no parameters.")
            try:
                lbl.setObjectName("Hint")
            except Exception:
                pass
            self._grid.addWidget(lbl, 0, 0, 1, 2)

    def read(self) -> Dict[str, Any]:
        cfg: Dict[str, Any] = {}
        for key, fw in self.widgets.items():
            if fw.ftype == "int":
                try:
                    cfg[key] = int(fw.widget.value())
                except Exception:
                    cfg[key] = 0
            else:
                try:
                    cfg[key] = str(fw.widget.text())
                except Exception:
                    cfg[key] = ""
        return cfg

    def fill_from_dict(self, values: Dict[str, Any]) -> None:
        if not isinstance(values, dict):
            return
        for key, fw in self.widgets.items():
            if key not in values:
                continue
            v = values[key]
            if fw.ftype == "int":
                try:
                    fw.widget.setValue(int(v))
                except Exception:
                    pass
            else:
                try:
                    fw.widget.setText("" if v is None else str(v))
                except Exception:
                    pass


def main() -> None:
    ab, fa, mm = _load_deps()

    from PySide6.QtCore import Qt, QTimer  # type: ignore
    from PySide6.QtGui import QFont  # type: ignore
    from PySide6.QtWidgets import (  # type: ignore
        QApplication,
        QCheckBox,
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QPushButton,
        QScrollArea,
        QSpinBox,
        QTabWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )

    def _mk_label(text: str) -> QLabel:
        lab = QLabel(text)
        lab.setObjectName("FieldLabel")
        return lab

    def _mk_lineedit(text: str) -> QLineEdit:
        le = QLineEdit(text)
        le.setObjectName("Input")
        return le

    def _mk_spinbox() -> QSpinBox:
        sp = QSpinBox()
        sp.setObjectName("Input")
        sp.setRange(-10**9, 10**9)
        return sp

    def _wrap_scroll(page: QWidget) -> QScrollArea:
        sa = QScrollArea()
        sa.setObjectName("PageScroll")
        sa.setWidgetResizable(True)
        sa.setFrameShape(QFrame.NoFrame)
        sa.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        sa.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        sa.setWidget(page)
        return sa

    class Card(QFrame):
        def __init__(self, title: str) -> None:
            super().__init__()
            self.setObjectName("Card")
            outer = QVBoxLayout(self)
            outer.setContentsMargins(14, 14, 14, 14)
            outer.setSpacing(10)
            t = QLabel(title)
            t.setObjectName("CardTitle")
            outer.addWidget(t)
            self.body = QVBoxLayout()
            self.body.setSpacing(10)
            outer.addLayout(self.body)

    class DefaultClearingTextEdit(QTextEdit):
        def __init__(self, default_text: str) -> None:
            super().__init__()
            self._default_text = default_text

        def mouseDoubleClickEvent(self, event) -> None:
            # Clear only when still equal to the shipped default text.
            try:
                if self.toPlainText() == self._default_text:
                    self.clear()
                    return
            except Exception:
                pass
            super().mouseDoubleClickEvent(event)

    class SendTab(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self.setObjectName("TabPage")
            self._q: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
            self._srv = None

            self._plugins = ab.load_encrypt_plugins()
            self._default_text = _read_default_sample_text()

            root = QHBoxLayout(self)
            root.setContentsMargins(0, 0, 0, 0)
            root.setSpacing(12)

            left = QVBoxLayout()
            left.setSpacing(12)

            conn = Card("Send A -> B (TCP)")
            grid = QGridLayout()
            grid.setHorizontalSpacing(10)
            grid.setVerticalSpacing(10)

            self.host_in = QLineEdit("127.0.0.1")
            self.host_in.setObjectName("Input")

            self.a_port = QSpinBox()
            self.a_port.setRange(1, 65535)
            self.a_port.setValue(6001)
            self.a_port.setObjectName("Input")

            self.b_port = QSpinBox()
            self.b_port.setRange(1, 65535)
            self.b_port.setValue(6002)
            self.b_port.setObjectName("Input")

            grid.addWidget(QLabel("Host"), 0, 0)
            grid.addWidget(self.host_in, 0, 1)
            grid.addWidget(QLabel("A source port"), 1, 0)
            grid.addWidget(self.a_port, 1, 1)
            grid.addWidget(QLabel("B listen port"), 2, 0)
            grid.addWidget(self.b_port, 2, 1)

            btnrow = QHBoxLayout()
            self.start_btn = QPushButton("Start B server")
            self.start_btn.setObjectName("PrimaryButton")
            self.stop_btn = QPushButton("Stop")
            self.stop_btn.setObjectName("GhostButton")
            btnrow.addWidget(self.start_btn)
            btnrow.addWidget(self.stop_btn)

            self.status = QLabel("B server: stopped")
            self.status.setObjectName("StatusPillBad")
            self.status.setAlignment(Qt.AlignCenter)

            conn.body.addLayout(grid)
            conn.body.addLayout(btnrow)
            conn.body.addWidget(self.status)
            left.addWidget(conn)

            compose = Card("Compose")
            self.plugin_list = QListWidget()
            self.plugin_list.setObjectName("List")
            for mid, pl in sorted(self._plugins.items(), key=lambda kv: kv[0]):
                it = QListWidgetItem(f"{pl.method_name} ({mid})")
                it.setData(Qt.UserRole, mid)
                self.plugin_list.addItem(it)

            compose.body.addWidget(QLabel("Encryption plugins (encryption_methods)"))
            compose.body.addWidget(self.plugin_list, 2)

            cfg_wrap = QFrame()
            cfg_wrap.setObjectName("ConfigPanel")
            cfg_layout = QVBoxLayout(cfg_wrap)
            cfg_layout.setContentsMargins(12, 12, 12, 12)
            self.cfg_grid = QGridLayout()
            self.cfg_grid.setHorizontalSpacing(10)
            self.cfg_grid.setVerticalSpacing(10)
            cfg_layout.addLayout(self.cfg_grid)

            cfg_scroll = QScrollArea()
            cfg_scroll.setObjectName("ScrollArea")
            cfg_scroll.setWidgetResizable(True)
            cfg_scroll.setWidget(cfg_wrap)
            cfg_scroll.setMinimumHeight(170)

            self.cfg_panel = ConfigPanel(
                self.cfg_grid,
                label_factory=_mk_label,
                make_input_str=_mk_lineedit,
                make_input_int=_mk_spinbox,
            )

            compose.body.addWidget(QLabel("Config"))
            compose.body.addWidget(cfg_scroll)

            self.include_debug = QCheckBox("Include debug_plaintext in record")
            self.include_debug.setObjectName("Check")
            compose.body.addWidget(self.include_debug)

            self.plain = DefaultClearingTextEdit(self._default_text)
            self.plain.setObjectName("TextArea")
            self.plain.setMinimumHeight(130)
            self.plain.setPlainText(self._default_text)
            compose.body.addWidget(QLabel(f"Plaintext (double-click to clear default: {str(DEFAULT_SAMPLE_TEXT_PATH)})"))
            compose.body.addWidget(self.plain)

            sendrow = QHBoxLayout()
            self.send_btn = QPushButton("Send")
            self.send_btn.setObjectName("PrimaryButton")
            self.reload_plugins_btn = QPushButton("Reload plugins")
            self.reload_plugins_btn.setObjectName("GhostButton")
            sendrow.addWidget(self.send_btn)
            sendrow.addWidget(self.reload_plugins_btn)
            compose.body.addLayout(sendrow)

            left.addWidget(compose, 1)
            root.addLayout(left, 2)

            right = QVBoxLayout()
            right.setSpacing(12)

            inbox = Card("Inbox at B")
            self.inbox = QListWidget()
            self.inbox.setObjectName("List")
            inbox.body.addWidget(self.inbox)
            right.addWidget(inbox, 2)

            details = Card("Selected")
            self.details = QTextEdit()
            self.details.setObjectName("TextArea")
            self.details.setReadOnly(True)
            details.body.addWidget(self.details)
            right.addWidget(details, 2)

            logc = Card("Log")
            self.log = QTextEdit()
            self.log.setObjectName("LogArea")
            self.log.setReadOnly(True)
            logc.body.addWidget(self.log)
            right.addWidget(logc, 1)

            root.addLayout(right, 3)

            self.plugin_list.currentRowChanged.connect(self._on_plugin_selected)
            self.inbox.currentRowChanged.connect(self._on_inbox_selected)
            self.start_btn.clicked.connect(self._start_server)
            self.stop_btn.clicked.connect(self._stop_server)
            self.send_btn.clicked.connect(self._send)
            self.reload_plugins_btn.clicked.connect(self._reload_plugins)

            self._timer = QTimer(self)
            self._timer.timeout.connect(self._poll_q)
            self._timer.start(100)

            if self.plugin_list.count() > 0:
                self.plugin_list.setCurrentRow(0)

        def _log(self, s: str) -> None:
            self.log.append(s)

        def _set_status(self, running: bool) -> None:
            if running:
                self.status.setText("B server: running")
                self.status.setObjectName("StatusPillOk")
            else:
                self.status.setText("B server: stopped")
                self.status.setObjectName("StatusPillBad")
            self.status.style().unpolish(self.status)
            self.status.style().polish(self.status)

        def _poll_q(self) -> None:
            while True:
                try:
                    kind, payload = self._q.get_nowait()
                except queue.Empty:
                    break
                if kind == "status":
                    self._log(str(payload))
                    t = str(payload).lower()
                    if "starting" in t:
                        self._set_status(True)
                    if "stopped" in t:
                        self._set_status(False)
                elif kind == "msg":
                    obj, addr = payload
                    try:
                        ab.append_message_store(obj)
                    except Exception as e:
                        self._log(f"store failed: {e}")
                    it = QListWidgetItem(f"{obj.get('id')} [{obj.get('method_id')}] from {addr[0]}:{addr[1]}")
                    it.setData(Qt.UserRole, obj)
                    self.inbox.addItem(it)
                    self.inbox.setCurrentRow(self.inbox.count() - 1)

        def _on_server_msg(self, obj: Dict[str, Any], addr: Tuple[str, int]) -> None:
            self._q.put(("msg", (obj, addr)))

        def _on_server_status(self, s: str) -> None:
            self._q.put(("status", s))

        def _start_server(self) -> None:
            port = int(self.b_port.value())
            try:
                self._srv = ab.TcpJsonLineServer("0.0.0.0", port, self._on_server_msg, self._on_server_status)
                self._srv.start()
            except Exception as e:
                self._log(f"server start failed: {e}")
                self._set_status(False)

        def _stop_server(self) -> None:
            try:
                if self._srv:
                    self._srv.stop()
            except Exception:
                pass
            self._srv = None
            self._set_status(False)

        def _reload_plugins(self) -> None:
            try:
                self._plugins = ab.load_encrypt_plugins()
            except Exception as e:
                self._log(f"reload plugins failed: {e}")
                return
            self.plugin_list.clear()
            for mid, pl in sorted(self._plugins.items(), key=lambda kv: kv[0]):
                it = QListWidgetItem(f"{pl.method_name} ({mid})")
                it.setData(Qt.UserRole, mid)
                self.plugin_list.addItem(it)
            if self.plugin_list.count() > 0:
                self.plugin_list.setCurrentRow(0)
            self._log(f"loaded {len(self._plugins)} encryption plugins")

        def _selected_plugin_id(self) -> Optional[str]:
            i = self.plugin_list.currentRow()
            if i < 0:
                return None
            mid = self.plugin_list.item(i).data(Qt.UserRole)
            return str(mid) if mid is not None else None

        def _on_plugin_selected(self) -> None:
            mid = self._selected_plugin_id()
            if not mid or mid not in self._plugins:
                return
            pl = self._plugins[mid]
            self.cfg_panel.build(pl.config_fields)

        def _on_inbox_selected(self) -> None:
            i = self.inbox.currentRow()
            if i < 0:
                return
            obj = self.inbox.item(i).data(Qt.UserRole)
            if not isinstance(obj, dict):
                return
            self.details.setPlainText(json.dumps(obj, ensure_ascii=True, indent=2))

        def _send(self) -> None:
            mid = self._selected_plugin_id()
            if not mid or mid not in self._plugins:
                self._log("no plugin selected")
                return
            pl = self._plugins[mid]

            host = str(self.host_in.text()).strip()
            a_port = int(self.a_port.value())
            b_port = int(self.b_port.value())
            if a_port == b_port:
                self._log("ERROR: A source port and B listen port must be different")
                return

            pt = ab.normalize_ascii_upper(self.plain.toPlainText())
            if not pt.strip():
                self._log("empty plaintext")
                return

            cfg = self.cfg_panel.read()
            try:
                ct = str(pl.encrypt_fn(pt, cfg))
            except Exception as e:
                self._log(f"encrypt failed: {e}")
                return

            rec: Dict[str, Any] = {
                "id": ab.make_msg_id(),
                "ts_utc": ab.now_utc_iso(),
                "from": "A",
                "to": "B",
                "method_id": pl.method_id,
                "method_name": pl.method_name,
                "config": cfg,
                "ciphertext": ct,
            }
            if self.include_debug.isChecked():
                rec["debug_plaintext"] = pt

            ok, msg = ab.tcp_send_json_line(host, b_port, a_port, rec)
            self._log(f"SEND A:{a_port} -> B:{b_port} ok={ok} ({msg}) id={rec['id']}")

    class FrequencyTab(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self.setObjectName("TabPage")
            self._plugins: Dict[str, Any] = {}
            self._records: list[dict] = []
            self._work_q: "queue.Queue[Tuple[str, Any]]" = queue.Queue()

            root = QHBoxLayout(self)
            root.setContentsMargins(0, 0, 0, 0)
            root.setSpacing(12)

            left = QVBoxLayout()
            left.setSpacing(12)

            rec = Card("Records")
            self.rec_list = QListWidget()
            self.rec_list.setObjectName("List")
            rec.body.addWidget(self.rec_list)

            btns = QHBoxLayout()
            self.reload_records = QPushButton("Reload records")
            self.reload_records.setObjectName("PrimaryButton")
            self.reload_plugins = QPushButton("Reload plugins")
            self.reload_plugins.setObjectName("GhostButton")
            btns.addWidget(self.reload_records)
            btns.addWidget(self.reload_plugins)
            rec.body.addLayout(btns)

            left.addWidget(rec, 2)

            actions = Card("Quick actions")
            self.use_record_cfg = QCheckBox("Use record config (recommended)")
            self.use_record_cfg.setChecked(True)
            self.use_record_cfg.setObjectName("Check")

            self.freq_sel = QPushButton("Frequency (selected)")
            self.freq_sel.setObjectName("GhostButton")
            self.freq_all = QPushButton("Frequency (all)")
            self.freq_all.setObjectName("GhostButton")
            self.crack_caesar = QPushButton("Crack Caesar (selected)")
            self.crack_caesar.setObjectName("GhostButton")
            self.crack_subst = QPushButton("Crack Substitution (method)")
            self.crack_subst.setObjectName("GhostButton")

            actions.body.addWidget(self.use_record_cfg)
            actions.body.addWidget(self.freq_sel)
            actions.body.addWidget(self.freq_all)
            actions.body.addWidget(self.crack_caesar)
            actions.body.addWidget(self.crack_subst)

            left.addWidget(actions, 1)
            root.addLayout(left, 2)

            center = QVBoxLayout()
            center.setSpacing(12)

            viewer = Card("Viewer")
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
            viewer.body.addWidget(self.tabs)

            center.addWidget(viewer, 1)
            root.addLayout(center, 4)

            right = QVBoxLayout()
            right.setSpacing(12)

            plug = Card("Decrypt plugins")
            self.plugin_list = QListWidget()
            self.plugin_list.setObjectName("List")
            plug.body.addWidget(self.plugin_list, 2)

            cfg_wrap = QFrame()
            cfg_wrap.setObjectName("ConfigPanel")
            cfg_layout = QVBoxLayout(cfg_wrap)
            cfg_layout.setContentsMargins(12, 12, 12, 12)
            self.cfg_grid = QGridLayout()
            self.cfg_grid.setHorizontalSpacing(10)
            self.cfg_grid.setVerticalSpacing(10)
            cfg_layout.addLayout(self.cfg_grid)

            cfg_scroll = QScrollArea()
            cfg_scroll.setObjectName("ScrollArea")
            cfg_scroll.setWidgetResizable(True)
            cfg_scroll.setWidget(cfg_wrap)
            cfg_scroll.setMinimumHeight(190)

            self.cfg_panel = ConfigPanel(
                self.cfg_grid,
                label_factory=_mk_label,
                make_input_str=_mk_lineedit,
                make_input_int=_mk_spinbox,
            )

            plug.body.addWidget(QLabel("Config"))
            plug.body.addWidget(cfg_scroll)

            runrow = QHBoxLayout()
            self.auto_pick = QPushButton("Auto-pick")
            self.auto_pick.setObjectName("GhostButton")
            self.decrypt_btn = QPushButton("Decrypt")
            self.decrypt_btn.setObjectName("PrimaryButton")
            runrow.addWidget(self.auto_pick)
            runrow.addWidget(self.decrypt_btn)
            plug.body.addLayout(runrow)

            right.addWidget(plug, 1)
            root.addLayout(right, 3)

            self.reload_records.clicked.connect(self._reload_records)
            self.reload_plugins.clicked.connect(self._reload_plugins)
            self.rec_list.currentRowChanged.connect(self._on_record_selected)
            self.plugin_list.currentRowChanged.connect(self._on_plugin_selected)

            self.auto_pick.clicked.connect(self._auto_pick)
            self.decrypt_btn.clicked.connect(self._decrypt)

            self.freq_sel.clicked.connect(self._freq_selected)
            self.freq_all.clicked.connect(self._freq_all)
            self.crack_caesar.clicked.connect(self._crack_caesar_selected)
            self.crack_subst.clicked.connect(self._crack_subst_method)

            self._timer = QTimer(self)
            self._timer.timeout.connect(self._poll_work)
            self._timer.start(120)

            self._reload_plugins()
            self._reload_records()

        def _poll_work(self) -> None:
            while True:
                try:
                    kind, payload = self._work_q.get_nowait()
                except queue.Empty:
                    break
                if kind == "analysis":
                    self.analysis_view.append(str(payload))
                    self.tabs.setCurrentWidget(self.analysis_view)

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
            mid = self.plugin_list.item(i).data(Qt.UserRole)
            return str(mid) if mid is not None else None

        def _reload_records(self) -> None:
            try:
                self._records = fa.load_records()
            except Exception as e:
                self.analysis_view.append(f"load records failed: {e}")
                return
            self.rec_list.clear()
            for r in self._records:
                rid = str(r.get("id", ""))
                mid = str(r.get("method_id", ""))
                ts = str(r.get("ts_utc", ""))
                it = QListWidgetItem(f"{rid}  [{mid}]  {ts}")
                it.setData(Qt.UserRole, r)
                self.rec_list.addItem(it)
            self.analysis_view.append(f"loaded {len(self._records)} records")
            if self.rec_list.count() > 0 and self.rec_list.currentRow() < 0:
                self.rec_list.setCurrentRow(self.rec_list.count() - 1)

        def _reload_plugins(self) -> None:
            try:
                self._plugins = fa.load_decrypt_plugins()
            except Exception as e:
                self.analysis_view.append(f"load plugins failed: {e}")
                return
            self.plugin_list.clear()
            for mid, pl in sorted(self._plugins.items(), key=lambda kv: kv[0]):
                it = QListWidgetItem(f"{pl.method_name} ({mid})")
                it.setData(Qt.UserRole, mid)
                self.plugin_list.addItem(it)
            self.analysis_view.append(f"loaded {len(self._plugins)} decrypt plugins")
            if self.plugin_list.count() > 0 and self.plugin_list.currentRow() < 0:
                self.plugin_list.setCurrentRow(0)

        def _on_record_selected(self) -> None:
            r = self._selected_record()
            if not r:
                return
            meta = dict(r)
            ct = str(meta.pop("ciphertext", ""))
            self.cipher_view.setPlainText(json.dumps(meta, ensure_ascii=True, indent=2) + "\n\n" + ct)
            self.tabs.setCurrentWidget(self.cipher_view)
            self._auto_pick()

        def _on_plugin_selected(self) -> None:
            pid = self._selected_plugin_id()
            if not pid or pid not in self._plugins:
                return
            pl = self._plugins[pid]
            self.cfg_panel.build(pl.config_fields)
            if self.use_record_cfg.isChecked():
                r = self._selected_record()
                if r and isinstance(r.get("config", {}), dict):
                    self.cfg_panel.fill_from_dict(r.get("config", {}))

        def _auto_pick(self) -> None:
            r = self._selected_record()
            if not r:
                return
            want = str(r.get("method_id", "")).strip()
            if not want:
                return
            for i in range(self.plugin_list.count()):
                if str(self.plugin_list.item(i).data(Qt.UserRole)) == want:
                    self.plugin_list.setCurrentRow(i)
                    self.analysis_view.append(f"auto-picked plugin: {want}")
                    return
            self.analysis_view.append(f"no decrypt plugin for method_id: {want}")

        def _decrypt(self) -> None:
            r = self._selected_record()
            pid = self._selected_plugin_id()
            if not r or not pid or pid not in self._plugins:
                self.analysis_view.append("select a record and a decrypt plugin")
                self.tabs.setCurrentWidget(self.analysis_view)
                return
            pl = self._plugins[pid]
            ct = str(r.get("ciphertext", ""))

            cfg = self.cfg_panel.read()
            if self.use_record_cfg.isChecked() and isinstance(r.get("config", {}), dict):
                merged = dict(r.get("config", {}))
                merged.update(cfg)
                cfg = merged

            try:
                pt = str(pl.decrypt_fn(ct, cfg))
            except Exception as e:
                self.analysis_view.append(f"decrypt failed: {e}")
                self.tabs.setCurrentWidget(self.analysis_view)
                return

            head = f"plugin={pl.method_name} ({pl.method_id})\nconfig={json.dumps(cfg, ensure_ascii=True)}\n\n"
            self.plain_view.setPlainText(head + pt)
            self.tabs.setCurrentWidget(self.plain_view)

        def _freq_selected(self) -> None:
            r = self._selected_record()
            if not r:
                return
            ct = str(r.get("ciphertext", ""))
            counts, total = fa.letter_counts(ct)
            s = ", ".join(f"{c}:{n}" for c, n in fa.top_letters(counts, 12))
            self.analysis_view.append(f"[frequency selected] {s} | TOTAL={total}")
            self.tabs.setCurrentWidget(self.analysis_view)

        def _freq_all(self) -> None:
            all_ct = "\n".join(str(x.get("ciphertext", "")) for x in self._records)
            counts, total = fa.letter_counts(all_ct)
            s = ", ".join(f"{c}:{n}" for c, n in fa.top_letters(counts, 12))
            self.analysis_view.append(f"[frequency all] {s} | TOTAL={total}")
            self.tabs.setCurrentWidget(self.analysis_view)

        def _crack_caesar_selected(self) -> None:
            r = self._selected_record()
            if not r:
                return
            ct = str(r.get("ciphertext", ""))
            shift, pt, score = fa.crack_caesar(ct)
            self.analysis_view.append(f"[crack caesar] best_shift={shift} score={score:.2f}\n{pt[:1400]}")
            self.tabs.setCurrentWidget(self.analysis_view)

        def _crack_subst_method(self) -> None:
            r = self._selected_record()
            if not r:
                return
            mid = str(r.get("method_id", ""))
            agg = "\n".join(str(x.get("ciphertext", "")) for x in self._records if str(x.get("method_id", "")) == mid)
            if not agg.strip():
                self.analysis_view.append("[crack substitution] nothing to crack")
                self.tabs.setCurrentWidget(self.analysis_view)
                return

            self.analysis_view.append(f"[crack substitution] running for method_id={mid} ...")
            self.tabs.setCurrentWidget(self.analysis_view)

            def worker() -> None:
                try:
                    key_map, pt, score = fa.crack_substitution(agg)
                    mapping = " ".join(f"{fa.ALPHABET[i]}->{chr(fa.A_ORD + key_map[i])}" for i in range(26))
                    out = f"[crack substitution] score={score:.2f}\n{mapping}\n\n{pt[:1600]}"
                except Exception as e:
                    out = f"[crack substitution] failed: {e}"
                self._work_q.put(("analysis", out))

            threading.Thread(target=worker, daemon=True).start()

    class ModificationTab(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self.setObjectName("TabPage")
            self._plugins: Dict[str, Any] = {}
            self._records: list[dict] = []
            self._last_preview: Optional[Dict[str, Any]] = None
            self._log_q: "queue.Queue[str]" = queue.Queue()

            root = QHBoxLayout(self)
            root.setContentsMargins(0, 0, 0, 0)
            root.setSpacing(12)

            left = QVBoxLayout()
            left.setSpacing(12)

            rec = Card("Records")
            self.rec_list = QListWidget()
            self.rec_list.setObjectName("List")
            rec.body.addWidget(self.rec_list)

            btns = QHBoxLayout()
            self.reload_records = QPushButton("Reload records")
            self.reload_records.setObjectName("PrimaryButton")
            self.reload_mods = QPushButton("Reload modifiers")
            self.reload_mods.setObjectName("GhostButton")
            btns.addWidget(self.reload_records)
            btns.addWidget(self.reload_mods)
            rec.body.addLayout(btns)

            left.addWidget(rec, 2)
            root.addLayout(left, 2)

            center = QVBoxLayout()
            center.setSpacing(12)

            viewer = Card("Viewer")
            self.tabs = QTabWidget()
            self.tabs.setObjectName("Tabs")

            self.orig_view = QTextEdit()
            self.orig_view.setObjectName("TextArea")
            self.orig_view.setReadOnly(True)

            self.tamp_view = QTextEdit()
            self.tamp_view.setObjectName("TextArea")
            self.tamp_view.setReadOnly(True)

            self.log_view = QTextEdit()
            self.log_view.setObjectName("LogArea")
            self.log_view.setReadOnly(True)

            self.tabs.addTab(self.orig_view, "Original")
            self.tabs.addTab(self.tamp_view, "Tampered")
            self.tabs.addTab(self.log_view, "Log")
            viewer.body.addWidget(self.tabs)

            center.addWidget(viewer, 1)
            root.addLayout(center, 4)

            right = QVBoxLayout()
            right.setSpacing(12)

            mods = Card("Modification methods")
            self.mod_list = QListWidget()
            self.mod_list.setObjectName("List")
            mods.body.addWidget(self.mod_list, 2)

            cfg_wrap = QFrame()
            cfg_wrap.setObjectName("ConfigPanel")
            cfg_layout = QVBoxLayout(cfg_wrap)
            cfg_layout.setContentsMargins(12, 12, 12, 12)
            self.cfg_grid = QGridLayout()
            self.cfg_grid.setHorizontalSpacing(10)
            self.cfg_grid.setVerticalSpacing(10)
            cfg_layout.addLayout(self.cfg_grid)

            cfg_scroll = QScrollArea()
            cfg_scroll.setObjectName("ScrollArea")
            cfg_scroll.setWidgetResizable(True)
            cfg_scroll.setWidget(cfg_wrap)
            cfg_scroll.setMinimumHeight(190)

            self.cfg_panel = ConfigPanel(
                self.cfg_grid,
                label_factory=_mk_label,
                make_input_str=_mk_lineedit,
                make_input_int=_mk_spinbox,
            )

            mods.body.addWidget(QLabel("Config"))
            mods.body.addWidget(cfg_scroll)

            meta = QGridLayout()
            self.from_in = QLineEdit("M")
            self.from_in.setObjectName("Input")
            self.to_in = QLineEdit("B")
            self.to_in.setObjectName("Input")
            meta.addWidget(QLabel("Store as sender"), 0, 0)
            meta.addWidget(self.from_in, 0, 1)
            meta.addWidget(QLabel("Store as recipient"), 1, 0)
            meta.addWidget(self.to_in, 1, 1)
            mods.body.addLayout(meta)

            run = QHBoxLayout()
            self.preview = QPushButton("Preview")
            self.preview.setObjectName("PrimaryButton")
            self.store = QPushButton("Store tampered")
            self.store.setObjectName("GhostButton")
            run.addWidget(self.preview)
            run.addWidget(self.store)
            mods.body.addLayout(run)

            right.addWidget(mods, 1)
            root.addLayout(right, 3)

            self.reload_records.clicked.connect(self._reload_records)
            self.reload_mods.clicked.connect(self._reload_mods)
            self.rec_list.currentRowChanged.connect(self._on_record_selected)
            self.mod_list.currentRowChanged.connect(self._on_mod_selected)
            self.preview.clicked.connect(self._preview)
            self.store.clicked.connect(self._store)

            self._timer = QTimer(self)
            self._timer.timeout.connect(self._poll_log)
            self._timer.start(120)

            self._reload_mods()
            self._reload_records()

        def _poll_log(self) -> None:
            while True:
                try:
                    s = self._log_q.get_nowait()
                except queue.Empty:
                    break
                self.log_view.append(s)

        def _log(self, s: str) -> None:
            self._log_q.put(s)
            self.tabs.setCurrentWidget(self.log_view)

        def _selected_record(self) -> Optional[Dict[str, Any]]:
            i = self.rec_list.currentRow()
            if i < 0:
                return None
            r = self.rec_list.item(i).data(Qt.UserRole)
            return r if isinstance(r, dict) else None

        def _selected_mod_id(self) -> Optional[str]:
            i = self.mod_list.currentRow()
            if i < 0:
                return None
            mid = self.mod_list.item(i).data(Qt.UserRole)
            return str(mid) if mid is not None else None

        def _reload_records(self) -> None:
            try:
                self._records = mm.load_records()
            except Exception as e:
                self._log(f"load records failed: {e}")
                return
            self.rec_list.clear()
            for r in self._records:
                rid = str(r.get("id", ""))
                mid = str(r.get("method_id", ""))
                ts = str(r.get("ts_utc", ""))
                it = QListWidgetItem(f"{rid}  [{mid}]  {ts}")
                it.setData(Qt.UserRole, r)
                self.rec_list.addItem(it)
            self._log(f"loaded {len(self._records)} records")
            if self.rec_list.count() > 0 and self.rec_list.currentRow() < 0:
                self.rec_list.setCurrentRow(self.rec_list.count() - 1)

        def _reload_mods(self) -> None:
            try:
                self._plugins = mm.load_mod_plugins()
            except Exception as e:
                self._log(f"load modifiers failed: {e}")
                return
            self.mod_list.clear()
            for mid, pl in sorted(self._plugins.items(), key=lambda kv: kv[0]):
                it = QListWidgetItem(f"{pl.method_name} ({mid})")
                it.setData(Qt.UserRole, mid)
                self.mod_list.addItem(it)
            self._log(f"loaded {len(self._plugins)} modifiers")
            if self.mod_list.count() > 0 and self.mod_list.currentRow() < 0:
                self.mod_list.setCurrentRow(0)

        def _on_record_selected(self) -> None:
            r = self._selected_record()
            if not r:
                return
            meta = dict(r)
            ct = str(meta.pop("ciphertext", ""))
            self.orig_view.setPlainText(json.dumps(meta, ensure_ascii=True, indent=2) + "\n\n" + ct)
            self.tabs.setCurrentWidget(self.orig_view)
            self._last_preview = None
            self.tamp_view.setPlainText("")

        def _on_mod_selected(self) -> None:
            mid = self._selected_mod_id()
            if not mid or mid not in self._plugins:
                return
            pl = self._plugins[mid]
            self.cfg_panel.build(pl.config_fields)

        def _preview(self) -> None:
            r = self._selected_record()
            mid = self._selected_mod_id()
            if not r or not mid or mid not in self._plugins:
                self._log("select a record and a modifier")
                return
            pl = self._plugins[mid]
            cfg = self.cfg_panel.read()
            try:
                out = pl.modify_fn(dict(r), cfg)
            except Exception as e:
                self._log(f"modify failed: {e}")
                return
            if not isinstance(out, dict):
                self._log("modifier returned non-dict")
                return
            self._last_preview = out
            meta = dict(out)
            ct = str(meta.pop("ciphertext", ""))
            self.tamp_view.setPlainText(json.dumps(meta, ensure_ascii=True, indent=2) + "\n\n" + ct)
            self.tabs.setCurrentWidget(self.tamp_view)
            self._log(f"preview ready: {mid}")

        def _store(self) -> None:
            if not self._last_preview:
                self._log("nothing to store (preview first)")
                return
            out = dict(self._last_preview)
            out["id"] = mm.make_id("tamper")
            out["ts_utc"] = mm.now_utc_iso()
            out["from"] = str(self.from_in.text()).strip() or "M"
            out["to"] = str(self.to_in.text()).strip() or "B"
            if not isinstance(out.get("config", {}), dict):
                out["config"] = {}
            try:
                mm.store_record(out)
            except Exception as e:
                self._log(f"store failed: {e}")
                return
            self._log(f"stored tampered record id={out['id']}")
            self._reload_records()

    class Suite(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self.setObjectName("AppWindow")
            self.setWindowTitle("Galactic Crypt Lab")

            root = QVBoxLayout(self)
            root.setContentsMargins(16, 16, 16, 16)
            root.setSpacing(12)

            header = QFrame()
            header.setObjectName("HeaderBar")
            h = QHBoxLayout(header)
            h.setContentsMargins(16, 14, 16, 14)

            tcol = QVBoxLayout()
            title = QLabel("Galactic Crypt Lab")
            title.setObjectName("AppTitle")
            subtitle = QLabel("Send, analyze, and tamper with messages.")
            subtitle.setObjectName("AppSubtitle")
            tcol.addWidget(title)
            tcol.addWidget(subtitle)
            h.addLayout(tcol, 1)

            hint = QLabel("encryption_methods / decryption_methods / modification_methods")
            hint.setObjectName("Hint")
            h.addWidget(hint)
            root.addWidget(header)

            self.tabs = QTabWidget()
            self.tabs.setObjectName("Tabs")
            self.tabs.addTab(_wrap_scroll(SendTab()), "Send")
            self.tabs.addTab(_wrap_scroll(FrequencyTab()), "Frequency attack")
            self.tabs.addTab(_wrap_scroll(ModificationTab()), "Modification")
            root.addWidget(self.tabs, 1)

    app = QApplication([])
    app.setApplicationName("Galactic Crypt Lab")
    f = QFont()
    f.setPointSize(10)
    app.setFont(f)

    _load_style(app)

    w = Suite()

    screen = app.primaryScreen()
    if screen is not None:
        geo = screen.availableGeometry()
        max_w = max(640, int(geo.width()))
        max_h = max(480, int(geo.height()))
        w.setMaximumSize(max_w, max_h)

        target_w = max(880, min(1400, max_w - 40))
        target_h = max(620, min(860, max_h - 40))
        w.resize(target_w, target_h)

        try:
            x = int(geo.x() + (max_w - target_w) / 2)
            y = int(geo.y() + (max_h - target_h) / 2)
            w.move(x, y)
        except Exception:
            pass
    else:
        w.resize(1200, 800)

    w.show()
    app.exec()


if __name__ == "__main__":
    main()