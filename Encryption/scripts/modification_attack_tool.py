# scripts/modification_attack_tool.py
from __future__ import annotations

import json
import queue
import random
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


def project_root() -> Path:
    hard = Path("/Users/python/Pycharm Projects/Cybersecurity/Encryption")
    if hard.exists():
        return hard
    return Path(__file__).resolve().parents[1]


def styles_qss_path() -> Path:
    return project_root() / "styles" / "ab_style.qss"


def modification_plugin_dir() -> Path:
    root = project_root()
    p = root / "modification_methods"
    p.mkdir(parents=True, exist_ok=True)
    return p


def data_dir() -> Path:
    d = project_root() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def channel_sqlite_path() -> Path:
    return data_dir() / "ab_channel.db"


def channel_jsonl_path() -> Path:
    return data_dir() / "ab_channel.jsonl"


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_id(prefix: str) -> str:
    return f"{prefix}-{int(time.time() * 1000)}-{random.randint(1000, 9999)}"


def ensure_sqlite_schema(db_path: Path) -> None:
    con = sqlite3.connect(str(db_path))
    try:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                ts_utc TEXT NOT NULL,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                method_id TEXT NOT NULL,
                method_name TEXT NOT NULL,
                config_json TEXT NOT NULL,
                ciphertext TEXT NOT NULL
            )
            """
        )
        con.commit()
    finally:
        con.close()


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
                    "config": cfg if isinstance(cfg, dict) else {},
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
                    if not isinstance(obj.get("config", {}), dict):
                        obj["config"] = {}
                    out2.append(obj)
            except Exception:
                continue
    return out2


def store_record(record: Dict[str, Any]) -> None:
    # JSONL append (best-effort)
    try:
        with channel_jsonl_path().open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=True) + "\n")
    except Exception:
        pass

    # SQLite upsert
    dbp = channel_sqlite_path()
    ensure_sqlite_schema(dbp)
    con = sqlite3.connect(str(dbp))
    try:
        con.execute(
            """
            INSERT OR REPLACE INTO messages
            (id, ts_utc, sender, recipient, method_id, method_name, config_json, ciphertext)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(record.get("id", "")),
                str(record.get("ts_utc", "")),
                str(record.get("from", "")),
                str(record.get("to", "")),
                str(record.get("method_id", "")),
                str(record.get("method_name", "")),
                json.dumps(record.get("config", {}), ensure_ascii=True),
                str(record.get("ciphertext", "")),
            ),
        )
        con.commit()
    finally:
        con.close()


@dataclass(frozen=True)
class ModPlugin:
    method_id: str
    method_name: str
    config_fields: List[Dict[str, Any]]
    modify_fn: Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]]


def load_mod_plugin_file(path: Path) -> ModPlugin:
    import importlib.util

    mod_name = f"mod_{path.stem}_{abs(hash(str(path)))}"
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load plugin spec")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore

    method_id = str(getattr(mod, "METHOD_ID", "")).strip()
    method_name = str(getattr(mod, "METHOD_NAME", "")).strip()
    config_fields = getattr(mod, "CONFIG_FIELDS", [])
    modify_fn = getattr(mod, "modify", None)

    if not method_id or not method_name or not isinstance(config_fields, list) or not callable(modify_fn):
        raise RuntimeError("Invalid plugin interface")

    return ModPlugin(
        method_id=method_id,
        method_name=method_name,
        config_fields=list(config_fields),
        modify_fn=modify_fn,
    )


def load_mod_plugins() -> Dict[str, ModPlugin]:
    plugins: Dict[str, ModPlugin] = {}
    plug_dir = modification_plugin_dir()
    for p in sorted(plug_dir.glob("*.py")):
        if p.name.startswith("_"):
            continue
        try:
            pl = load_mod_plugin_file(p)
            plugins[pl.method_id] = pl
        except Exception:
            continue
    return plugins


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
            self.setWindowTitle("HarborModify - tamper with messages (modification attack)")

            self.plugins: Dict[str, ModPlugin] = {}
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
            title = QLabel("HarborModify")
            title.setObjectName("AppTitle")
            subtitle = QLabel("Modification attacks: tamper ciphertext / metadata (integrity)")
            subtitle.setObjectName("AppSubtitle")
            tcol.addWidget(title)
            tcol.addWidget(subtitle)
            h.addLayout(tcol, 1)

            hint = QLabel(f"Root: {str(project_root())} | Mods: {str(modification_plugin_dir())}")
            hint.setObjectName("Hint")
            h.addWidget(hint)

            root.addWidget(header)

            topbar = QHBoxLayout()
            topbar.setSpacing(10)
            self.reload_records_btn = QPushButton("Reload records")
            self.reload_records_btn.setObjectName("PrimaryButton")
            self.reload_plugins_btn = QPushButton("Reload modifiers")
            self.reload_plugins_btn.setObjectName("GhostButton")
            topbar.addWidget(self.reload_records_btn)
            topbar.addWidget(self.reload_plugins_btn)
            topbar.addStretch(1)
            root.addLayout(topbar)

            body = QHBoxLayout()
            body.setSpacing(12)

            rec_card = Card("Records")
            self.rec_list = QListWidget()
            self.rec_list.setObjectName("List")
            rec_card.body.addWidget(self.rec_list)
            body.addWidget(rec_card, 2)

            view_card = Card("Viewer")
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
            self.tabs.addTab(self.tamp_view, "Tampered preview")
            self.tabs.addTab(self.log_view, "Log")
            view_card.body.addWidget(self.tabs)
            body.addWidget(view_card, 4)

            mod_card = Card("Modification methods")
            self.mod_list = QListWidget()
            self.mod_list.setObjectName("List")
            self.mod_list.setMinimumWidth(380)
            mod_card.body.addWidget(QLabel("Loaded from modification_methods/*.py"))
            mod_card.body.addWidget(self.mod_list, 2)

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
            cfg_scroll.setMinimumHeight(180)

            mod_card.body.addWidget(QLabel("Modifier config:"))
            mod_card.body.addWidget(cfg_scroll)

            run_row = QHBoxLayout()
            self.preview_btn = QPushButton("Preview modify")
            self.preview_btn.setObjectName("PrimaryButton")
            self.store_btn = QPushButton("Store tampered record")
            self.store_btn.setObjectName("GhostButton")
            run_row.addWidget(self.preview_btn)
            run_row.addWidget(self.store_btn)
            mod_card.body.addLayout(run_row)

            self.attacker_from = QLineEdit("M")
            self.attacker_from.setObjectName("Input")
            self.attacker_to = QLineEdit("B")
            self.attacker_to.setObjectName("Input")

            meta_grid = QGridLayout()
            meta_grid.setHorizontalSpacing(10)
            meta_grid.setVerticalSpacing(10)
            meta_grid.addWidget(QLabel("Store as sender"), 0, 0)
            meta_grid.addWidget(self.attacker_from, 0, 1)
            meta_grid.addWidget(QLabel("Store as recipient"), 1, 0)
            meta_grid.addWidget(self.attacker_to, 1, 1)
            mod_card.body.addLayout(meta_grid)

            body.addWidget(mod_card, 3)

            root.addLayout(body, 1)

            self.cfg_widgets: Dict[str, Tuple[str, Any]] = {}
            self.last_preview: Optional[Dict[str, Any]] = None

            self.reload_records_btn.clicked.connect(self._reload_records)
            self.reload_plugins_btn.clicked.connect(self._reload_plugins)
            self.rec_list.currentRowChanged.connect(self._on_record_selected)
            self.mod_list.currentRowChanged.connect(self._on_mod_selected)
            self.preview_btn.clicked.connect(self._preview)
            self.store_btn.clicked.connect(self._store)

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
                if kind == "log":
                    self.log_view.append(str(payload))
                    self.tabs.setCurrentWidget(self.log_view)

        def _log(self, s: str) -> None:
            self.work_q.put(("log", s))

        def _reload_records(self) -> None:
            self.records = load_records()
            self.rec_list.clear()
            for r in self.records:
                rid = str(r.get("id", ""))
                mid = str(r.get("method_id", ""))
                ts = str(r.get("ts_utc", ""))
                fr = str(r.get("from", ""))
                it = QListWidgetItem(f"{rid}  [{mid}]  {ts}  ({fr})")
                it.setData(Qt.UserRole, r)
                self.rec_list.addItem(it)
            self._log(f"Loaded {len(self.records)} records")
            if self.rec_list.count() > 0 and self.rec_list.currentRow() < 0:
                self.rec_list.setCurrentRow(self.rec_list.count() - 1)

        def _reload_plugins(self) -> None:
            self.plugins = load_mod_plugins()
            self.mod_list.clear()
            for mid, pl in sorted(self.plugins.items(), key=lambda kv: kv[0]):
                it = QListWidgetItem(f"{pl.method_name} ({mid})")
                it.setData(Qt.UserRole, mid)
                self.mod_list.addItem(it)
            self._log(f"Loaded {len(self.plugins)} modifiers from: {str(modification_plugin_dir())}")
            if self.mod_list.count() > 0 and self.mod_list.currentRow() < 0:
                self.mod_list.setCurrentRow(0)

        def _selected_record(self) -> Optional[Dict[str, Any]]:
            i = self.rec_list.currentRow()
            if i < 0:
                return None
            it = self.rec_list.item(i)
            r = it.data(Qt.UserRole)
            return r if isinstance(r, dict) else None

        def _selected_mod_id(self) -> Optional[str]:
            i = self.mod_list.currentRow()
            if i < 0:
                return None
            it = self.mod_list.item(i)
            mid = it.data(Qt.UserRole)
            return str(mid) if mid is not None else None

        def _on_record_selected(self) -> None:
            r = self._selected_record()
            if not r:
                return
            meta = dict(r)
            ct = str(meta.pop("ciphertext", ""))
            self.orig_view.setPlainText(json.dumps(meta, ensure_ascii=True, indent=2) + "\n\n" + ct)
            self.tabs.setCurrentWidget(self.orig_view)
            self.last_preview = None
            self.tamp_view.setPlainText("")

        def _on_mod_selected(self) -> None:
            self._rebuild_cfg()

        def _clear_cfg(self) -> None:
            while self.cfg_grid.count() > 0:
                item = self.cfg_grid.takeAt(0)
                w = item.widget()
                if w is not None:
                    w.deleteLater()
            self.cfg_widgets.clear()

        def _rebuild_cfg(self) -> None:
            self._clear_cfg()
            mid = self._selected_mod_id()
            if not mid or mid not in self.plugins:
                return
            pl = self.plugins[mid]
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
                hint = QLabel("This modifier has no parameters.")
                hint.setObjectName("Hint")
                self.cfg_grid.addWidget(hint, 0, 0, 1, 2)

        def _read_cfg(self) -> Dict[str, Any]:
            cfg: Dict[str, Any] = {}
            for key, (ftype, w) in self.cfg_widgets.items():
                if ftype == "int":
                    cfg[key] = int(w.value())
                else:
                    cfg[key] = str(w.text())
            return cfg

        def _preview(self) -> None:
            r = self._selected_record()
            mid = self._selected_mod_id()
            if not r:
                self._log("No record selected")
                return
            if not mid or mid not in self.plugins:
                self._log("No modifier selected")
                return

            pl = self.plugins[mid]
            cfg = self._read_cfg()

            try:
                out = pl.modify_fn(dict(r), cfg)
            except Exception as e:
                self._log(f"Modify failed ({mid}): {e}")
                self.tabs.setCurrentWidget(self.log_view)
                return

            if not isinstance(out, dict):
                self._log(f"Modify returned non-dict ({mid})")
                self.tabs.setCurrentWidget(self.log_view)
                return

            # Keep a preview; do not auto-store.
            self.last_preview = out
            meta = dict(out)
            ct = str(meta.pop("ciphertext", ""))
            self.tamp_view.setPlainText(json.dumps(meta, ensure_ascii=True, indent=2) + "\n\n" + ct)
            self.tabs.setCurrentWidget(self.tamp_view)
            self._log(f"Preview ready: modifier={mid}")

        def _store(self) -> None:
            if not self.last_preview:
                self._log("Nothing to store (run Preview modify first)")
                self.tabs.setCurrentWidget(self.log_view)
                return

            base = dict(self.last_preview)
            base["id"] = make_id("tamper")
            base["ts_utc"] = now_utc_iso()
            base["from"] = str(self.attacker_from.text()).strip() or "M"
            base["to"] = str(self.attacker_to.text()).strip() or "B"

            if not isinstance(base.get("config", {}), dict):
                base["config"] = {}

            try:
                store_record(base)
            except Exception as e:
                self._log(f"Store failed: {e}")
                self.tabs.setCurrentWidget(self.log_view)
                return

            self._log(f"Stored tampered record as id={base['id']}")
            self._reload_records()

    app = QApplication([])
    app.setApplicationName("HarborModify")
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
    w.resize(1540, 880)
    w.show()
    app.exec()


def main() -> None:
    try:
        run_gui()
    except Exception as e:
        print("ERROR: PySide6 GUI could not start.")
        print(f"Reason: {e}")
        print("Install PySide6, or run inside the same venv as your other GUI scripts.")


if __name__ == "__main__":
    main()
