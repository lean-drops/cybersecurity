# scripts/ab_send_messages.py
from __future__ import annotations

import json
import queue
import random
import socket
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def project_root() -> Path:
    hard = Path("/Users/python/Pycharm Projects/Cybersecurity/Encryption")
    if hard.exists():
        return hard

    here = Path(__file__).resolve()
    candidates = [here.parent, here.parent.parent]
    if len(here.parents) >= 3:
        candidates.append(here.parents[2])

    for cand in candidates:
        if (cand / "encryption_methods").exists() or (cand / "decryption_methods").exists() or (cand / "encrypt").exists() or (cand / "decrypt").exists():
            return cand

    return here.parent.parent


def _find_dir(root: Path, names: List[str], create_name: str) -> Path:
    for n in names:
        p = root / n
        if p.exists() and p.is_dir():
            return p
    p = root / create_name
    p.mkdir(parents=True, exist_ok=True)
    return p


def encryption_plugin_dir() -> Path:
    root = project_root()
    return _find_dir(root, ["encryption_methods", "encrypt", "encryption"], "encryption_methods")


def styles_qss_path() -> Path:
    return Path("style.qss")


def data_dir() -> Path:
    d = project_root() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def channel_jsonl_path() -> Path:
    return data_dir() / "ab_channel.jsonl"


def channel_sqlite_path() -> Path:
    return data_dir() / "ab_channel.db"


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


def append_message_store(record: Dict[str, Any]) -> None:
    jp = channel_jsonl_path()
    with jp.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=True) + "\n")

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


def normalize_ascii_upper(text: str) -> str:
    out: List[str] = []
    for ch in text.upper():
        if "A" <= ch <= "Z":
            out.append(ch)
        elif ch in " .,!?:;'-\n":
            out.append(ch)
        else:
            out.append(" ")
    return "".join(out)


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_msg_id() -> str:
    return f"msg-{int(time.time() * 1000)}-{random.randint(1000, 9999)}"


# scripts/ab_send_messages.py
def tcp_send_json_line(
    host: str,
    dest_port: int,
    source_port: int,
    obj: Dict[str, Any],
    timeout_s: float = 4.0,
) -> Tuple[bool, str]:
    """
    Send one JSON line over TCP.

    Fix for macOS Errno 48 (Address already in use) when reusing a fixed source_port:
    - Reuse a persistent TCP connection per (host, dest_port, source_port) instead of reconnecting each send.
    - Enable SO_REUSEADDR (and best-effort SO_REUSEPORT) before bind.
    - If the user changes destination while keeping the same source_port, close any previous pooled socket
      using that source_port so a new connection can be created.
    """
    data = (json.dumps(obj, ensure_ascii=True) + "\n").encode("utf-8")
    dest_port_i = int(dest_port)
    source_port_i = int(source_port)

    # Lazy-init function-static pool + lock (no globals needed)
    if not hasattr(tcp_send_json_line, "_pool"):
        tcp_send_json_line._pool = {}  # type: ignore[attr-defined]
    if not hasattr(tcp_send_json_line, "_lock"):
        tcp_send_json_line._lock = threading.Lock()  # type: ignore[attr-defined]

    pool = tcp_send_json_line._pool  # type: ignore[attr-defined]
    lock = tcp_send_json_line._lock  # type: ignore[attr-defined]

    key = (str(host), dest_port_i, source_port_i)

    # 1) Try reuse existing connection
    with lock:
        s = pool.get(key)

    if s is not None:
        try:
            s.settimeout(timeout_s)
            s.sendall(data)
            return True, "sent(reuse)"
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            with lock:
                if pool.get(key) is s:
                    pool.pop(key, None)

    # 2) If we are using a fixed source port and destination changed, we cannot keep another socket
    #    bound to the same source port. Close any pooled sockets that use this source port.
    if source_port_i > 0:
        to_close = []
        with lock:
            for k, sock in list(pool.items()):
                if k != key and k[2] == source_port_i:
                    to_close.append((k, sock))
            for k, _sock in to_close:
                pool.pop(k, None)
        for _k, sock in to_close:
            try:
                sock.close()
            except Exception:
                pass

    # 3) Create a new connection and keep it open for future sends
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s2.settimeout(timeout_s)
        try:
            s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass
        # Best-effort on platforms that support it
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except Exception:
                pass

        if source_port_i > 0:
            s2.bind(("0.0.0.0", source_port_i))

        s2.connect((host, dest_port_i))
        s2.sendall(data)

        with lock:
            pool[key] = s2

        return True, "sent(new)"
    except Exception as e:
        try:
            s2.close()
        except Exception:
            pass
        return False, f"send failed: {e}"
class TcpJsonLineServer:
    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        on_message: Callable[[Dict[str, Any], Tuple[str, int]], None],
        on_status: Callable[[str], None],
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.on_message = on_message
        self.on_status = on_status
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        t = threading.Thread(target=self._run, daemon=True)
        self._thread = t
        t.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def _run(self) -> None:
        self.on_status(f"B server starting on {self.listen_host}:{self.listen_port}")
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock = srv
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.listen_host, int(self.listen_port)))
            srv.listen(8)
            srv.settimeout(0.5)
            while not self._stop.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except Exception:
                    break
                threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()
        except Exception as e:
            self.on_status(f"B server error: {e}")
        finally:
            try:
                srv.close()
            except Exception:
                pass
            self.on_status("B server stopped")

    def _handle_conn(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        try:
            conn.settimeout(2.0)
            buf = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line.decode("utf-8", errors="replace"))
                        if isinstance(obj, dict):
                            self.on_message(obj, addr)
                    except Exception:
                        continue
        finally:
            try:
                conn.close()
            except Exception:
                pass


@dataclass(frozen=True)
class Plugin:
    method_id: str
    method_name: str
    config_fields: List[Dict[str, Any]]
    encrypt_fn: Callable[[str, Dict[str, Any]], str]


def load_encrypt_plugin_file(path: Path) -> Plugin:
    import importlib.util

    mod_name = f"enc_{path.stem}_{abs(hash(str(path)))}"
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load plugin spec")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore

    method_id = str(getattr(mod, "METHOD_ID", "")).strip()
    method_name = str(getattr(mod, "METHOD_NAME", "")).strip()
    config_fields = getattr(mod, "CONFIG_FIELDS", [])
    encrypt_fn = getattr(mod, "encrypt", None)

    if not method_id or not method_name or not isinstance(config_fields, list) or not callable(encrypt_fn):
        raise RuntimeError("Invalid plugin interface")

    return Plugin(
        method_id=method_id,
        method_name=method_name,
        config_fields=list(config_fields),
        encrypt_fn=encrypt_fn,
    )


def identity_encrypt(plaintext: str, _config: Dict[str, Any]) -> str:
    return plaintext


def load_encrypt_plugins() -> Dict[str, Plugin]:
    plugins: Dict[str, Plugin] = {}
    plugins["identity"] = Plugin(
        method_id="identity",
        method_name="No encryption (identity)",
        config_fields=[],
        encrypt_fn=identity_encrypt,
    )

    plug_dir = encryption_plugin_dir()
    for p in sorted(plug_dir.glob("*.py")):
        if p.name.startswith("_"):
            continue
        try:
            plugin = load_encrypt_plugin_file(p)
            plugins[plugin.method_id] = plugin
        except Exception:
            continue

    return plugins


def run_gui_pyside() -> None:
    from PySide6.QtCore import Qt, QTimer  # type: ignore
    from PySide6.QtGui import QFont  # type: ignore
    from PySide6.QtWidgets import (  # type: ignore
        QApplication,
        QComboBox,
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

            head = QHBoxLayout()
            lbl = QLabel(title)
            lbl.setObjectName("CardTitle")
            head.addWidget(lbl, 1)
            outer.addLayout(head)

            self.body = QVBoxLayout()
            self.body.setSpacing(10)
            outer.addLayout(self.body)

    class Main(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self.setObjectName("AppWindow")
            self.setWindowTitle("HarborLink - Summer Night Toulouse")

            self.plugins = load_encrypt_plugins()
            self.q: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
            self.srv: Optional[TcpJsonLineServer] = None

            self.records: List[Dict[str, Any]] = []

            root = QVBoxLayout(self)
            root.setContentsMargins(16, 16, 16, 16)
            root.setSpacing(12)

            header = QFrame()
            header.setObjectName("HeaderBar")
            h = QHBoxLayout(header)
            h.setContentsMargins(16, 14, 16, 14)

            title = QLabel("HarborLink")
            title.setObjectName("AppTitle")
            subtitle = QLabel("A -> B TCP channel + plugins")
            subtitle.setObjectName("AppSubtitle")

            tcol = QVBoxLayout()
            tcol.setSpacing(2)
            tcol.addWidget(title)
            tcol.addWidget(subtitle)
            h.addLayout(tcol, 1)

            self.status_pill = QLabel("B server: stopped")
            self.status_pill.setObjectName("StatusPillBad")
            self.status_pill.setAlignment(Qt.AlignCenter)
            self.status_pill.setMinimumWidth(180)
            h.addWidget(self.status_pill)

            root.addWidget(header)

            mid = QHBoxLayout()
            mid.setSpacing(12)

            left = QVBoxLayout()
            left.setSpacing(12)

            conn = Card("Channel settings")
            grid = QGridLayout()
            grid.setHorizontalSpacing(10)
            grid.setVerticalSpacing(10)

            self.host_in = QLineEdit("127.0.0.1")
            self.host_in.setObjectName("Input")
            self.a_port_in = QSpinBox()
            self.a_port_in.setRange(1, 65535)
            self.a_port_in.setValue(6001)
            self.b_port_in = QSpinBox()
            self.b_port_in.setRange(1, 65535)
            self.b_port_in.setValue(6002)

            grid.addWidget(QLabel("Host"), 0, 0)
            grid.addWidget(self.host_in, 0, 1)
            grid.addWidget(QLabel("A source port"), 1, 0)
            grid.addWidget(self.a_port_in, 1, 1)
            grid.addWidget(QLabel("B listen port"), 2, 0)
            grid.addWidget(self.b_port_in, 2, 1)

            btn_row = QHBoxLayout()
            self.start_btn = QPushButton("Start B server")
            self.start_btn.setObjectName("PrimaryButton")
            self.stop_btn = QPushButton("Stop")
            self.stop_btn.setObjectName("GhostButton")
            btn_row.addWidget(self.start_btn)
            btn_row.addWidget(self.stop_btn)

            conn.body.addLayout(grid)
            conn.body.addLayout(btn_row)

            plug_hint = QLabel(
                f"Plugin dir: {str(encryption_plugin_dir())}"
            )
            plug_hint.setObjectName("Hint")
            conn.body.addWidget(plug_hint)

            left.addWidget(conn)

            compose = Card("Compose from A")
            self.method_sel = QComboBox()
            self.method_sel.setObjectName("Input")
            for mid_k, pl in self.plugins.items():
                self.method_sel.addItem(f"{pl.method_name} ({mid_k})", mid_k)

            compose.body.addWidget(QLabel("Encryption method"))
            compose.body.addWidget(self.method_sel)

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
            cfg_scroll.setMinimumHeight(140)

            compose.body.addWidget(QLabel("Method config"))
            compose.body.addWidget(cfg_scroll)

            self.plain_in = QTextEdit()
            self.plain_in.setObjectName("TextArea")
            self.plain_in.setPlaceholderText("Type plaintext here ...")
            self.plain_in.setMinimumHeight(160)

            compose.body.addWidget(QLabel("Plaintext"))
            compose.body.addWidget(self.plain_in)

            send_row = QHBoxLayout()
            self.include_debug_btn = QPushButton("Include debug_plaintext: OFF")
            self.include_debug_btn.setCheckable(True)
            self.include_debug_btn.setObjectName("ToggleButton")
            self.send_btn = QPushButton("Send A -> B")
            self.send_btn.setObjectName("PrimaryButton")
            send_row.addWidget(self.include_debug_btn, 1)
            send_row.addWidget(self.send_btn, 1)
            compose.body.addLayout(send_row)

            left.addWidget(compose, 1)

            mid.addLayout(left, 2)

            right = QVBoxLayout()
            right.setSpacing(12)

            inbox = Card("Inbox at B (received)")
            self.inbox_list = QListWidget()
            self.inbox_list.setObjectName("List")
            self.inbox_list.setMinimumWidth(420)
            inbox.body.addWidget(self.inbox_list)
            right.addWidget(inbox, 2)

            details = Card("Selected message")
            self.details = QTextEdit()
            self.details.setObjectName("TextArea")
            self.details.setReadOnly(True)
            details.body.addWidget(self.details)
            right.addWidget(details, 2)

            log_card = Card("Log")
            self.log = QTextEdit()
            self.log.setObjectName("LogArea")
            self.log.setReadOnly(True)
            self.log.setMinimumHeight(140)
            log_card.body.addWidget(self.log)
            right.addWidget(log_card, 1)

            mid.addLayout(right, 3)
            root.addLayout(mid, 1)

            self.cfg_widgets: Dict[str, Tuple[str, Any]] = {}

            self.method_sel.currentIndexChanged.connect(self._rebuild_cfg)
            self.start_btn.clicked.connect(self._start_server)
            self.stop_btn.clicked.connect(self._stop_server)
            self.send_btn.clicked.connect(self._send)
            self.include_debug_btn.toggled.connect(self._toggle_debug)
            self.inbox_list.currentRowChanged.connect(self._show_selected)

            self._rebuild_cfg()
            self._load_existing_records()

            self.timer = QTimer(self)
            self.timer.timeout.connect(self._poll_q)
            self.timer.start(100)

            self._log(f"Using project root: {str(project_root())}")
            self._log(f"Using encryption plugin dir: {str(encryption_plugin_dir())}")

        def _toggle_debug(self, on: bool) -> None:
            self.include_debug_btn.setText("Include debug_plaintext: ON" if on else "Include debug_plaintext: OFF")

        def _set_status(self, running: bool) -> None:
            if running:
                self.status_pill.setText("B server: running")
                self.status_pill.setObjectName("StatusPillOk")
            else:
                self.status_pill.setText("B server: stopped")
                self.status_pill.setObjectName("StatusPillBad")
            self.status_pill.style().unpolish(self.status_pill)
            self.status_pill.style().polish(self.status_pill)

        def _log(self, s: str) -> None:
            self.log.append(s)

        def _poll_q(self) -> None:
            while True:
                try:
                    kind, payload = self.q.get_nowait()
                except queue.Empty:
                    break
                if kind == "status":
                    self._log(str(payload))
                    txt = str(payload).lower()
                    if "starting" in txt:
                        self._set_status(True)
                    if "stopped" in txt:
                        self._set_status(False)
                elif kind == "msg":
                    obj, addr = payload
                    try:
                        append_message_store(obj)
                    except Exception as e:
                        self._log(f"store failed: {e}")
                    self._add_record_to_inbox(obj, addr)

        def _on_server_msg(self, obj: Dict[str, Any], addr: Tuple[str, int]) -> None:
            self.q.put(("msg", (obj, addr)))

        def _on_server_status(self, s: str) -> None:
            self.q.put(("status", s))

        def _start_server(self) -> None:
            port = int(self.b_port_in.value())
            self.srv = TcpJsonLineServer("0.0.0.0", port, self._on_server_msg, self._on_server_status)
            self.srv.start()

        def _stop_server(self) -> None:
            if self.srv:
                self.srv.stop()
                self.srv = None
            self._set_status(False)

        def _clear_cfg_grid(self) -> None:
            while self.cfg_grid.count() > 0:
                item = self.cfg_grid.takeAt(0)
                w = item.widget()
                if w is not None:
                    w.deleteLater()
            self.cfg_widgets.clear()

        def _rebuild_cfg(self) -> None:
            self._clear_cfg_grid()
            mid_k = self.method_sel.currentData()
            if not mid_k or mid_k not in self.plugins:
                return
            pl = self.plugins[mid_k]
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
                        w.setValue(int(default))
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
                hint = QLabel("This method has no parameters.")
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

        def _send(self) -> None:
            host = str(self.host_in.text()).strip()
            a_port = int(self.a_port_in.value())
            b_port = int(self.b_port_in.value())
            if a_port == b_port:
                self._log("ERROR: A source port and B listen port must be different")
                return

            mid_k = self.method_sel.currentData()
            if not mid_k or mid_k not in self.plugins:
                self._log("ERROR: no encryption plugin selected")
                return
            pl = self.plugins[mid_k]

            pt = normalize_ascii_upper(self.plain_in.toPlainText())
            if not pt.strip():
                self._log("ERROR: empty plaintext")
                return

            cfg = self._read_cfg()
            try:
                ct = str(pl.encrypt_fn(pt, cfg))
            except Exception as e:
                self._log(f"encrypt failed: {e}")
                return

            rec: Dict[str, Any] = {
                "id": make_msg_id(),
                "ts_utc": now_utc_iso(),
                "from": "A",
                "to": "B",
                "method_id": pl.method_id,
                "method_name": pl.method_name,
                "config": cfg,
                "ciphertext": ct,
            }
            if self.include_debug_btn.isChecked():
                rec["debug_plaintext"] = pt

            ok, msg = tcp_send_json_line(host, b_port, a_port, rec)
            self._log(f"SEND A:{a_port} -> B:{b_port} ok={ok} ({msg}) id={rec['id']}")

        def _load_existing_records(self) -> None:
            self.records = load_records()
            self.inbox_list.clear()
            for r in self.records[-300:]:
                self._add_inbox_item(r, None)

        def _add_inbox_item(self, r: Dict[str, Any], addr: Optional[Tuple[str, int]]) -> None:
            mid_k = str(r.get("method_id", ""))
            rid = str(r.get("id", ""))
            ts = str(r.get("ts_utc", ""))
            src = f"{addr[0]}:{addr[1]}" if addr else "stored"
            text = f"{rid}  [{mid_k}]  {ts}  ({src})"
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, r)
            self.inbox_list.addItem(item)

        def _add_record_to_inbox(self, r: Dict[str, Any], addr: Tuple[str, int]) -> None:
            self._add_inbox_item(r, addr)
            self.inbox_list.setCurrentRow(self.inbox_list.count() - 1)

        def _show_selected(self) -> None:
            i = self.inbox_list.currentRow()
            if i < 0:
                return
            item = self.inbox_list.item(i)
            r = item.data(Qt.UserRole)
            if not isinstance(r, dict):
                return
            self.details.setPlainText(json.dumps(r, ensure_ascii=True, indent=2))

    app = QApplication([])
    app.setApplicationName("HarborLink")

    f = QFont()
    f.setPointSize(10)
    app.setFont(f)

    qss_path = styles_qss_path()
    if qss_path.exists():
        try:
            app.setStyleSheet(qss_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    w = Main()
    w.resize(1280, 820)
    w.show()
    app.exec()


def main() -> None:
    run_gui_pyside()


if __name__ == "__main__":
    main()