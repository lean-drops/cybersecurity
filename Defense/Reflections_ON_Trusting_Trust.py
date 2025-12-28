# Defense/Reflections_ON_Trusting_Trust.py
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

try:
    from PySide6 import QtCore, QtGui, QtWidgets
except ImportError:  # pragma: no cover
    from PySide2 import QtCore, QtGui, QtWidgets  # type: ignore


CLEAN_COMPILER_SRC = r'''#!/usr/bin/env python3
# clean_compiler_src.py
# A tiny "compiler" from MiniLang to Python.
# MiniLang format:
#   PRINT <text...>
# It generates a Python script that prints those lines.

import sys

def compile_minilang(mini_text):
    out = []
    out.append("# generated_by_clean_compiler")
    out.append("def main():")
    for line in mini_text.splitlines():
        line = line.rstrip("\n")
        if not line.strip():
            continue
        if line.startswith("PRINT "):
            payload = line[6:]
            payload = payload.replace("\\\\", "\\\\\\\\").replace('"', '\\"')
            out.append(f'    print("{payload}")')
        else:
            out.append('    print("UNKNOWN_LINE")')
    out.append("")
    out.append('if __name__ == "__main__":')
    out.append("    main()")
    out.append("")
    return "\n".join(out)

def main():
    if len(sys.argv) != 3:
        print("usage: compiler.py <in.mini> <out.py>")
        return 2
    inp, outp = sys.argv[1], sys.argv[2]
    mini = open(inp, "r", encoding="utf-8").read()
    py = compile_minilang(mini)
    open(outp, "w", encoding="utf-8").write(py)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'''


TROJAN_COMPILER_BIN = r'''#!/usr/bin/env python3
# trojan_compiler_bin.py
# A "trojaned compiler" for the demo. It injects harmless markers:
# - Adds a constant INJECTED_BY_COMPILER = True into generated output.
# - If compiling *the compiler source itself*, it ensures the resulting compiler
#   retains this injection logic (self-propagation).
#
# This is a safe simulation: no networking, no credential bypass, no exploitation.

import sys
import re

INJECT_MARKER = "INJECTED_BY_COMPILER = True"

def compile_minilang(mini_text):
    out = []
    out.append("# generated_by_trojan_compiler")
    out.append(INJECT_MARKER)
    out.append("def main():")
    for line in mini_text.splitlines():
        line = line.rstrip("\n")
        if not line.strip():
            continue
        if line.startswith("PRINT "):
            payload = line[6:]
            payload = payload.replace("\\\\", "\\\\\\\\").replace('"', '\\"')
            out.append(f'    print("{payload}")')
        else:
            out.append('    print("UNKNOWN_LINE")')
    out.append("")
    out.append('if __name__ == "__main__":')
    out.append("    main()")
    out.append("")
    return "\n".join(out)

def inject_into_compiler_source(src_text):
    # If the source already looks trojaned, leave it.
    if "inject_into_compiler_source" in src_text and "INJECTED_BY_COMPILER" in src_text:
        return src_text

    wrapper = []
    wrapper.append("#!/usr/bin/env python3")
    wrapper.append("# compiler_stage_from_trojan.py")
    wrapper.append("# Built from clean-looking source, but contains injected logic.")
    wrapper.append("")
    wrapper.append("import sys")
    wrapper.append("")
    wrapper.append('INJECT_MARKER = "INJECTED_BY_COMPILER = True"')
    wrapper.append("")
    wrapper.append("def compile_minilang(mini_text):")
    wrapper.append("    out = []")
    wrapper.append('    out.append("# generated_by_injected_stage_compiler")')
    wrapper.append("    out.append(INJECT_MARKER)")
    wrapper.append("    out.append('def main():')")
    wrapper.append("    for line in mini_text.splitlines():")
    wrapper.append("        line = line.rstrip('\\n')")
    wrapper.append("        if not line.strip():")
    wrapper.append("            continue")
    wrapper.append("        if line.startswith('PRINT '):")
    wrapper.append("            payload = line[6:]")
    wrapper.append("            payload = payload.replace('\\\\\\\\', '\\\\\\\\\\\\\\\\').replace('\"', '\\\\\"')")
    wrapper.append("            out.append(f'    print(\"{payload}\")')")
    wrapper.append("        else:")
    wrapper.append('            out.append(\'    print("UNKNOWN_LINE")\')')
    wrapper.append("    out.append('')")
    wrapper.append("    out.append('if __name__ == \"__main__\":')")
    wrapper.append("    out.append('    main()')")
    wrapper.append("    out.append('')")
    wrapper.append("    return \"\\n\".join(out)")
    wrapper.append("")
    wrapper.append("def main():")
    wrapper.append("    if len(sys.argv) != 3:")
    wrapper.append("        print('usage: compiler.py <in.mini> <out.py>')")
    wrapper.append("        return 2")
    wrapper.append("    inp, outp = sys.argv[1], sys.argv[2]")
    wrapper.append("    mini = open(inp, 'r', encoding='utf-8').read()")
    wrapper.append("    py = compile_minilang(mini)")
    wrapper.append("    open(outp, 'w', encoding='utf-8').write(py)")
    wrapper.append("    return 0")
    wrapper.append("")
    wrapper.append("if __name__ == '__main__':")
    wrapper.append("    raise SystemExit(main())")
    wrapper.append("")
    return "\n".join(wrapper)

def main():
    if len(sys.argv) != 3:
        print("usage: trojan_compiler.py <in> <out>")
        return 2

    inp, outp = sys.argv[1], sys.argv[2]
    text = open(inp, "r", encoding="utf-8").read()

    # If input looks like MiniLang, compile it.
    if inp.endswith(".mini"):
        py = compile_minilang(text)
        open(outp, "w", encoding="utf-8").write(py)
        return 0

    # If input is the clean compiler source, output an injected compiler stage.
    if inp.endswith("_src.py") or "clean_compiler_src.py" in inp:
        injected = inject_into_compiler_source(text)
        open(outp, "w", encoding="utf-8").write(injected)
        return 0

    # Otherwise: pass-through (still "compromised": add a harmless marker comment).
    open(outp, "w", encoding="utf-8").write("# passthrough_by_trojan\n" + text)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'''


MINILANG_PROGRAM = "PRINT Hello from MiniLang!\\nPRINT This build shows a harmless injection marker.\\n"


def run_py(p: Path, args: List[str]) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(p)] + list(args)
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def read_first_match(path: Path, pattern: str) -> Tuple[Optional[str], str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    m = re.search(pattern, text)
    return (m.group(0) if m else None), text


@dataclass
class DemoResult:
    workdir: str
    steps: List[Tuple[str, bool]]
    generated_stdout: str
    notes: List[str]
    ok: bool


def _looks_like_compiler_script(text: str) -> bool:
    return ("usage: compiler.py <in.mini> <out.py>" in text) and ("open(outp" in text) and ("def compile_minilang" in text)


def run_trusting_trust_demo(keep_workdir: bool, log: Callable[[str], None]) -> DemoResult:
    base = Path(tempfile.mkdtemp(prefix="trusting_trust_demo_"))
    steps: List[Tuple[str, bool]] = []
    notes: List[str] = []

    def add_step(label: str, value: bool) -> None:
        steps.append((label, value))
        log(f"{label} -> {value}")

    def add_note(line: str) -> None:
        notes.append(line)
        log(line)

    clean_src = base / "clean_compiler_src.py"
    trojan_bin = base / "trojan_compiler_bin.py"
    stage1 = base / "compiler_stage1.py"
    stage2 = base / "compiler_stage2.py"
    prog_mini = base / "hello.mini"
    out_py_1 = base / "hello_stage1.py"
    out_py_2 = base / "hello_stage2.py"

    try:
        clean_src.write_text(CLEAN_COMPILER_SRC, encoding="utf-8")
        trojan_bin.write_text(TROJAN_COMPILER_BIN, encoding="utf-8")
        prog_mini.write_text(MINILANG_PROGRAM, encoding="utf-8")

        try:
            os.chmod(clean_src, 0o755)
            os.chmod(trojan_bin, 0o755)
        except Exception:
            pass

        log(f"Workdir: {base}")
        log("")

        marker = "INJECTED_BY_COMPILER"

        found_clean, _ = read_first_match(clean_src, marker)
        add_step("1) Clean compiler source contains marker?", bool(found_clean))

        r = run_py(trojan_bin, [str(clean_src), str(stage1)])
        if r.returncode != 0:
            add_note("ERROR compiling stage1:")
            add_note(r.stderr.strip() or "(no stderr)")
            return DemoResult(str(base), steps, "", notes, False)

        found_s1, text_s1 = read_first_match(stage1, marker)
        add_step("2) Stage1 compiler contains marker?", bool(found_s1))

        r = run_py(stage1, [str(prog_mini), str(out_py_1)])
        if r.returncode != 0 or not out_py_1.exists():
            add_note("ERROR compiling hello_stage1:")
            add_note(r.stderr.strip() or "(no stderr)")
            return DemoResult(str(base), steps, "", notes, False)

        found_o1, _ = read_first_match(out_py_1, marker)
        add_step("3) Output program built by stage1 contains marker?", bool(found_o1))

        # Attempt stage2 rebuild from clean source using stage1. This is intentionally "wrong input"
        # for stage1; we detect the result and fall back to copying stage1 -> stage2 to simulate
        # persistence without crashing later.
        r = run_py(stage1, [str(clean_src), str(stage2)])
        fallback = False
        if r.returncode != 0:
            fallback = True
        else:
            try:
                stage2_text = stage2.read_text(encoding="utf-8", errors="replace")
            except FileNotFoundError:
                stage2_text = ""
            if not _looks_like_compiler_script(stage2_text):
                fallback = True

        if fallback:
            stage2.write_text(text_s1, encoding="utf-8")
            add_note("note: stage2 rebuild produced a non-compiler; copying stage1 -> stage2 to simulate persistence")

        found_s2, _ = read_first_match(stage2, marker)
        add_step("4) Stage2 compiler contains marker (persistence)?", bool(found_s2))

        r = run_py(stage2, [str(prog_mini), str(out_py_2)])
        if r.returncode != 0 or not out_py_2.exists():
            add_note("ERROR compiling hello_stage2:")
            if r.returncode != 0:
                add_note(r.stderr.strip() or "(no stderr)")
            else:
                add_note("stage2 returned success but did not create output file")
                if r.stdout.strip():
                    add_note("stdout: " + r.stdout.strip())
                if r.stderr.strip():
                    add_note("stderr: " + r.stderr.strip())
            return DemoResult(str(base), steps, "", notes, False)

        found_o2, _ = read_first_match(out_py_2, marker)
        add_step("5) Output program built by stage2 contains marker?", bool(found_o2))

        log("")
        r = run_py(out_py_2, [])
        log("Generated program output:")
        generated = (r.stdout or "").rstrip("\n")
        log(generated if generated else "(no stdout)")
        if (r.stderr or "").strip():
            log("stderr: " + r.stderr.strip())

        log("")
        log("Key point:")
        log("- The source of the compiler can look clean,")
        log("  but a compromised compiler/toolchain can still inject behavior into the binary output.")

        return DemoResult(str(base), steps, generated, notes, True)
    finally:
        if not keep_workdir:
            shutil.rmtree(base, ignore_errors=True)


def open_in_file_manager(path: str) -> None:
    p = str(Path(path))
    if sys.platform.startswith("darwin"):
        subprocess.Popen(["open", p])
    elif os.name == "nt":
        subprocess.Popen(["explorer", p])
    else:
        subprocess.Popen(["xdg-open", p])


class StarfieldBackground(QtWidgets.QWidget):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.setAttribute(QtCore.Qt.WA_OpaquePaintEvent, True)
        self._rng = QtCore.QRandomGenerator(1337)
        self._stars = []
        self._t = 0.0
        self._timer = QtCore.QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(33)
        self._reseed_stars(260)

    def _reseed_stars(self, n: int) -> None:
        self._stars = []
        for _ in range(n):
            x = float(self._rng.generateDouble())
            y = float(self._rng.generateDouble())
            r = 0.6 + 1.8 * float(self._rng.generateDouble())
            a = 0.25 + 0.75 * float(self._rng.generateDouble())
            sp = 0.6 + 2.8 * float(self._rng.generateDouble())
            self._stars.append((x, y, r, a, sp))

    def _tick(self) -> None:
        self._t += 0.033
        if self._t > 10_000.0:
            self._t = 0.0
        self.update()

    def paintEvent(self, event: QtGui.QPaintEvent) -> None:
        w = max(1, self.width())
        h = max(1, self.height())

        p = QtGui.QPainter(self)
        try:
            p.setRenderHint(QtGui.QPainter.Antialiasing, True)

            # Deep space gradient
            bg = QtGui.QLinearGradient(0, 0, 0, h)
            bg.setColorAt(0.0, QtGui.QColor(3, 5, 18))
            bg.setColorAt(0.55, QtGui.QColor(7, 10, 28))
            bg.setColorAt(1.0, QtGui.QColor(2, 3, 12))
            p.fillRect(0, 0, w, h, bg)

            # Nebula blobs
            def blob(cx: float, cy: float, radius: float, color: QtGui.QColor) -> None:
                g = QtGui.QRadialGradient(cx, cy, radius)
                c0 = QtGui.QColor(color)
                c1 = QtGui.QColor(color)
                c0.setAlpha(100)
                c1.setAlpha(0)
                g.setColorAt(0.0, c0)
                g.setColorAt(1.0, c1)
                p.fillRect(0, 0, w, h, g)

            blob(0.18 * w, 0.28 * h, 0.55 * min(w, h), QtGui.QColor(120, 60, 220))
            blob(0.78 * w, 0.22 * h, 0.45 * min(w, h), QtGui.QColor(20, 200, 220))
            blob(0.62 * w, 0.72 * h, 0.60 * min(w, h), QtGui.QColor(70, 120, 255))

            # Stars
            sin = __import__("math").sin
            for (nx, ny, r, a, sp) in self._stars:
                x = nx * w
                y = ny * h
                tw = 0.55 + 0.45 * (0.5 + 0.5 * sin(self._t * sp + (nx * 9.0 + ny * 7.0)))
                alpha = int(255 * max(0.0, min(1.0, a * tw)))
                col = QtGui.QColor(230, 240, 255, alpha)
                p.setBrush(col)
                p.setPen(QtCore.Qt.NoPen)
                p.drawEllipse(QtCore.QPointF(x, y), r, r)

            # Subtle vignette
            vg = QtGui.QRadialGradient(0.5 * w, 0.5 * h, 0.75 * max(w, h))
            vg.setColorAt(0.0, QtGui.QColor(0, 0, 0, 0))
            vg.setColorAt(1.0, QtGui.QColor(0, 0, 0, 160))
            p.fillRect(0, 0, w, h, vg)
        finally:
            if p.isActive():
                p.end()

class GlassFrame(QtWidgets.QFrame):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("GlassFrame")
        self.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.setAutoFillBackground(False)
        shadow = QtWidgets.QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(28)
        shadow.setOffset(0, 10)
        shadow.setColor(QtGui.QColor(0, 0, 0, 180))
        self.setGraphicsEffect(shadow)


class DemoWorker(QtCore.QObject):
    log_line = QtCore.Signal(str)
    finished = QtCore.Signal(object)

    def __init__(self, keep_workdir: bool) -> None:
        super().__init__()
        self._keep = keep_workdir

    @QtCore.Slot()
    def run(self) -> None:
        def cb(line: str) -> None:
            self.log_line.emit(line)

        try:
            res = run_trusting_trust_demo(self._keep, cb)
        except Exception as e:
            res = DemoResult(workdir="", steps=[], generated_stdout="", notes=[str(e)], ok=False)
        self.finished.emit(res)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Reflections on Trusting Trust - Galaxy Demo")
        self.resize(1100, 720)

        self._last_workdir = ""
        self._thread: Optional[QtCore.QThread] = None

        bg = StarfieldBackground()
        self.setCentralWidget(bg)

        outer = QtWidgets.QVBoxLayout(bg)
        outer.setContentsMargins(22, 22, 22, 22)
        outer.setSpacing(14)

        header = GlassFrame()
        header_l = QtWidgets.QHBoxLayout(header)
        header_l.setContentsMargins(18, 14, 18, 14)

        title_box = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel("Reflections on Trusting Trust")
        title.setObjectName("Title")
        subtitle = QtWidgets.QLabel("Safe simulation: clean-looking source, injected outputs, persistence effect")
        subtitle.setObjectName("Subtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        header_l.addLayout(title_box)
        header_l.addStretch(1)

        self.status_pill = QtWidgets.QLabel("Idle")
        self.status_pill.setObjectName("StatusPill")
        header_l.addWidget(self.status_pill)

        outer.addWidget(header)

        content = QtWidgets.QHBoxLayout()
        content.setSpacing(14)

        left = GlassFrame()
        left.setMinimumWidth(320)
        left_l = QtWidgets.QVBoxLayout(left)
        left_l.setContentsMargins(16, 16, 16, 16)
        left_l.setSpacing(12)

        controls_title = QtWidgets.QLabel("Controls")
        controls_title.setObjectName("SectionTitle")
        left_l.addWidget(controls_title)

        self.keep_cb = QtWidgets.QCheckBox("Keep workdir (for inspection)")
        self.keep_cb.setChecked(False)
        left_l.addWidget(self.keep_cb)

        self.run_btn = QtWidgets.QPushButton("Run Demo")
        self.run_btn.setObjectName("PrimaryButton")
        self.run_btn.clicked.connect(self._on_run)
        left_l.addWidget(self.run_btn)

        self.open_btn = QtWidgets.QPushButton("Open workdir")
        self.open_btn.setEnabled(False)
        self.open_btn.clicked.connect(self._on_open_workdir)
        left_l.addWidget(self.open_btn)

        self.copy_btn = QtWidgets.QPushButton("Copy log")
        self.copy_btn.clicked.connect(self._on_copy_log)
        left_l.addWidget(self.copy_btn)

        self.clear_btn = QtWidgets.QPushButton("Clear log")
        self.clear_btn.clicked.connect(self._on_clear_log)
        left_l.addWidget(self.clear_btn)

        left_l.addSpacing(6)
        left_l.addWidget(QtWidgets.QLabel("Step Results"))
        self.table = QtWidgets.QTableWidget(5, 2)
        self.table.setHorizontalHeaderLabels(["Step", "Value"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        self.table.setObjectName("ResultsTable")
        left_l.addWidget(self.table, 1)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setObjectName("ProgressBar")
        left_l.addWidget(self.progress)

        left_l.addStretch(1)

        right = GlassFrame()
        right_l = QtWidgets.QVBoxLayout(right)
        right_l.setContentsMargins(16, 16, 16, 16)
        right_l.setSpacing(10)

        log_title = QtWidgets.QHBoxLayout()
        log_label = QtWidgets.QLabel("Log")
        log_label.setObjectName("SectionTitle")
        log_title.addWidget(log_label)
        log_title.addStretch(1)

        self.workdir_label = QtWidgets.QLabel("")
        self.workdir_label.setObjectName("WorkdirLabel")
        self.workdir_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        log_title.addWidget(self.workdir_label)

        right_l.addLayout(log_title)

        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setObjectName("LogView")
        self.log.setPlaceholderText("Output will appear here...")
        right_l.addWidget(self.log, 1)

        content.addWidget(left, 0)
        content.addWidget(right, 1)

        outer.addLayout(content, 1)

        self._apply_galaxy_theme()

        for i in range(5):
            self.table.setItem(i, 0, QtWidgets.QTableWidgetItem(""))
            self.table.setItem(i, 1, QtWidgets.QTableWidgetItem(""))

    def _apply_galaxy_theme(self) -> None:
        qss = """
        QWidget { color: rgba(235, 242, 255, 230); font-size: 13px; }
        #Title { font-size: 22px; font-weight: 700; letter-spacing: 0.2px; }
        #Subtitle { color: rgba(210, 225, 255, 190); font-size: 12px; }
        #SectionTitle { font-size: 14px; font-weight: 650; color: rgba(235, 242, 255, 230); }
        #WorkdirLabel { color: rgba(190, 220, 255, 190); font-size: 12px; }
        #StatusPill {
            padding: 6px 10px;
            border-radius: 999px;
            background: rgba(15, 22, 45, 200);
            border: 1px solid rgba(130, 90, 255, 140);
            color: rgba(230, 240, 255, 230);
            font-weight: 600;
        }
        #GlassFrame {
            background: rgba(10, 14, 28, 170);
            border: 1px solid rgba(140, 105, 255, 90);
            border-radius: 16px;
        }
        QPushButton {
            background: rgba(18, 24, 50, 220);
            border: 1px solid rgba(120, 100, 255, 110);
            border-radius: 12px;
            padding: 10px 12px;
            font-weight: 600;
        }
        QPushButton:hover {
            border: 1px solid rgba(60, 215, 255, 160);
            background: rgba(22, 30, 62, 235);
        }
        QPushButton:pressed {
            background: rgba(12, 16, 34, 230);
        }
        QPushButton:disabled {
            color: rgba(235, 242, 255, 120);
            border: 1px solid rgba(120, 100, 255, 55);
            background: rgba(18, 24, 50, 130);
        }
        #PrimaryButton {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 rgba(120, 60, 255, 235),
                        stop:1 rgba(35, 210, 240, 235));
            border: 0px;
            color: rgba(5, 7, 18, 240);
        }
        #PrimaryButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 rgba(140, 80, 255, 245),
                        stop:1 rgba(55, 230, 255, 245));
        }
        QCheckBox { spacing: 10px; }
        QCheckBox::indicator {
            width: 18px; height: 18px;
            border-radius: 6px;
            border: 1px solid rgba(120, 100, 255, 110);
            background: rgba(12, 16, 34, 200);
        }
        QCheckBox::indicator:checked {
            background: rgba(35, 210, 240, 235);
            border: 1px solid rgba(35, 210, 240, 235);
        }
        #LogView {
            background: rgba(6, 9, 18, 210);
            border: 1px solid rgba(120, 100, 255, 80);
            border-radius: 14px;
            padding: 10px;
            selection-background-color: rgba(35, 210, 240, 140);
        }
        #ResultsTable {
            background: rgba(6, 9, 18, 160);
            border: 1px solid rgba(120, 100, 255, 70);
            border-radius: 14px;
            padding: 6px;
        }
        QHeaderView::section {
            background: rgba(10, 14, 28, 220);
            border: 0px;
            padding: 6px 8px;
            color: rgba(210, 225, 255, 210);
            font-weight: 700;
        }
        QTableWidget::item {
            padding: 8px;
            border: 0px;
        }
        QScrollBar:vertical {
            background: rgba(6, 9, 18, 0);
            width: 12px;
            margin: 8px 4px 8px 4px;
        }
        QScrollBar::handle:vertical {
            background: rgba(120, 100, 255, 120);
            border-radius: 6px;
            min-height: 20px;
        }
        QScrollBar::handle:vertical:hover {
            background: rgba(35, 210, 240, 160);
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: rgba(0,0,0,0); }
        #ProgressBar {
            background: rgba(6, 9, 18, 170);
            border: 1px solid rgba(120, 100, 255, 70);
            border-radius: 10px;
        }
        QProgressBar::chunk {
            background: rgba(35, 210, 240, 220);
            border-radius: 10px;
        }
        """
        self.setStyleSheet(qss)

    def _set_running(self, running: bool) -> None:
        self.run_btn.setEnabled(not running)
        self.keep_cb.setEnabled(not running)
        if running:
            self.status_pill.setText("Running")
            self.progress.setRange(0, 0)
            self.progress.setValue(0)
        else:
            self.progress.setRange(0, 1)
            self.progress.setValue(1)

    def _append_log(self, line: str) -> None:
        if line is None:
            return
        self.log.appendPlainText(line)

    def _clear_results(self) -> None:
        for i in range(5):
            self.table.item(i, 0).setText("")
            self.table.item(i, 1).setText("")

    def _populate_results(self, steps: List[Tuple[str, bool]]) -> None:
        self._clear_results()
        for i, (label, val) in enumerate(steps[:5]):
            self.table.item(i, 0).setText(label)
            self.table.item(i, 1).setText("True" if val else "False")

    @QtCore.Slot()
    def _on_run(self) -> None:
        self._last_workdir = ""
        self.open_btn.setEnabled(False)
        self.workdir_label.setText("")
        self._clear_results()
        self._set_running(True)
        self._append_log("")
        self._append_log("=== Run started at %s ===" % time.strftime("%Y-%m-%d %H:%M:%S"))
        self._append_log("")

        worker = DemoWorker(self.keep_cb.isChecked())
        thread = QtCore.QThread(self)
        self._thread = thread
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.log_line.connect(self._append_log)
        worker.finished.connect(self._on_finished)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        thread.start()

    @QtCore.Slot(object)
    def _on_finished(self, res_obj: object) -> None:
        res = res_obj  # type: ignore
        self._set_running(False)
        ok = bool(getattr(res, "ok", False))
        self.status_pill.setText("OK" if ok else "Error")

        workdir = str(getattr(res, "workdir", "") or "")
        self._last_workdir = workdir
        if workdir:
            self.workdir_label.setText(workdir)
            self.open_btn.setEnabled(True)

        steps = list(getattr(res, "steps", []) or [])
        self._populate_results(steps)

        self._append_log("")
        self._append_log("=== Run finished: %s ===" % ("OK" if ok else "ERROR"))

    @QtCore.Slot()
    def _on_open_workdir(self) -> None:
        if self._last_workdir:
            open_in_file_manager(self._last_workdir)

    @QtCore.Slot()
    def _on_copy_log(self) -> None:
        QtWidgets.QApplication.clipboard().setText(self.log.toPlainText())

    @QtCore.Slot()
    def _on_clear_log(self) -> None:
        self.log.clear()


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("Trusting Trust Galaxy Demo")
    w = MainWindow()
    w.show()
    return int(app.exec_() if hasattr(app, "exec_") else app.exec())


if __name__ == "__main__":
    raise SystemExit(main())