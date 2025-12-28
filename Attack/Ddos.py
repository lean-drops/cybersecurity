import http.client
import http.server
import socket
import threading
import time
import tkinter as tk
from collections import deque
from tkinter import ttk

LOCAL_HOST = "127.0.0.1"
PATH_WORK = "/work"
PATH_HEALTH = "/health"

class WindowMetrics:
    def __init__(self, window_s=10.0, max_events=200000):
        self._lock = threading.Lock()
        self._window_s = float(window_s)
        self._events = deque()
        self._max_events = int(max_events)

    def add(self, ok, status_code, latency_s):
        now = time.time()
        with self._lock:
            self._events.append((now, bool(ok), int(status_code), float(latency_s)))
            while len(self._events) > self._max_events:
                self._events.popleft()
            self._trim_locked(now)

    def snapshot(self):
        now = time.time()
        with self._lock:
            self._trim_locked(now)
            events = list(self._events)
        return self._compute(events, self._window_s)

    def _trim_locked(self, now):
        cutoff = now - self._window_s
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    @staticmethod
    def _percentile(sorted_vals, p):
        if not sorted_vals:
            return 0.0
        if p <= 0:
            return float(sorted_vals[0])
        if p >= 100:
            return float(sorted_vals[-1])
        idx = int(round((p / 100.0) * (len(sorted_vals) - 1)))
        idx = max(0, min(len(sorted_vals) - 1, idx))
        return float(sorted_vals[idx])

    def _compute(self, events, window_s):
        n = len(events)
        rps = n / window_s if window_s > 0 else 0.0
        ok_lat = []
        status_counts = {}
        ok_count = 0
        for _t, ok, sc, lat in events:
            status_counts[sc] = status_counts.get(sc, 0) + 1
            if ok:
                ok_count += 1
                ok_lat.append(lat)
        err_count = n - ok_count
        err_rate = (err_count / n) * 100.0 if n else 0.0
        ok_lat.sort()
        avg = (sum(ok_lat) / len(ok_lat)) if ok_lat else 0.0
        p50 = self._percentile(ok_lat, 50)
        p95 = self._percentile(ok_lat, 95)
        p99 = self._percentile(ok_lat, 99)
        mx = ok_lat[-1] if ok_lat else 0.0
        return {
            "n": n, "rps": rps, "ok": ok_count, "err": err_count, "err_rate": err_rate,
            "avg": avg, "p50": p50, "p95": p95, "p99": p99, "max": mx,
            "status_counts": status_counts,
        }

class ServerState:
    def __init__(self):
        self._lock = threading.Lock()
        self.workers = 20
        self.reserved_for_legit = 0
        self.work_ms = 50
        self.in_use = 0
        self.total_200 = 0
        self.total_503 = 0
        self.total_other = 0
        self.window = WindowMetrics(window_s=10.0)

    def configure(self, workers, reserved_for_legit, work_ms):
        with self._lock:
            self.workers = int(max(1, workers))
            self.reserved_for_legit = int(max(0, min(reserved_for_legit, self.workers)))
            self.work_ms = int(max(0, work_ms))

    def try_acquire(self, client_type):
        with self._lock:
            workers = self.workers
            reserved = self.reserved_for_legit
            if client_type == "attack":
                if self.in_use >= max(0, workers - reserved):
                    return False
            else:
                if self.in_use >= workers:
                    return False
            self.in_use += 1
            return True

    def release(self):
        with self._lock:
            if self.in_use > 0:
                self.in_use -= 1

    def record(self, status_code, latency_s):
        ok = (status_code == 200)
        self.window.add(ok=ok, status_code=status_code, latency_s=latency_s)
        with self._lock:
            if status_code == 200:
                self.total_200 += 1
            elif status_code == 503:
                self.total_503 += 1
            else:
                self.total_other += 1

    def snapshot(self):
        w = self.window.snapshot()
        with self._lock:
            return {
                "workers": self.workers,
                "reserved_for_legit": self.reserved_for_legit,
                "work_ms": self.work_ms,
                "in_use": self.in_use,
                "total_200": self.total_200,
                "total_503": self.total_503,
                "total_other": self.total_other,
                "window": w,
            }

class DemoHandler(http.server.BaseHTTPRequestHandler):
    server_version = "DemoHTTP/1.0"

    def log_message(self, fmt, *args):
        return

    def _send_text(self, code, body):
        body_b = body.encode("utf-8", errors="replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body_b)))
        self.end_headers()
        self.wfile.write(body_b)

    def do_GET(self):
        st = self.server.state
        if self.path.startswith(PATH_HEALTH):
            self._send_text(200, "ok\n")
            return
        if not self.path.startswith(PATH_WORK):
            self._send_text(404, "not found\n")
            return

        client_type = self.headers.get("X-Client", "legit").strip().lower()
        if client_type not in ("legit", "attack"):
            client_type = "legit"

        t0 = time.time()
        acquired = st.try_acquire(client_type)
        if not acquired:
            st.record(503, time.time() - t0)
            self._send_text(503, "busy\n")
            return

        try:
            snap = st.snapshot()
            work_ms = snap["work_ms"]
            if work_ms > 0:
                time.sleep(work_ms / 1000.0)
            st.record(200, time.time() - t0)
            self._send_text(200, "done\n")
        except Exception:
            st.record(500, time.time() - t0)
            self._send_text(500, "error\n")
        finally:
            st.release()

class LocalHTTPServer:
    def __init__(self):
        self.state = ServerState()
        self._httpd = None
        self._thread = None
        self.port = None

    def start(self, port=0):
        if self._httpd is not None:
            return
        class _ThreadingHTTPServer(http.server.ThreadingHTTPServer):
            daemon_threads = True
        httpd = _ThreadingHTTPServer((LOCAL_HOST, int(port)), DemoHandler)
        httpd.state = self.state
        self._httpd = httpd
        self.port = httpd.server_address[1]

        def _run():
            try:
                httpd.serve_forever(poll_interval=0.2)
            except Exception:
                pass

        th = threading.Thread(target=_run, daemon=True)
        self._thread = th
        th.start()

    def stop(self):
        if self._httpd is None:
            return
        try:
            self._httpd.shutdown()
        except Exception:
            pass
        try:
            self._httpd.server_close()
        except Exception:
            pass
        self._httpd = None
        self._thread = None
        self.port = None

    def is_running(self):
        return self._httpd is not None

class TrafficRunner:
    def __init__(self, server: LocalHTTPServer):
        self.server = server
        self._lock = threading.Lock()
        self._running = False
        self.legit_rps = 5.0
        self.attack_rps = 0.0
        self.timeout_s = 1.0
        self.legit_metrics = WindowMetrics(window_s=10.0)
        self.attack_metrics = WindowMetrics(window_s=10.0)
        self._threads = []
        self._num_threads = 20

    def start(self):
        if self._running:
            return
        self._running = True
        self._threads = []
        for i in range(self._num_threads):
            self._threads.append(threading.Thread(target=self._worker, args=("legit", i), daemon=True))
            self._threads.append(threading.Thread(target=self._worker, args=("attack", i), daemon=True))
        for th in self._threads:
            th.start()

    def stop(self):
        self._running = False

    def set_rates(self, legit_rps, attack_rps):
        with self._lock:
            self.legit_rps = max(0.0, float(legit_rps))
            self.attack_rps = max(0.0, float(attack_rps))

    def _get_rate(self, typ):
        with self._lock:
            return self.legit_rps if typ == "legit" else self.attack_rps

    def _do_request(self, typ):
        if not self.server.is_running() or self.server.port is None:
            return False, 0, 0.0
        host = LOCAL_HOST
        port = int(self.server.port)
        t0 = time.time()
        try:
            conn = http.client.HTTPConnection(host, port, timeout=self.timeout_s)
            conn.request("GET", PATH_WORK, headers={"X-Client": typ})
            resp = conn.getresponse()
            _ = resp.read()
            sc = int(resp.status)
            conn.close()
            return (sc == 200), sc, time.time() - t0
        except (socket.timeout, TimeoutError):
            return False, 408, time.time() - t0
        except Exception:
            return False, 599, time.time() - t0

    def _worker(self, typ, idx):
        jitter = (idx % 10) * 0.001
        time.sleep(jitter)
        next_t = time.time()
        while self._running:
            rate = self._get_rate(typ)
            if rate <= 0.0:
                time.sleep(0.1)
                next_t = time.time()
                continue
            per_thread_rate = rate / float(self._num_threads)
            if per_thread_rate <= 0.0:
                time.sleep(0.1)
                next_t = time.time()
                continue
            interval = 1.0 / per_thread_rate
            ok, sc, lat = self._do_request(typ)
            if typ == "legit":
                self.legit_metrics.add(ok, sc, lat)
            else:
                self.attack_metrics.add(ok, sc, lat)
            next_t += interval
            sleep_s = next_t - time.time()
            if sleep_s > 0:
                time.sleep(min(sleep_s, 0.5))
            else:
                time.sleep(0.001)

    def snapshot(self):
        return {
            "legit": self.legit_metrics.snapshot(),
            "attack": self.attack_metrics.snapshot(),
        }

class App:
    def __init__(self, root):
        self.root = root
        root.title("Local DoS/DDoS Effect Demo (localhost only)")
        self.server = LocalHTTPServer()
        self.traffic = TrafficRunner(self.server)
        self.var_workers = tk.IntVar(value=20)
        self.var_reserved = tk.IntVar(value=0)
        self.var_work_ms = tk.IntVar(value=50)
        self.var_legit_rps = tk.DoubleVar(value=5.0)
        self.var_attack_rps = tk.DoubleVar(value=0.0)
        self._build_ui()
        self._ui_tick()
        root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        top = ttk.Frame(main)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(3, weight=1)

        self.lbl_server = ttk.Label(top, text="Server: stopped")
        self.lbl_server.grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.btn_server = ttk.Button(top, text="Start server", command=self._toggle_server)
        self.btn_server.grid(row=0, column=1, sticky="w", padx=(0, 10))
        self.btn_traffic = ttk.Button(top, text="Start traffic", command=self._toggle_traffic)
        self.btn_traffic.grid(row=0, column=2, sticky="w", padx=(0, 10))
        self.lbl_note = ttk.Label(top, text="Target hardcoded to 127.0.0.1 only")
        self.lbl_note.grid(row=0, column=3, sticky="e")

        mid = ttk.Frame(main)
        mid.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        mid.columnconfigure(0, weight=1)
        mid.columnconfigure(1, weight=1)

        srv = ttk.Labelframe(mid, text="Server parameters", padding=10)
        srv.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        self._add_scale(srv, 0, "Workers (capacity)", self.var_workers, 1, 200, self._on_server_param)
        self._add_scale(srv, 1, "Reserved for legit (mitigation)", self.var_reserved, 0, 200, self._on_server_param)
        self._add_scale(srv, 2, "Work per request (ms)", self.var_work_ms, 0, 200, self._on_server_param)

        traf = ttk.Labelframe(mid, text="Traffic parameters", padding=10)
        traf.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        self._add_scale(traf, 0, "Legit RPS", self.var_legit_rps, 0, 200, self._on_traffic_param)
        self._add_scale(traf, 1, "Attack RPS", self.var_attack_rps, 0, 500, self._on_traffic_param)

        bot = ttk.Frame(main)
        bot.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        bot.columnconfigure(0, weight=1)
        bot.rowconfigure(1, weight=1)

        self.lbl_metrics = ttk.Label(bot, text="", justify="left")
        self.lbl_metrics.grid(row=0, column=0, sticky="w")
        self.text = tk.Text(bot, height=14, wrap="none")
        self.text.grid(row=1, column=0, sticky="nsew")
        sy = ttk.Scrollbar(bot, orient="vertical", command=self.text.yview)
        sy.grid(row=1, column=1, sticky="ns")
        self.text.configure(yscrollcommand=sy.set)

        self._log("How to use:\n- Start server\n- Start traffic\n- Increase Attack RPS; watch 503 + latency\n- Increase Reserved for legit to protect legit traffic\n")

    def _add_scale(self, parent, row, label, var, mn, mx, cmd):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w")
        sc = ttk.Scale(parent, from_=mn, to=mx, orient="horizontal", variable=var, command=lambda _e: cmd())
        sc.grid(row=row, column=1, sticky="ew", padx=(10, 0))
        parent.columnconfigure(1, weight=1)
        val = ttk.Label(parent, width=8, anchor="e")
        val.grid(row=row, column=2, sticky="e", padx=(10, 0))

        def _update_val():
            try:
                if isinstance(var, tk.IntVar):
                    val.configure(text=str(int(var.get())))
                else:
                    val.configure(text="%.1f" % float(var.get()))
            except Exception:
                pass
            self.root.after(200, _update_val)
        _update_val()

    def _log(self, msg):
        self.text.insert("end", msg)
        self.text.see("end")

    def _toggle_server(self):
        if self.server.is_running():
            self.server.stop()
            self._log("Server stopped.\n")
        else:
            self.server.start(port=0)
            self._log(f"Server started on {LOCAL_HOST}:{int(self.server.port or 0)}\n")
        self._apply_server_params()

    def _toggle_traffic(self):
        if self.traffic._running:
            self.traffic.stop()
            self._log("Traffic stopped.\n")
        else:
            if not self.server.is_running():
                self._log("Start server first.\n")
                return
            self.traffic.start()
            self._log("Traffic started.\n")
        self._apply_traffic_params()

    def _on_server_param(self):
        self._apply_server_params()

    def _on_traffic_param(self):
        self._apply_traffic_params()

    def _apply_server_params(self):
        workers = int(self.var_workers.get())
        reserved = int(self.var_reserved.get())
        work_ms = int(self.var_work_ms.get())
        if reserved > workers:
            reserved = workers
            self.var_reserved.set(reserved)
        self.server.state.configure(workers=workers, reserved_for_legit=reserved, work_ms=work_ms)

    def _apply_traffic_params(self):
        self.traffic.set_rates(self.var_legit_rps.get(), self.var_attack_rps.get())

    def _ui_tick(self):
        if self.server.is_running():
            self.lbl_server.configure(text=f"Server: running on {LOCAL_HOST}:{int(self.server.port or 0)}")
            self.btn_server.configure(text="Stop server")
        else:
            self.lbl_server.configure(text="Server: stopped")
            self.btn_server.configure(text="Start server")

        if self.traffic._running:
            self.btn_traffic.configure(text="Stop traffic")
        else:
            self.btn_traffic.configure(text="Start traffic")

        srv = self.server.state.snapshot()
        traf = self.traffic.snapshot()
        m_leg = traf["legit"]
        m_att = traf["attack"]
        m_srv = srv["window"]

        def fmt(m):
            return f"rps={m['rps']:.1f} ok={m['ok']} err={m['err']} err%={m['err_rate']:.1f} avg={m['avg']:.3f}s p95={m['p95']:.3f}s"

        s = []
        s.append(f"Server: workers={srv['workers']} reserved={srv['reserved_for_legit']} work_ms={srv['work_ms']} in_use={srv['in_use']}")
        s.append("Server(window 10s): " + fmt(m_srv) + " statuses=" + str(m_srv["status_counts"]))
        s.append("Legit (window 10s):   " + fmt(m_leg) + " statuses=" + str(m_leg["status_counts"]))
        s.append("Attack(window 10s):  " + fmt(m_att) + " statuses=" + str(m_att["status_counts"]))
        s.append(f"Totals: 200={srv['total_200']} 503={srv['total_503']} other={srv['total_other']}")

        self.lbl_metrics.configure(text="\n".join(s))
        self.root.after(500, self._ui_tick)

    def _on_close(self):
        try:
            self.traffic.stop()
        except Exception:
            pass
        try:
            self.server.stop()
        except Exception:
            pass
        self.root.destroy()

def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()