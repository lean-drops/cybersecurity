# privacy_audit_gui.py
import os
import platform
import socket
import subprocess
import threading
import time
import tkinter as tk
import urllib.request
import webbrowser
from tkinter import ttk


LOCAL_HOST = "127.0.0.1"
IPV4_ECHO_URL = "https://api.ipify.org"
IPV6_ECHO_URL = "https://api64.ipify.org"


def _run_cmd(cmd_list, timeout_s=3):
    try:
        p = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
        return out.strip()
    except Exception as e:
        return "ERROR running %r: %s" % (cmd_list, str(e))


def _read_text_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except Exception as e:
        return "ERROR reading %s: %s" % (path, str(e))


def _get_local_ip_guess():
    # No packets are sent for UDP connect; it just selects a route.
    ip4 = ""
    ip6 = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip4 = s.getsockname()[0]
        s.close()
    except Exception:
        ip4 = ""

    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2001:4860:4860::8888", 80, 0, 0))
        ip6 = s.getsockname()[0]
        s.close()
    except Exception:
        ip6 = ""

    return ip4, ip6


def _get_all_host_ips():
    ips = set()
    try:
        host = socket.gethostname()
        for fam, _t, _p, _c, sa in socket.getaddrinfo(host, None):
            if fam == socket.AF_INET:
                ips.add(sa[0])
            elif fam == socket.AF_INET6:
                ips.add(sa[0])
    except Exception:
        pass
    return sorted(ips)


def _fetch_url_text(url, timeout_s=3):
    req = urllib.request.Request(url, headers={"User-Agent": "privacy-audit-demo/1.0"})
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        data = resp.read()
    return data.decode("utf-8", errors="replace").strip()


def _detect_vpn_hints(text_blob):
    blob = (text_blob or "").lower()
    hints = []
    keywords = [
        "nord",
        "nordlynx",
        "wireguard",
        "wg",
        "openvpn",
        "tun",
        "tap",
        "ppp",
        "utun",
        "tailscale",
        "zerotier",
    ]
    for k in keywords:
        if k in blob:
            hints.append(k)
    # de-dup preserving order
    seen = set()
    out = []
    for h in hints:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _collect_network_details():
    sysname = platform.system().strip()
    details = []
    details.append("OS: %s %s" % (sysname, platform.version()))
    details.append("Platform: %s" % platform.platform())
    details.append("Machine: %s" % platform.machine())
    details.append("Python: %s" % platform.python_version())
    details.append("Time: %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    details.append("Hostname: %s" % socket.gethostname())
    details.append("")

    ip4_guess, ip6_guess = _get_local_ip_guess()
    details.append("Local IP guess (outbound route):")
    details.append("  IPv4: %s" % (ip4_guess or "(unknown)"))
    details.append("  IPv6: %s" % (ip6_guess or "(unknown)"))
    details.append("")

    details.append("All host IPs (getaddrinfo):")
    for ip in _get_all_host_ips():
        details.append("  %s" % ip)
    if not _get_all_host_ips():
        details.append("  (none found)")
    details.append("")

    raw = ""

    if sysname == "Windows":
        raw_ipconfig = _run_cmd(["ipconfig", "/all"], timeout_s=5)
        raw_getmac = _run_cmd(["getmac", "/v", "/fo", "list"], timeout_s=5)
        raw_route = _run_cmd(["route", "print", "-4"], timeout_s=5)
        raw_route6 = _run_cmd(["route", "print", "-6"], timeout_s=5)
        raw = "\n\n".join(
            [
                "=== ipconfig /all ===",
                raw_ipconfig,
                "=== getmac /v /fo list ===",
                raw_getmac,
                "=== route print -4 ===",
                raw_route,
                "=== route print -6 ===",
                raw_route6,
            ]
        )
        details.append(raw)

    else:
        # Unix-like
        raw_ifconfig = _run_cmd(["ifconfig"], timeout_s=5)
        raw_ip_addr = _run_cmd(["ip", "-o", "addr"], timeout_s=5)
        raw_ip_link = _run_cmd(["ip", "link"], timeout_s=5)
        raw_route = _run_cmd(["netstat", "-rn"], timeout_s=5)
        resolv = _read_text_file("/etc/resolv.conf")
        sys_class = ""
        if os.path.isdir("/sys/class/net"):
            sys_class_lines = ["=== /sys/class/net/* ==="]
            try:
                for name in sorted(os.listdir("/sys/class/net")):
                    addr_path = "/sys/class/net/%s/address" % name
                    state_path = "/sys/class/net/%s/operstate" % name
                    mac = _read_text_file(addr_path)
                    st = _read_text_file(state_path)
                    sys_class_lines.append("  %s  mac=%s  state=%s" % (name, mac, st))
            except Exception as e:
                sys_class_lines.append("  ERROR: %s" % str(e))
            sys_class = "\n".join(sys_class_lines)

        raw = "\n\n".join(
            [
                "=== ifconfig ===",
                raw_ifconfig,
                "=== ip -o addr ===",
                raw_ip_addr,
                "=== ip link ===",
                raw_ip_link,
                "=== netstat -rn ===",
                raw_route,
                "=== /etc/resolv.conf ===",
                resolv,
                sys_class,
            ]
        )
        details.append(raw)

    vpn_hints = _detect_vpn_hints(raw)
    details.append("")
    details.append("VPN interface/name hints found in output: %s" % (", ".join(vpn_hints) if vpn_hints else "(none)"))
    details.append("Note: This is heuristic; it does not prove VPN is active.")
    details.append("")

    details.append("Leak checklist (manual):")
    details.append("  - Public IP shows VPN exit? (use buttons below)")
    details.append("  - DNS servers appear to be VPN-provided (resolv.conf / ipconfig)?")
    details.append("  - IPv6: if your VPN does not tunnel IPv6, it may leak.")
    details.append("  - Browser leaks: WebRTC can expose local IPs; disable/mitigate in browser settings.")
    details.append("")

    return "\n".join(details)


class App:
    def __init__(self, root):
        self.root = root
        root.title("Privacy / VPN Leak Audit (read-only)")

        main = ttk.Frame(root, padding=10)
        main.grid(row=0, column=0, sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(2, weight=1)

        row0 = ttk.Frame(main)
        row0.grid(row=0, column=0, sticky="ew")
        row0.columnconfigure(6, weight=1)

        self.btn_refresh = ttk.Button(row0, text="Refresh local report", command=self.refresh_report)
        self.btn_refresh.grid(row=0, column=0, padx=(0, 8), sticky="w")

        self.btn_ipv4 = ttk.Button(row0, text="Fetch public IPv4", command=lambda: self.fetch_public(IPV4_ECHO_URL))
        self.btn_ipv4.grid(row=0, column=1, padx=(0, 8), sticky="w")

        self.btn_ipv6 = ttk.Button(row0, text="Fetch public IPv6", command=lambda: self.fetch_public(IPV6_ECHO_URL))
        self.btn_ipv6.grid(row=0, column=2, padx=(0, 8), sticky="w")

        self.btn_dns_test = ttk.Button(row0, text="Open DNS leak test page", command=self.open_dns_test)
        self.btn_dns_test.grid(row=0, column=3, padx=(0, 8), sticky="w")

        self.btn_copy = ttk.Button(row0, text="Copy report", command=self.copy_report)
        self.btn_copy.grid(row=0, column=4, padx=(0, 8), sticky="w")

        self.status = ttk.Label(row0, text="Read-only tool. No system changes.")
        self.status.grid(row=0, column=5, sticky="w")

        sep = ttk.Separator(main, orient="horizontal")
        sep.grid(row=1, column=0, sticky="ew", pady=(8, 8))

        self.text = tk.Text(main, wrap="none", height=28)
        self.text.grid(row=2, column=0, sticky="nsew")

        sy = ttk.Scrollbar(main, orient="vertical", command=self.text.yview)
        sy.grid(row=2, column=1, sticky="ns")
        self.text.configure(yscrollcommand=sy.set)

        sx = ttk.Scrollbar(main, orient="horizontal", command=self.text.xview)
        sx.grid(row=3, column=0, sticky="ew")
        self.text.configure(xscrollcommand=sx.set)

        self.refresh_report()

    def _set_status(self, msg):
        self.status.configure(text=msg)

    def refresh_report(self):
        self._set_status("Collecting local info...")
        self.btn_refresh.configure(state="disabled")
        self.text.delete("1.0", "end")

        def work():
            rep = _collect_network_details()

            def done():
                self.text.insert("end", rep + "\n")
                self.btn_refresh.configure(state="normal")
                self._set_status("Local report updated.")

            self.root.after(0, done)

        threading.Thread(target=work, daemon=True).start()

    def fetch_public(self, url):
        self._set_status("Fetching %s ..." % url)
        self.btn_ipv4.configure(state="disabled")
        self.btn_ipv6.configure(state="disabled")

        def work():
            try:
                val = _fetch_url_text(url, timeout_s=4)
                line = "Public via %s: %s" % (url, val)
            except Exception as e:
                line = "Public via %s: ERROR: %s" % (url, str(e))

            def done():
                self.text.insert("end", line + "\n")
                self.text.see("end")
                self.btn_ipv4.configure(state="normal")
                self.btn_ipv6.configure(state="normal")
                self._set_status("Done.")

            self.root.after(0, done)

        threading.Thread(target=work, daemon=True).start()

    def open_dns_test(self):
        # This opens a browser page; still read-only from this tool.
        try:
            webbrowser.open("https://nordvpn.com/dns-leak-test/", new=2)
            self._set_status("Opened DNS leak test in browser.")
        except Exception as e:
            self._set_status("ERROR opening browser: %s" % str(e))

    def copy_report(self):
        try:
            txt = self.text.get("1.0", "end")
            self.root.clipboard_clear()
            self.root.clipboard_append(txt)
            self._set_status("Copied to clipboard.")
        except Exception as e:
            self._set_status("ERROR copying: %s" % str(e))


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