import tkinter as tk
from tkinter import ttk, messagebox
import asyncio
import ipaddress
import time
import ssl
import threading
import re


BG_ROOT = "#07090F"
BG_SURFACE = "#0D1117"
BG_ELEVATED = "#111820"
BG_INPUT = "#0A0E16"
BG_ROW_ODD = "#0D1117"
BG_ROW_EVEN = "#111820"

BORDER = "#1C2333"
BORDER_FOCUS = "#2A3A55"

ACCENT = "#00D9FF"
ACCENT_DIM = "#0099BB"

GREEN = "#00E5A0"
AMBER = "#FFB547"
RED = "#FF4D6A"

TEXT_PRIMARY = "#E8EDF5"
TEXT_SECOND = "#8896A8"
TEXT_DIM = "#3D4D5E"
TEXT_CODE = "#A8C4D4"


class SNIChecker:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SNI Spoof Checker")
        self.root.configure(bg=BG_ROOT)
        self._center_window(1080, 780)

        self.is_scanning = False
        self.valid_ips = []
        self.total_checked = 0
        self.worker_tasks = []
        self._scan_tasks = []
        self._scan_loop = None
        self._scan_thread = None
        self._stop_event = threading.Event()
        self._anim_step = 0
        self._dot_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self._pulse_colors = [ACCENT, "#00BBDD", "#0099CC", "#00BBDD"]
        self._pulse_i = 0

        self._build_styles()
        self._build_ui()

    def _center_window(self, w: int, h: int):
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")
        self.root.minsize(860, 620)

    def _font(self, size=10, weight="normal", mono=False):
        family = "Consolas" if mono else "Segoe UI"
        return (family, size, weight)

    def _build_styles(self):
        s = ttk.Style()
        s.theme_use("clam")

        s.configure(
            ".",
            background=BG_SURFACE,
            foreground=TEXT_PRIMARY,
            troughcolor=BG_ELEVATED,
            selectbackground=ACCENT,
            selectforeground=BG_ROOT,
        )

        s.configure(
            "Results.Treeview",
            background=BG_SURFACE,
            foreground=TEXT_PRIMARY,
            fieldbackground=BG_SURFACE,
            rowheight=36,
            borderwidth=0,
            font=self._font(10, mono=True),
        )
        s.configure(
            "Results.Treeview.Heading",
            background=BG_ELEVATED,
            foreground=TEXT_SECOND,
            font=self._font(9, "bold"),
            borderwidth=0,
            relief="flat",
            padding=(8, 6),
        )
        s.map(
            "Results.Treeview",
            background=[("selected", "#162035")],
            foreground=[("selected", ACCENT)],
        )
        s.map(
            "Results.Treeview.Heading",
            background=[("active", BG_ELEVATED)],
        )

        s.configure(
            "Thin.Vertical.TScrollbar",
            background=BG_ELEVATED,
            troughcolor=BG_SURFACE,
            borderwidth=0,
            arrowsize=0,
            width=6,
        )
        s.map(
            "Thin.Vertical.TScrollbar",
            background=[("active", BORDER_FOCUS)],
        )

        s.configure(
            "Horizontal.TProgressbar",
            thickness=3,
            troughcolor=BORDER,
            background=ACCENT,
            borderwidth=0,
        )

    def _build_ui(self):
        outer = tk.Frame(self.root, bg=BG_ROOT)
        outer.pack(fill=tk.BOTH, expand=True, padx=24, pady=20)

        self._build_header(outer)
        self._build_stat_cards(outer)
        self._build_config_row(outer)
        self._build_inputs_row(outer)
        self._build_controls_row(outer)
        self._build_pbar(outer)
        self._build_results(outer)

    def _build_header(self, parent):
        hf = tk.Frame(parent, bg=BG_ROOT)
        hf.pack(fill=tk.X, pady=(0, 20))

        left = tk.Frame(hf, bg=BG_ROOT)
        left.pack(side=tk.LEFT)

        bar = tk.Frame(left, bg=ACCENT, width=4, height=38)
        bar.pack(side=tk.LEFT, padx=(0, 12))
        bar.pack_propagate(False)

        title_block = tk.Frame(left, bg=BG_ROOT)
        title_block.pack(side=tk.LEFT)

        tk.Label(
            title_block,
            text="SNI Spoof Checker",
            font=self._font(20, "bold"),
            fg=TEXT_PRIMARY,
            bg=BG_ROOT,
        ).pack(anchor=tk.W)

        tk.Label(
            title_block,
            text="TLS / SSL  ·  Port 443  ·  Async Scanner",
            font=self._font(9),
            fg=TEXT_DIM,
            bg=BG_ROOT,
        ).pack(anchor=tk.W, pady=(1, 0))

        right = tk.Frame(hf, bg=BG_ROOT)
        right.pack(side=tk.RIGHT, anchor=tk.CENTER)
        badge = tk.Label(
            right,
            text="  v2.0  ",
            font=self._font(8, "bold"),
            fg=ACCENT_DIM,
            bg=BG_ELEVATED,
            relief=tk.FLAT,
            padx=4,
            pady=3,
        )
        badge.pack()
        self._rounded_border(badge)

    def _build_stat_cards(self, parent):
        cf = tk.Frame(parent, bg=BG_ROOT)
        cf.pack(fill=tk.X, pady=(0, 18))
        cf.columnconfigure(0, weight=1)
        cf.columnconfigure(1, weight=1)
        cf.columnconfigure(2, weight=1)

        self.card_checked_val = self._stat_card(cf, "CHECKED", "0", TEXT_PRIMARY, 0)
        self.card_found_val = self._stat_card(cf, "FOUND", "0", GREEN, 1)
        self.card_status_val = self._stat_card(cf, "STATUS", "IDLE", TEXT_SECOND, 2)

    def _stat_card(self, parent, label, value, value_color, col):
        padx = (0, 10) if col < 2 else (10, 0)
        if col == 1:
            padx = (5, 5)

        card = tk.Frame(
            parent,
            bg=BG_SURFACE,
            highlightbackground=BORDER,
            highlightthickness=1,
        )
        card.grid(row=0, column=col, sticky=tk.EW, padx=padx)

        inner = tk.Frame(card, bg=BG_SURFACE, padx=16, pady=12)
        inner.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            inner,
            text=label,
            font=self._font(8, "bold"),
            fg=TEXT_DIM,
            bg=BG_SURFACE,
        ).pack(anchor=tk.W)

        val_lbl = tk.Label(
            inner,
            text=value,
            font=self._font(22, "bold", mono=True),
            fg=value_color,
            bg=BG_SURFACE,
        )
        val_lbl.pack(anchor=tk.W, pady=(2, 0))
        return val_lbl

    def _build_config_row(self, parent):
        outer = tk.Frame(
            parent,
            bg=BG_SURFACE,
            highlightbackground=BORDER,
            highlightthickness=1,
        )
        outer.pack(fill=tk.X, pady=(0, 12))

        inner = tk.Frame(outer, bg=BG_SURFACE, padx=16, pady=12)
        inner.pack(fill=tk.X)

        tk.Label(
            inner,
            text="CONFIGURATION",
            font=self._font(8, "bold"),
            fg=TEXT_DIM,
            bg=BG_SURFACE,
        ).pack(anchor=tk.W, pady=(0, 8))

        row = tk.Frame(inner, bg=BG_SURFACE)
        row.pack(fill=tk.X)

        self.timeout_entry = self._config_field(row, "Timeout (s)", "1.5", 0)
        self.concurrency_entry = self._config_field(row, "Concurrency", "150", 1)
        self.port_entry = self._config_field(row, "Port", "443", 2)

    def _config_field(self, parent, label, default, idx):
        f = tk.Frame(parent, bg=BG_SURFACE)
        f.grid(row=0, column=idx, sticky=tk.W, padx=(0, 32))

        tk.Label(
            f,
            text=label,
            font=self._font(9),
            fg=TEXT_SECOND,
            bg=BG_SURFACE,
        ).pack(anchor=tk.W)

        entry_wrap = tk.Frame(
            f,
            bg=BG_INPUT,
            highlightbackground=BORDER,
            highlightthickness=1,
        )
        entry_wrap.pack(anchor=tk.W, pady=(4, 0))

        e = tk.Entry(
            entry_wrap,
            bg=BG_INPUT,
            fg=TEXT_CODE,
            insertbackground=ACCENT,
            bd=0,
            width=12,
            font=self._font(11, mono=True),
            relief=tk.FLAT,
        )
        e.insert(0, default)
        e.pack(padx=8, pady=5)

        e.bind("<FocusIn>", lambda _: entry_wrap.config(highlightbackground=ACCENT_DIM))
        e.bind("<FocusOut>", lambda _: entry_wrap.config(highlightbackground=BORDER))
        return e

    def _build_inputs_row(self, parent):
        row = tk.Frame(parent, bg=BG_ROOT)
        row.pack(fill=tk.X, pady=(0, 12))
        row.columnconfigure(0, weight=1)
        row.columnconfigure(1, weight=1)

        self.subnet_text = self._text_panel(
            row,
            "IP SUBNETS",
            "104.19.229.0/24\n104.16.0.0/24",
            0,
            padx=(0, 6),
        )

        self.sni_text = self._text_panel(
            row,
            "SNI HOSTNAMES",
            "www.hcaptcha.com\nwww.cloudflare.com",
            1,
            padx=(6, 0),
        )

    def _text_panel(self, parent, title, placeholder, col, padx=(0, 0)):
        wrap = tk.Frame(
            parent,
            bg=BG_SURFACE,
            highlightbackground=BORDER,
            highlightthickness=1,
        )
        wrap.grid(row=0, column=col, sticky=tk.NSEW, padx=padx)

        header = tk.Frame(wrap, bg=BG_ELEVATED, padx=12, pady=8)
        header.pack(fill=tk.X)

        tk.Label(
            header,
            text=title,
            font=self._font(8, "bold"),
            fg=TEXT_DIM,
            bg=BG_ELEVATED,
        ).pack(side=tk.LEFT)

        body = tk.Frame(wrap, bg=BG_SURFACE, padx=2, pady=2)
        body.pack(fill=tk.BOTH, expand=True)

        txt = tk.Text(
            body,
            height=5,
            bg=BG_INPUT,
            fg=ACCENT,
            insertbackground=ACCENT,
            bd=0,
            font=self._font(10, mono=True),
            wrap=tk.WORD,
            padx=10,
            pady=8,
            relief=tk.FLAT,
            selectbackground="#162035",
            selectforeground=ACCENT,
        )
        txt.insert("1.0", placeholder)
        txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        return txt

    def _build_controls_row(self, parent):
        cf = tk.Frame(parent, bg=BG_ROOT)
        cf.pack(fill=tk.X, pady=(0, 10))

        self.start_btn = tk.Button(
            cf,
            text="  ▶  START SCAN  ",
            font=self._font(11, "bold"),
            bg=ACCENT,
            fg=BG_ROOT,
            activebackground="#33E5FF",
            activeforeground=BG_ROOT,
            bd=0,
            padx=16,
            pady=10,
            cursor="hand2",
            relief=tk.FLAT,
            command=self._toggle_scan,
        )
        self.start_btn.pack(side=tk.LEFT)

        self.clear_btn = tk.Button(
            cf,
            text="  ✕  CLEAR  ",
            font=self._font(10, "bold"),
            bg=BG_ELEVATED,
            fg=TEXT_SECOND,
            activebackground=BORDER_FOCUS,
            activeforeground=TEXT_PRIMARY,
            bd=0,
            padx=12,
            pady=10,
            cursor="hand2",
            relief=tk.FLAT,
            command=self._clear_results,
        )
        self.clear_btn.pack(side=tk.LEFT, padx=(10, 0))

        self.export_btn = tk.Button(
            cf,
            text="  ↓  EXPORT  ",
            font=self._font(10, "bold"),
            bg=BG_ELEVATED,
            fg=TEXT_SECOND,
            activebackground=BORDER_FOCUS,
            activeforeground=TEXT_PRIMARY,
            bd=0,
            padx=12,
            pady=10,
            cursor="hand2",
            relief=tk.FLAT,
            command=self._export_results,
        )
        self.export_btn.pack(side=tk.LEFT, padx=(8, 0))

        for btn, active_bg, default_bg in [
            (self.start_btn, "#33E5FF", ACCENT),
            (self.clear_btn, BORDER_FOCUS, BG_ELEVATED),
            (self.export_btn, BORDER_FOCUS, BG_ELEVATED),
        ]:
            btn.bind(
                "<Enter>",
                lambda e, b=btn, c=active_bg: b.config(bg=c)
                if not self.is_scanning or b is not self.start_btn
                else None,
            )
            btn.bind(
                "<Leave>",
                lambda e, b=btn, c=default_bg: b.config(bg=c)
                if not self.is_scanning or b is not self.start_btn
                else None,
            )

    def _build_pbar(self, parent):
        pf = tk.Frame(parent, bg=BG_ROOT)
        pf.pack(fill=tk.X, pady=(0, 10))

        self.pbar = ttk.Progressbar(
            pf,
            mode="indeterminate",
            style="Horizontal.TProgressbar",
        )
        self.pbar.pack(fill=tk.X)

    def _build_results(self, parent):
        wrap = tk.Frame(
            parent,
            bg=BG_SURFACE,
            highlightbackground=BORDER,
            highlightthickness=1,
        )
        wrap.pack(fill=tk.BOTH, expand=True)

        thead = tk.Frame(wrap, bg=BG_ELEVATED, padx=14, pady=9)
        thead.pack(fill=tk.X)

        tk.Label(
            thead,
            text="RESULTS",
            font=self._font(8, "bold"),
            fg=TEXT_DIM,
            bg=BG_ELEVATED,
        ).pack(side=tk.LEFT)

        self.results_count_lbl = tk.Label(
            thead,
            text="0 entries",
            font=self._font(8, mono=True),
            fg=TEXT_DIM,
            bg=BG_ELEVATED,
        )
        self.results_count_lbl.pack(side=tk.RIGHT)

        tree_frame = tk.Frame(wrap, bg=BG_SURFACE)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        cols = ("ip", "sni", "ping", "status")
        self.tree = ttk.Treeview(
            tree_frame,
            columns=cols,
            show="headings",
            style="Results.Treeview",
            selectmode="browse",
        )

        hdrs = {
            "ip": ("IP ADDRESS", 180, tk.CENTER),
            "sni": ("SNI HOSTNAME", 360, tk.W),
            "ping": ("LATENCY", 110, tk.CENTER),
            "status": ("STATUS", 110, tk.CENTER),
        }

        for col, (text, w, anchor) in hdrs.items():
            self.tree.heading(col, text=text)
            self.tree.column(col, width=w, anchor=anchor, stretch=(col == "sni"))

        self.tree.tag_configure("odd", background=BG_ROW_ODD)
        self.tree.tag_configure("even", background=BG_ROW_EVEN)
        self.tree.tag_configure("fast", foreground=GREEN)
        self.tree.tag_configure("medium", foreground=AMBER)
        self.tree.tag_configure("slow", foreground=RED)

        vsb = ttk.Scrollbar(
            tree_frame,
            orient=tk.VERTICAL,
            command=self.tree.yview,
            style="Thin.Vertical.TScrollbar",
        )
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y, padx=(2, 0))

    def _rounded_border(self, widget):
        widget.config(
            highlightbackground=ACCENT_DIM,
            highlightthickness=1,
        )

    def _toggle_scan(self):
        if self.is_scanning:
            self._stop_scan()
        else:
            self._start_scan()

    def _stop_scan(self):
        self._stop_event.set()
        self.is_scanning = False
        self.start_btn.config(
            state=tk.DISABLED,
            text="  ◼  STOPPING…  ",
            bg=BG_ELEVATED,
            fg=TEXT_SECOND,
        )
        self._update_status("STOPPING", RED)
        self.pbar.stop()

        if self._scan_loop is not None and self._scan_tasks:
            for task in list(self._scan_tasks):
                try:
                    self._scan_loop.call_soon_threadsafe(task.cancel)
                except Exception:
                    pass

    def _start_scan(self):
        subnets = [
            s.strip()
            for s in re.split(r"[\n\r,;]+", self.subnet_text.get("1.0", tk.END))
            if s.strip()
        ]
        snis = [
            s.strip()
            for s in re.split(r"[\n\r,;]+", self.sni_text.get("1.0", tk.END))
            if s.strip()
        ]

        if not subnets or not snis:
            messagebox.showwarning(
                "Missing Input",
                "Please supply at least one subnet and one SNI hostname.",
            )
            return

        try:
            timeout = float(self.timeout_entry.get())
            concurrency = int(self.concurrency_entry.get())
            port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror(
                "Invalid Config",
                "Timeout, Concurrency, and Port must be numeric values.",
            )
            return

        if concurrency < 1 or concurrency > 1000:
            messagebox.showerror("Invalid Config", "Concurrency must be between 1 and 1000.")
            return

        self._clear_results()
        self._stop_event.clear()
        self.is_scanning = True
        self.worker_tasks = []
        self._scan_tasks = []
        self._scan_loop = None
        self._anim_step = 0
        self._pulse_i = 0

        self.start_btn.config(
            text="  ◼  STOP SCAN  ",
            bg=RED,
            fg="#FFF",
            state=tk.NORMAL,
        )
        self.start_btn.bind("<Enter>", lambda e: self.start_btn.config(bg="#FF6680"))
        self.start_btn.bind("<Leave>", lambda e: self.start_btn.config(bg=RED))

        self.pbar.start(8)
        self._animate_status()

        self._scan_thread = threading.Thread(
            target=self._run_loop,
            args=(subnets, snis, timeout, concurrency, port),
            daemon=True,
        )
        self._scan_thread.start()

    def _run_loop(self, subnets, snis, timeout, concurrency, port):
        loop = asyncio.new_event_loop()
        self._scan_loop = loop
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(
                self._scanner(subnets, snis, timeout, concurrency, port)
            )
        except asyncio.CancelledError:
            pass
        finally:
            try:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
            except Exception:
                pass
            loop.close()
            self._scan_loop = None
            self.is_scanning = False
            self.root.after(0, self._on_scan_finished)

    def _on_scan_finished(self):
        self.pbar.stop()
        self.start_btn.config(
            state=tk.NORMAL,
            text="  ▶  START SCAN  ",
            bg=ACCENT,
            fg=BG_ROOT,
        )
        self.start_btn.bind("<Enter>", lambda e: self.start_btn.config(bg="#33E5FF"))
        self.start_btn.bind("<Leave>", lambda e: self.start_btn.config(bg=ACCENT))

        if self.valid_ips:
            self.valid_ips.sort(key=lambda x: x[2])
            if self._stop_event.is_set():
                self._update_status(f"STOPPED — {len(self.valid_ips)} FOUND", AMBER)
            else:
                self._update_status(f"DONE — {len(self.valid_ips)} FOUND", GREEN)
                try:
                    with open("working_tls_ips.txt", "w", encoding="utf-8") as f:
                        for ip, sni, ping in self.valid_ips:
                            f.write(f"{ip} | {sni} | {ping}ms\n")
                except OSError:
                    pass
        else:
            if self._stop_event.is_set():
                self._update_status("STOPPED", RED)
            else:
                self._update_status("DONE — NONE FOUND", AMBER)

    async def _scanner(self, subnets, snis, timeout, concurrency, port):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        queue = asyncio.Queue(maxsize=concurrency * 2)

        async def producer():
            try:
                for subnet_str in subnets:
                    if self._stop_event.is_set():
                        break
                    try:
                        net = ipaddress.IPv4Network(subnet_str, strict=False)
                    except ValueError:
                        continue

                    for ip in net.hosts():
                        if self._stop_event.is_set():
                            break
                        for sni in snis:
                            if self._stop_event.is_set():
                                break
                            await queue.put((str(ip), sni))
                    if self._stop_event.is_set():
                        break
            finally:
                for _ in range(concurrency):
                    try:
                        queue.put_nowait(None)
                    except asyncio.QueueFull:
                        await queue.put(None)

        async def worker():
            while True:
                if self._stop_event.is_set() and queue.empty():
                    break

                try:
                    item = await asyncio.wait_for(queue.get(), timeout=0.25)
                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    break

                try:
                    if item is None:
                        break

                    ip, sni = item
                    self.root.after(0, self._inc_checked)

                    writer = None
                    try:
                        t0 = time.time()
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(
                                ip,
                                port,
                                ssl=ctx,
                                server_hostname=sni,
                            ),
                            timeout=timeout,
                        )
                        ping = int((time.time() - t0) * 1000)
                        self.valid_ips.append((ip, sni, ping))
                        self.root.after(
                            0,
                            lambda _ip=ip, _sni=sni, _p=ping: self._log_result(
                                _ip, _sni, _p
                            ),
                        )
                    except Exception:
                        pass
                    finally:
                        if writer:
                            writer.close()
                            try:
                                await writer.wait_closed()
                            except Exception:
                                pass
                finally:
                    queue.task_done()

        prod_task = asyncio.create_task(producer())
        self.worker_tasks = [asyncio.create_task(worker()) for _ in range(concurrency)]
        self._scan_tasks = [prod_task, *self.worker_tasks]

        await asyncio.gather(prod_task, *self.worker_tasks, return_exceptions=True)

    def _inc_checked(self):
        self.total_checked += 1
        self.card_checked_val.config(text=str(self.total_checked))

    def _log_result(self, ip: str, sni: str, ping: int):
        n = len(self.valid_ips)
        row_tag = "even" if n % 2 == 0 else "odd"

        if ping < 100:
            latency_tag = "fast"
        elif ping < 300:
            latency_tag = "medium"
        else:
            latency_tag = "slow"

        self.tree.insert(
            "",
            tk.END,
            values=(ip, sni, f"{ping} ms", "✓  OK"),
            tags=(row_tag, latency_tag),
        )
        self.tree.yview_moveto(1.0)
        self.card_found_val.config(text=str(n))
        self.results_count_lbl.config(text=f"{n} entr{'y' if n == 1 else 'ies'}")

    def _update_status(self, text: str, color=TEXT_SECOND):
        self.card_status_val.config(text=text, fg=color)

    def _animate_status(self):
        if not self.is_scanning:
            return
        dot = self._dot_chars[self._anim_step % len(self._dot_chars)]
        color = self._pulse_colors[self._pulse_i % len(self._pulse_colors)]
        self._anim_step += 1
        self._pulse_i += 1
        self._update_status(f"{dot}  SCANNING", color)
        self.root.after(100, self._animate_status)

    def _clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.valid_ips = []
        self.total_checked = 0
        self.card_checked_val.config(text="0")
        self.card_found_val.config(text="0", fg=GREEN)
        self.results_count_lbl.config(text="0 entries")
        self._update_status("IDLE", TEXT_SECOND)

    def _export_results(self):
        if not self.valid_ips:
            messagebox.showinfo("Nothing to export", "Run a scan first to collect results.")
            return
        try:
            with open("working_tls_ips.txt", "w", encoding="utf-8") as f:
                for ip, sni, ping in self.valid_ips:
                    f.write(f"{ip} | {sni} | {ping}ms\n")
            messagebox.showinfo(
                "Exported",
                f"Saved {len(self.valid_ips)} results → working_tls_ips.txt",
            )
        except OSError as e:
            messagebox.showerror("Export Failed", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    SNIChecker(root)
    root.mainloop()
