import tkinter as tk
from tkinter import ttk, messagebox
import asyncio
import ipaddress
import time
import ssl
import threading
import re

class SNISpoofingGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SNI Spoofing Cheker")

        window_width, window_height = 1000, 750
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        center_x = int(screen_width / 2 - window_width / 2)
        center_y = int(screen_height / 2 - window_height / 2)
        self.root.geometry(f"{window_width}x{window_height}+{center_x}+{center_y}")
        
        self.root.configure(bg="#090D16")
        
        self.is_scanning = False
        self.valid_ips = []
        self.total_checked = 0
        self.animation_frame = 0
        self.animation_chars = ["▰▱▱▱▱", "▰▰▱▱▱", "▰▰▰▱▱", "▰▰▰▰▱", "▰▰▰▰▰", "▱▰▰▰▰", "▱▱▰▰▰", "▱▱▱▰▰", "▱▱▱▱▰"]
        self.pulse_colors = ["#38BDF8", "#0EA5E9", "#2563EB", "#0EA5E9"]
        self.pulse_index = 0
        self.workers_tasks = []
        
        self.setup_styles()
        self.setup_ui()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        self.style.configure(".", background="#090D16", foreground="#F1F5F9")
        self.style.configure("TLabelframe", background="#111827", bordercolor="#1F2937", borderwidth=2)
        self.style.configure("TLabelframe.Label", background="#111827", foreground="#00F0FF", font=("Segoe UI", 11, "bold"))
        self.style.configure("TLabel", background="#111827", foreground="#94A3B8", font=("Segoe UI", 10))
        
        self.style.configure("Treeview", 
                             background="#111827", 
                             foreground="#F8FAFC", 
                             fieldbackground="#111827", 
                             rowheight=35, 
                             borderwidth=0, 
                             font=("Segoe UI", 10))
        
        self.style.configure("Treeview.Heading", 
                             background="#1E293B", 
                             foreground="#00F0FF", 
                             font=("Segoe UI", 11, "bold"), 
                             borderwidth=1,
                             relief="flat")
                             
        self.style.map("Treeview", background=[("selected", "#1E3A8A")], foreground=[("selected", "#00F0FF")])
        self.style.configure("TProgressbar", thickness=5, troughcolor="#111827", background="#00F0FF")

    def setup_ui(self):
        main_frame = tk.Frame(self.root, bg="#090D16", padx=30, pady=25)
        main_frame.pack(fill=tk.BOTH, expand=True)

        header_frame = tk.Frame(main_frame, bg="#090D16")
        header_frame.pack(fill=tk.X, pady=(0, 25))
        
        title_lbl = tk.Label(header_frame, text="⚡ SNI SPOOFER", font=("Segoe UI", 26, "bold"), fg="#00F0FF", bg="#090D16")
        title_lbl.pack(side=tk.LEFT)
        
        author_lbl = tk.Label(header_frame, text="RohamEnemy Edition", font=("Segoe UI", 11, "bold", "italic"), fg="#475569", bg="#090D16")
        author_lbl.pack(side=tk.RIGHT, anchor=tk.S, pady=5)

        stats_frame = tk.Frame(main_frame, bg="#090D16")
        stats_frame.pack(fill=tk.X, pady=(0, 20))

        self.card_checked = tk.Frame(stats_frame, bg="#111827", highlightbackground="#1F2937", highlightthickness=1, padx=20, pady=15)
        self.card_checked.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        tk.Label(self.card_checked, text="TOTAL CHECKED", font=("Segoe UI", 10, "bold"), fg="#64748B", bg="#111827").pack(anchor=tk.W)
        self.lbl_checked_val = tk.Label(self.card_checked, text="0", font=("Consolas", 24, "bold"), fg="#F1F5F9", bg="#111827")
        self.lbl_checked_val.pack(anchor=tk.W)

        self.card_found = tk.Frame(stats_frame, bg="#111827", highlightbackground="#1F2937", highlightthickness=1, padx=20, pady=15)
        self.card_found.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(10, 0))
        tk.Label(self.card_found, text="SUCCESSFUL IPS", font=("Segoe UI", 10, "bold"), fg="#64748B", bg="#111827").pack(anchor=tk.W)
        self.lbl_found_val = tk.Label(self.card_found, text="0", font=("Consolas", 24, "bold"), fg="#10B981", bg="#111827")
        self.lbl_found_val.pack(anchor=tk.W)

        config_frame = ttk.LabelFrame(main_frame, text=" Configuration ", padding="15")
        config_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(config_frame, text="Timeout (s):").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.timeout_entry = tk.Entry(config_frame, bg="#1E293B", fg="#FFF", insertbackground="white", bd=0, width=15, font=("Segoe UI", 11), relief=tk.FLAT)
        self.timeout_entry.insert(0, "1.5")
        self.timeout_entry.grid(row=0, column=1, padx=(10, 40), pady=5, ipady=3)

        ttk.Label(config_frame, text="Concurrency:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.concurrency_entry = tk.Entry(config_frame, bg="#1E293B", fg="#FFF", insertbackground="white", bd=0, width=15, font=("Segoe UI", 11), relief=tk.FLAT)
        self.concurrency_entry.insert(0, "150")
        self.concurrency_entry.grid(row=0, column=3, padx=(10, 30), pady=5, ipady=3)

        inputs_frame = tk.Frame(main_frame, bg="#090D16")
        inputs_frame.pack(fill=tk.X, pady=(0, 20))

        subnet_frame = ttk.LabelFrame(inputs_frame, text=" IP Subnets Target ", padding="15")
        subnet_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        self.subnet_text = tk.Text(subnet_frame, height=5, bg="#0F172A", fg="#38BDF8", insertbackground="white", bd=0, font=("Consolas", 11), wrap=tk.WORD)
        self.subnet_text.insert("1.0", "104.19.229.0/24\n104.16.0.0/24")
        self.subnet_text.pack(fill=tk.BOTH, expand=True)

        sni_frame = ttk.LabelFrame(inputs_frame, text=" SNI Hostnames ", padding="15")
        sni_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        self.sni_text = tk.Text(sni_frame, height=5, bg="#0F172A", fg="#38BDF8", insertbackground="white", bd=0, font=("Consolas", 11), wrap=tk.WORD)
        self.sni_text.insert("1.0", "www.hcaptcha.com\nwww.cloudflare.com")
        self.sni_text.pack(fill=tk.BOTH, expand=True)

        control_frame = tk.Frame(main_frame, bg="#090D16")
        control_frame.pack(fill=tk.X, pady=(0, 15))

        self.start_btn = tk.Button(control_frame, text="▶ START SCAN", font=("Segoe UI", 11, "bold"), bg="#00F0FF", fg="#090D16", activebackground="#38BDF8", activeforeground="#090D16", bd=0, padx=30, pady=10, cursor="hand2")
        self.start_btn.pack(side=tk.LEFT)
        self.start_btn.bind("<Enter>", lambda e: self.start_btn.config(bg="#38BDF8") if self.is_scanning is False else None)
        self.start_btn.bind("<Leave>", lambda e: self.start_btn.config(bg="#00F0FF") if self.is_scanning is False else None)
        self.start_btn.config(command=self.toggle_scan)

        self.status_label = tk.Label(control_frame, text="SYSTEM READY", font=("Segoe UI", 12, "bold"), fg="#64748B", bg="#090D16")
        self.status_label.pack(side=tk.RIGHT, pady=5)

        self.pbar = ttk.Progressbar(main_frame, mode="indeterminate", style="TProgressbar")
        self.pbar.pack(fill=tk.X, pady=(0, 15))

        results_frame = ttk.LabelFrame(main_frame, text=" Real-time Results Terminal ", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("ip", "sni", "ping")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        self.tree.heading("ip", text="IP ADDRESS")
        self.tree.heading("sni", text="TARGET SNI")
        self.tree.heading("ping", text="PING RESPONSE")

        self.tree.column("ip", width=200, anchor=tk.CENTER)
        self.tree.column("sni", width=400, anchor=tk.W)
        self.tree.column("ping", width=150, anchor=tk.CENTER)
        
        self.tree.tag_configure('oddrow', background="#0F172A")
        self.tree.tag_configure('evenrow', background="#111827")

        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def animate_status(self):
        if self.is_scanning:
            char = self.animation_chars[self.animation_frame % len(self.animation_chars)]
            self.animation_frame += 1
            color = self.pulse_colors[self.pulse_index % len(self.pulse_colors)]
            self.pulse_index += 1
            self.status_label.config(text=f"SCANNING {char}", fg=color)
            self.root.after(120, self.animate_status)

    def log_success_to_ui(self, ip, sni, ping_time):
        tag = 'evenrow' if len(self.valid_ips) % 2 == 0 else 'oddrow'
        self.root.after(0, lambda: self.tree.insert("", tk.END, values=(ip, sni, f"{ping_time} ms"), tags=(tag,)))
        self.root.after(0, self.increment_found)

    def increment_checked(self):
        self.total_checked += 1
        self.lbl_checked_val.config(text=str(self.total_checked))

    def increment_found(self):
        self.lbl_found_val.config(text=str(len(self.valid_ips)))

    def update_status(self, text, color="#64748B"):
        self.root.after(0, lambda: self.status_label.config(text=text, fg=color))

    def toggle_scan(self):
        if self.is_scanning:
            self.is_scanning = False
            self.start_btn.config(state=tk.DISABLED, bg="#1F2937", fg="#475569")
            self.update_status("ABORTING...", "#EF4444")
            self.pbar.stop()
            for task in self.workers_tasks:
                task.cancel()
            return

        subnets_raw = re.split(r'[\n\r,;]+', self.subnet_text.get("1.0", tk.END).strip())
        snis_raw = re.split(r'[\n\r,;]+', self.sni_text.get("1.0", tk.END).strip())

        subnets = [s.strip() for s in subnets_raw if s.strip()]
        snis = [s.strip() for s in snis_raw if s.strip()]

        if not subnets or not snis:
            messagebox.showwarning("Error", "Please provide at least one IP range and one SNI.")
            return

        try:
            timeout = float(self.timeout_entry.get())
            concurrency = int(self.concurrency_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Concurrency and Timeout must be numbers.")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.valid_ips = []
        self.total_checked = 0
        self.lbl_checked_val.config(text="0")
        self.lbl_found_val.config(text="0")
        
        self.is_scanning = True
        self.workers_tasks = []
        
        self.start_btn.config(text="⏹ STOP SCAN", bg="#EF4444", fg="#FFF")
        self.pbar.start(10)
        self.animate_status()

        threading.Thread(target=self.start_async_loop, args=(subnets, snis, timeout, concurrency), daemon=True).start()

    def start_async_loop(self, subnets, snis, timeout, concurrency):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.run_scanner(subnets, snis, timeout, concurrency))
        except asyncio.CancelledError:
            pass
        finally:
            loop.close()

        self.is_scanning = False
        self.root.after(0, lambda: self.pbar.stop())
        self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL, text="▶ START SCAN", bg="#00F0FF", fg="#090D16"))

        if self.valid_ips:
            self.valid_ips.sort(key=lambda x: x[2])
            with open("working_tls_ips.txt", "w") as f:
                for ip, sni, ping in self.valid_ips:
                    f.write(f"{ip} | {sni} | {ping}ms\n")
            self.update_status("SUCCESSFULLY COMPLETED", "#10B981")
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Found {len(self.valid_ips)} working IPs!"))
        else:
            self.update_status("FINISHED WITH NO RESULTS", "#F59E0B")
            self.root.after(0, lambda: messagebox.showinfo("Finished", "No working IPs found for these SNIs."))

    async def worker(self, queue, port, timeout, ctx):
        while True:
            try:
                item = await queue.get()
                if item is None:
                    queue.task_done()
                    break

                ip, sni = item
                self.root.after(0, self.increment_checked)
                start_time = time.time()
                writer = None
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni),
                        timeout=timeout
                    )
                    ping_time = int((time.time() - start_time) * 1000)
                    self.valid_ips.append((ip, sni, ping_time))
                    self.log_success_to_ui(ip, sni, ping_time)
                except Exception:
                    pass
                finally:
                    if writer:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
                    queue.task_done()
            except asyncio.CancelledError:
                break

    async def run_scanner(self, subnets, snis, timeout, concurrency):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        port = 443

        queue = asyncio.Queue(maxsize=concurrency * 2)

        async def producer():
            for subnet_str in subnets:
                try:
                    network = ipaddress.IPv4Network(subnet_str, strict=False)
                    for ip in network.hosts():
                        if not self.is_scanning:
                            break
                        for sni in snis:
                            await queue.put((str(ip), sni))
                except ValueError:
                    pass
                
                if not self.is_scanning:
                    break

            for _ in range(concurrency):
                await queue.put(None)

        prod_task = asyncio.create_task(producer())
        self.workers_tasks = [asyncio.create_task(self.worker(queue, port, timeout, ctx)) for _ in range(concurrency)]

        await asyncio.gather(prod_task, *self.workers_tasks, return_exceptions=True)


if __name__ == "__main__":
    root = tk.Tk()
    app = SNISpoofingGUI(root)
    root.mainloop()