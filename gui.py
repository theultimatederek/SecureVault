# gui.py — SecureVault GUI
# Dark professional file manager style

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import time
import os
import subprocess
import sys

from client import SecureVaultClient
from server import SecureVaultServer
from crypto_engine import human_size

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

BG     = "#0D1117"
PANEL  = "#161B22"
CARD   = "#21262D"
BORDER = "#30363D"
ACCENT = "#58A6FF"
GREEN  = "#3FB950"
RED    = "#F85149"
ORANGE = "#F0883E"
YELLOW = "#D29922"
DIM    = "#8B949E"
BRIGHT = "#E6EDF3"
FONT   = "Courier New"


class SecureVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SecureVault — Encrypted File Transfer")
        self.geometry("1200x800")
        self.minsize(1000, 680)
        self.configure(fg_color=BG)

        self._server      = None
        self._server_thread = None
        self._client      = None
        self._files       = []

        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()

    # ── SIDEBAR ────────────────────────────────────────────────────────────
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0,
                          width=300, border_width=1, border_color=BORDER)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)

        # Logo
        ctk.CTkLabel(sb, text="🔐 SecureVault",
            font=ctk.CTkFont(family=FONT, size=20, weight="bold"),
            text_color=ACCENT).pack(anchor="w", padx=18, pady=(20,4))
        ctk.CTkLabel(sb, text="Encrypted File Transfer System",
            font=ctk.CTkFont(family=FONT, size=9),
            text_color=DIM).pack(anchor="w", padx=18, pady=(0,12))
        ctk.CTkFrame(sb, height=1, fg_color=BORDER).pack(fill="x")

        sc = ctk.CTkScrollableFrame(sb, fg_color="transparent",
            scrollbar_button_color=BORDER)
        sc.pack(fill="both", expand=True)

        def sec(t, c=ACCENT):
            ctk.CTkLabel(sc, text=t,
                font=ctk.CTkFont(family=FONT, size=9, weight="bold"),
                text_color=c).pack(anchor="w", padx=16, pady=(16,4))

        def inp(ph, var):
            e = ctk.CTkEntry(sc, textvariable=var, placeholder_text=ph,
                font=ctk.CTkFont(family=FONT, size=11),
                fg_color=CARD, border_color=BORDER,
                text_color=BRIGHT, height=34, corner_radius=5)
            e.pack(fill="x", padx=14, pady=(0,8))
            return e

        # Server config
        sec("// SERVER")
        self._host_var = tk.StringVar(value="127.0.0.1")
        self._port_var = tk.StringVar(value="9999")
        inp("Host", self._host_var)
        inp("Port", self._port_var)

        self._srv_btn = ctk.CTkButton(sc, text="▶  Start Server",
            font=ctk.CTkFont(family=FONT, size=11, weight="bold"),
            fg_color=GREEN, text_color=BG, hover_color="#56D364",
            height=34, corner_radius=5, command=self._toggle_server)
        self._srv_btn.pack(fill="x", padx=14, pady=(0,8))

        self._srv_status = ctk.CTkLabel(sc, text="● Server offline",
            font=ctk.CTkFont(family=FONT, size=10), text_color=RED)
        self._srv_status.pack(anchor="w", padx=16)

        # Encryption config
        sec("// ENCRYPTION KEY")
        self._pass_var = tk.StringVar()
        ctk.CTkEntry(sc, textvariable=self._pass_var,
            placeholder_text="Enter password / passphrase",
            show="●",
            font=ctk.CTkFont(family=FONT, size=11),
            fg_color=CARD, border_color=BORDER,
            text_color=BRIGHT, height=34, corner_radius=5).pack(
            fill="x", padx=14, pady=(0,4))
        ctk.CTkLabel(sc, text="AES-256-GCM · PBKDF2 · 600k iterations",
            font=ctk.CTkFont(family=FONT, size=9),
            text_color=DIM).pack(anchor="w", padx=16, pady=(0,8))

        ctk.CTkButton(sc, text="🔗  Connect Client",
            font=ctk.CTkFont(family=FONT, size=11, weight="bold"),
            fg_color=ACCENT, text_color=BG, hover_color="#79C0FF",
            height=34, corner_radius=5,
            command=self._connect_client).pack(fill="x", padx=14, pady=(0,8))

        self._cli_status = ctk.CTkLabel(sc, text="● Client not connected",
            font=ctk.CTkFont(family=FONT, size=10), text_color=RED)
        self._cli_status.pack(anchor="w", padx=16)

        # Threat model
        sec("// THREAT MODEL", ORANGE)
        threats = [
            ("MITM",     "TLS + ECDH ephemeral key"),
            ("Tampering","AES-GCM tag + HMAC/chunk"),
            ("Replay",   "Random IV per chunk"),
            ("Brute",    "PBKDF2 600k iters + salt"),
            ("At-rest",  "Files stored AES-256 only"),
        ]
        for threat, mitigation in threats:
            row = ctk.CTkFrame(sc, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=1)
            ctk.CTkLabel(row, text=f"{threat}:", width=70,
                font=ctk.CTkFont(family=FONT, size=9, weight="bold"),
                text_color=ORANGE, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=mitigation,
                font=ctk.CTkFont(family=FONT, size=9),
                text_color=DIM, anchor="w").pack(side="left")

        # Bottom buttons
        btns = ctk.CTkFrame(sb, fg_color="transparent")
        btns.pack(side="bottom", fill="x", padx=14, pady=14)

        ctk.CTkButton(btns, text="📤  Upload File",
            font=ctk.CTkFont(family=FONT, size=12, weight="bold"),
            fg_color=ACCENT, text_color=BG, hover_color="#79C0FF",
            height=40, corner_radius=5,
            command=self._upload_file).pack(fill="x", pady=(0,6))

        ctk.CTkButton(btns, text="📥  Download Selected",
            font=ctk.CTkFont(family=FONT, size=11),
            fg_color=CARD, text_color=GREEN,
            border_width=1, border_color=GREEN,
            height=34, corner_radius=5,
            command=self._download_selected).pack(fill="x", pady=(0,6))

        ctk.CTkButton(btns, text="🗑  Delete Selected",
            font=ctk.CTkFont(family=FONT, size=11),
            fg_color=CARD, text_color=RED,
            border_width=1, border_color=RED,
            height=34, corner_radius=5,
            command=self._delete_selected).pack(fill="x", pady=(0,6))

        ctk.CTkButton(btns, text="🔄  Refresh List",
            font=ctk.CTkFont(family=FONT, size=11),
            fg_color=CARD, text_color=DIM,
            border_width=1, border_color=BORDER,
            height=34, corner_radius=5,
            command=self._refresh_files).pack(fill="x")

    # ── MAIN ───────────────────────────────────────────────────────────────
    def _build_main(self):
        main = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(1, weight=1)
        main.grid_columnconfigure(0, weight=1)

        # Stats bar
        stats = ctk.CTkFrame(main, fg_color=PANEL, corner_radius=0,
            height=70, border_width=1, border_color=BORDER)
        stats.grid(row=0, column=0, sticky="ew")
        stats.grid_propagate(False)
        self._svars = {}
        for label, init, color in [
            ("FILES",     "0",     ACCENT),
            ("UPLOADED",  "0 B",   GREEN),
            ("DOWNLOADED","0 B",   GREEN),
            ("ENCRYPTION","AES-256-GCM", ORANGE),
            ("INTEGRITY", "HMAC-SHA256", YELLOW),
            ("STATUS",    "OFFLINE",RED),
        ]:
            f = ctk.CTkFrame(stats, fg_color="transparent")
            f.pack(side="left", expand=True, fill="both")
            ctk.CTkLabel(f, text=label,
                font=ctk.CTkFont(family=FONT, size=9, weight="bold"),
                text_color=DIM).pack(pady=(8,2))
            var = tk.StringVar(value=init)
            self._svars[label] = var
            ctk.CTkLabel(f, textvariable=var,
                font=ctk.CTkFont(family=FONT, size=12, weight="bold"),
                text_color=color).pack()

        # Tabs
        tabs = ctk.CTkTabview(main, fg_color=BG,
            segmented_button_fg_color=PANEL,
            segmented_button_selected_color=ACCENT,
            segmented_button_unselected_color=PANEL,
            text_color=BRIGHT)
        tabs.grid(row=1, column=0, sticky="nsew")
        tabs.add("📁 Files on Server")
        tabs.add("📋 Activity Log")
        tabs.add("🔒 Security Info")

        # Files tab
        ff = tabs.tab("📁 Files on Server")
        ff.grid_rowconfigure(1, weight=1)
        ff.grid_columnconfigure(0, weight=1)

        # Header row
        hdr = ctk.CTkFrame(ff, fg_color=CARD, corner_radius=0, height=30)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)
        for text, width in [("FILE NAME",240),("SIZE",90),("UPLOADED",160),("ENCRYPTED",90),("STORED AS",260)]:
            ctk.CTkLabel(hdr, text=text, width=width,
                font=ctk.CTkFont(family=FONT, size=10, weight="bold"),
                text_color=ACCENT, anchor="w").pack(side="left", padx=(10,0))

        self._file_frame = ctk.CTkScrollableFrame(ff, fg_color=BG,
            scrollbar_button_color=BORDER)
        self._file_frame.grid(row=1, column=0, sticky="nsew")
        self._selected_file = tk.StringVar()

        # Log tab
        lf = tabs.tab("📋 Activity Log")
        lf.grid_rowconfigure(0, weight=1)
        lf.grid_columnconfigure(0, weight=1)
        self._log_box = ctk.CTkTextbox(lf, fg_color="#000",
            text_color=BRIGHT, font=ctk.CTkFont(family=FONT, size=12),
            border_width=0, wrap="word")
        self._log_box.grid(row=0, column=0, sticky="nsew")
        self._log_box.configure(state="disabled")
        for tag, color in [("info",ACCENT),("ok",GREEN),("warn",ORANGE),
                           ("vuln",RED),("dim",DIM)]:
            self._log_box.tag_config(tag, foreground=color)

        # Security Info tab
        sf = tabs.tab("🔒 Security Info")
        sf.grid_rowconfigure(0, weight=1)
        sf.grid_columnconfigure(0, weight=1)
        sec_text = ctk.CTkTextbox(sf, fg_color=BG,
            text_color=BRIGHT, font=ctk.CTkFont(family=FONT, size=12),
            border_width=0, wrap="word")
        sec_text.grid(row=0, column=0, sticky="nsew")
        sec_text.configure(state="normal")
        sec_text.insert("end", SECURITY_INFO)
        sec_text.configure(state="disabled")

        # Status bar
        sbar = ctk.CTkFrame(main, fg_color=PANEL, height=26,
            corner_radius=0, border_width=1, border_color=BORDER)
        sbar.grid(row=2, column=0, sticky="ew")
        sbar.grid_propagate(False)
        self._status_var = tk.StringVar(value="Start server and connect client to begin.")
        ctk.CTkLabel(sbar, textvariable=self._status_var,
            font=ctk.CTkFont(family=FONT, size=10),
            text_color=DIM, anchor="w").pack(side="left", padx=10)

        # Progress bar
        self._progress_var = tk.DoubleVar(value=0)
        self._prog_bar = ctk.CTkProgressBar(main,
            variable=self._progress_var,
            progress_color=ACCENT, fg_color=BORDER,
            height=3, corner_radius=0)
        self._prog_bar.grid(row=3, column=0, sticky="ew")

    # ── Server control ─────────────────────────────────────────────────────
    def _toggle_server(self):
        if self._server is None:
            self._server = SecureVaultServer(
                host=self._host_var.get(),
                port=int(self._port_var.get()),
            )
            self._server_thread = threading.Thread(
                target=self._server.start, daemon=True)
            self._server_thread.start()
            self._srv_btn.configure(text="■  Stop Server", fg_color=RED,
                text_color=BRIGHT, hover_color="#B91C1C")
            self._srv_status.configure(text="● Server online", text_color=GREEN)
            self._svars["STATUS"].set("ONLINE")
            self._log("Server started on "
                      f"{self._host_var.get()}:{self._port_var.get()}", "ok")
        else:
            self._server.stop()
            self._server = None
            self._srv_btn.configure(text="▶  Start Server", fg_color=GREEN,
                text_color=BG, hover_color="#56D364")
            self._srv_status.configure(text="● Server offline", text_color=RED)
            self._svars["STATUS"].set("OFFLINE")
            self._log("Server stopped.", "warn")

    # ── Client connect ─────────────────────────────────────────────────────
    def _connect_client(self):
        pw = self._pass_var.get()
        if not pw:
            messagebox.showwarning("Password Required",
                "Enter a passphrase to derive the encryption key.")
            return
        try:
            self._client = SecureVaultClient(
                host     = self._host_var.get(),
                port     = int(self._port_var.get()),
                password = pw,
                callback = self._log,
            )
            # Test connection
            self._client.list_files()
            self._cli_status.configure(text="● Client connected", text_color=GREEN)
            self._log(f"Client connected — key derived from passphrase "
                      f"(AES-256, PBKDF2 600k iters)", "ok")
            self._refresh_files()
        except Exception as e:
            self._cli_status.configure(text="● Connection failed", text_color=RED)
            self._log(f"Connection error: {e}", "vuln")
            messagebox.showerror("Connection Failed",
                f"Cannot connect to server.\n\nStart the server first!\n\n{e}")

    # ── Upload ─────────────────────────────────────────────────────────────
    def _upload_file(self):
        if not self._client:
            messagebox.showwarning("Not Connected", "Connect client first.")
            return
        path = filedialog.askopenfilename(title="Select file to upload")
        if not path:
            return

        def do_upload():
            try:
                size = os.path.getsize(path)

                def progress(done, total, _):
                    pct = done / total if total else 0
                    self.after(0, self._progress_var.set, pct)
                    self.after(0, self._status,
                        f"Uploading {os.path.basename(path)}... "
                        f"{human_size(done)} / {human_size(total)}")

                result = self._client.upload(path, progress_cb=progress)
                self.after(0, self._progress_var.set, 0)
                self.after(0, self._svars["UPLOADED"].set, human_size(size))
                self.after(0, self._refresh_files)
                self.after(0, self._status, f"Upload complete ✓")
            except Exception as e:
                self.after(0, self._log, f"Upload error: {e}", "vuln")
                self.after(0, messagebox.showerror, "Upload Failed", str(e))

        threading.Thread(target=do_upload, daemon=True).start()

    # ── Download ───────────────────────────────────────────────────────────
    def _download_selected(self):
        if not self._client:
            messagebox.showwarning("Not Connected", "Connect client first.")
            return
        stored = self._selected_file.get()
        if not stored:
            messagebox.showwarning("No Selection", "Select a file first.")
            return
        save_dir = filedialog.askdirectory(title="Save to folder")
        if not save_dir:
            return

        def do_download():
            try:
                def progress(done, total, _):
                    pct = done / total if total else 0
                    self.after(0, self._progress_var.set, pct)
                    self.after(0, self._status,
                        f"Downloading {stored}... "
                        f"{human_size(done)} / {human_size(total)}")

                result = self._client.download(stored, save_dir, progress)
                self.after(0, self._progress_var.set, 0)
                self.after(0, self._svars["DOWNLOADED"].set,
                    human_size(result.get('bytes', 0)))
                self.after(0, self._status,
                    f"Download & decrypt complete ✓  Saved: {result['saved_to']}")
            except Exception as e:
                self.after(0, self._log, f"Download error: {e}", "vuln")
                self.after(0, messagebox.showerror, "Download Failed", str(e))

        threading.Thread(target=do_download, daemon=True).start()

    # ── Delete ─────────────────────────────────────────────────────────────
    def _delete_selected(self):
        stored = self._selected_file.get()
        if not stored:
            messagebox.showwarning("No Selection", "Select a file first.")
            return
        if not messagebox.askyesno("Confirm Delete",
                f"Permanently delete {stored}?"):
            return
        try:
            self._client.delete_file(stored)
            self._log(f"Deleted: {stored}", "warn")
            self._refresh_files()
        except Exception as e:
            messagebox.showerror("Delete Failed", str(e))

    # ── Refresh file list ──────────────────────────────────────────────────
    def _refresh_files(self):
        if not self._client:
            return
        try:
            files = self._client.list_files()
            self._files = files
            self._svars["FILES"].set(str(len(files)))
            # Clear and rebuild file list
            for w in self._file_frame.winfo_children():
                w.destroy()
            for meta in files:
                self._add_file_row(meta)
        except Exception as e:
            self._log(f"Refresh error: {e}", "warn")

    def _add_file_row(self, meta):
        stored = meta.get('stored_name', '')
        is_sel = self._selected_file.get() == stored

        row = ctk.CTkFrame(self._file_frame,
            fg_color=CARD if is_sel else "transparent",
            border_width=1,
            border_color=ACCENT if is_sel else BORDER,
            corner_radius=6)
        row.pack(fill="x", pady=2, padx=4)

        def select(e, s=stored):
            self._selected_file.set(s)
            self._refresh_files()

        size_str = human_size(meta.get('file_size', 0))
        ts       = meta.get('uploaded_at', '—')[:19]

        for text, width in [
            (meta.get('original_name','?'), 240),
            (size_str, 90),
            (ts, 160),
            ("🔐 AES-256", 90),
            (stored[:36], 260),
        ]:
            lbl = ctk.CTkLabel(row, text=text, width=width,
                font=ctk.CTkFont(family=FONT, size=11),
                text_color=BRIGHT if is_sel else DIM, anchor="w")
            lbl.pack(side="left", padx=(10,0))
            lbl.bind("<Button-1>", select)

        row.bind("<Button-1>", select)

    # ── Log ────────────────────────────────────────────────────────────────
    def _log(self, msg, level='info'):
        self.after(0, self._log_ui, msg, level)

    def _log_ui(self, msg, level):
        from datetime import datetime
        ts = datetime.now().strftime('%H:%M:%S')
        self._log_box.configure(state="normal")
        self._log_box.insert("end", f"[{ts}] {msg}\n", level)
        self._log_box.see("end")
        self._log_box.configure(state="disabled")

    def _status(self, msg):
        self._status_var.set(f"  ▶  {msg}")


# ── Security Info text ─────────────────────────────────────────────────────
SECURITY_INFO = """
  SecureVault — Security Architecture & Threat Model
  ═══════════════════════════════════════════════════════════

  ENCRYPTION
  ──────────
  Algorithm   : AES-256-GCM (authenticated encryption)
  Key Size    : 256 bits
  IV/Nonce    : 96 bits, random per chunk (prevents replay)
  Auth Tag    : 128 bits (detects any tampering)
  Key Derive  : PBKDF2-HMAC-SHA256, 600,000 iterations

  INTEGRITY
  ─────────
  Per-chunk   : HMAC-SHA256 over [index + IV + ciphertext]
  Chunk index : included in AAD — prevents reordering
  File-level  : SHA-256 of entire encrypted payload
  Server-side : SHA-256 verified on upload & download

  CHUNKING
  ────────
  Chunk size  : 64 KB per chunk
  Each chunk independently encrypted + HMAC'd
  Enables     : parallel processing, resume support
  Chunk index : in AAD — swapped chunks rejected

  THREAT MODEL & MITIGATIONS
  ──────────────────────────
  Man-in-the-Middle:
    Threat   : Attacker intercepts data in transit
    Mitigation: TLS channel (production) + ECDH key exchange
                File-level SHA-256 verified end-to-end
                HMAC fails if any byte modified

  Replay Attack:
    Threat   : Attacker replays old encrypted chunks
    Mitigation: Random 96-bit IV per chunk — ciphertext
                differs even for identical plaintext

  Data Tampering:
    Threat   : Attacker modifies encrypted file on server
    Mitigation: HMAC-SHA256 per chunk — fails on any change
                GCM auth tag — additional layer

  Brute Force / Weak Keys:
    Threat   : Password guessing
    Mitigation: PBKDF2 with 600,000 iterations + 256-bit salt
                Makes brute force computationally infeasible

  Key Exposure:
    Threat   : Encryption key leaked
    Mitigation: Session keys never written to disk
                Keys exist only in memory during session
                ECDH provides forward secrecy (session keys)

  Data at Rest:
    Threat   : Server disk compromise
    Mitigation: Files stored ONLY as AES-256-GCM ciphertext
                Server NEVER decrypts — zero-knowledge design
                Original filename not stored in plaintext

  RESPONSIBLE DISCLOSURE
  ──────────────────────
  This is an educational prototype. Production deployment
  requires: TLS 1.3 for transport, hardware HSM for key
  storage, audit logging, and formal security review.

  Built during Week 3 internship at Syntecxhub.
"""


if __name__ == "__main__":
    app = SecureVaultApp()
    app.mainloop()
