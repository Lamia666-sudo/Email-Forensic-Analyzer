"""
gui_launcher.py
Email Forensics Analyzer GUI
Professional interface for email forensic analysis
"""

import os
import sys
import subprocess
import threading
import re
import time
import json
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from pathlib import Path

# --- Project Root ---
if getattr(sys, 'frozen', False):
    PROJECT_ROOT = Path(sys.executable).parent
else:
    PROJECT_ROOT = Path(__file__).parent.resolve()

os.chdir(PROJECT_ROOT)
PIPELINE_SCRIPT = PROJECT_ROOT / "pipeline.py"

# --- Use current Python executable (cross-platform) ---
PYTHON_EXEC = sys.executable

# --- Professional Color Palette ---
PALETTE = {
    "bg": "#1e1433",           
    "card": "#2a1b45",        
    "accent": "#c678dd",       
    "accent_hover": "#e0a1ff",  
    "accent_active": "#d48aff",
    "secondary": "#a29bfe",
    "muted": "#b8a9d4",
    "success": "#a7f3d0",
    "error": "#fca5a5",
    "exception": "#ffd93d",
    "report": "#f8b4d9",
    "text": "#f0e6ff",
    "glow": "#e6ccff",
}

def run_pipeline_in_thread(mbox_path: str, text_widget: scrolledtext.ScrolledText, run_btn: tk.Button, root: tk.Tk):
    output_queue = queue.Queue()
    
    def worker():
        try:
            output_queue.put(("disable_btn", None))
            output_queue.put(("clear", None))
            output_queue.put(("text", "Starting forensic analysis...\n", "info"))
            output_queue.put(("text", f"    File: {os.path.basename(mbox_path)}\n\n", "info"))
            output_queue.put(("text", "─" * 70 + "\n", "normal"))

            cmd = [PYTHON_EXEC, str(PIPELINE_SCRIPT), mbox_path]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                encoding='utf-8',
                errors='replace'
            )

            for line in proc.stdout:
                tag = "normal"
                if "[ERROR]" in line or "failed" in line.lower():
                    tag = "error"
                elif "[EXCEPTION]" in line or "Traceback" in line:
                    tag = "exception"
                elif "[✔]" in line or "success" in line.lower() or "complete" in line.lower():
                    tag = "success"
                elif any(x in line.lower() for x in ["report", ".json", "forensic", "attachment", "interaction"]):
                    tag = "report"
                elif "[+]" in line or "Parsing" in line or "Using" in line:
                    tag = "info"

                output_queue.put(("text", line, tag))

            proc.wait()
            if proc.returncode == 0:
                output_queue.put(("text", "\nPipeline completed successfully.\n", "success"))
                output_queue.put(("msgbox", "success", "Analysis complete!\nCheck the 'reports/' folder for results."))
            else:
                output_queue.put(("text", f"\nPipeline failed (code {proc.returncode})\n", "error"))
                output_queue.put(("msgbox", "error", "Analysis failed. Check log for details."))

        except Exception as e:
            output_queue.put(("text", f"\nException: {str(e)}\n", "exception"))
            output_queue.put(("msgbox", "error", str(e)))
        finally:
            output_queue.put(("enable_btn", None))

    def process_queue():
        try:
            while True:
                action, *args = output_queue.get_nowait()
                if action == "disable_btn":
                    run_btn.config(state="disabled")
                elif action == "enable_btn":
                    run_btn.config(state="normal")
                elif action == "clear":
                    text_widget.delete(1.0, tk.END)
                elif action == "text":
                    text_widget.insert(tk.END, args[0], args[1] if len(args) > 1 else "normal")
                    text_widget.see(tk.END)
                elif action == "msgbox":
                    if args[0] == "success":
                        messagebox.showinfo("Success", args[1])
                    else:
                        messagebox.showerror("Error", args[1])
        except queue.Empty:
            pass
        root.after(50, process_queue)

    threading.Thread(target=worker, daemon=True).start()
    process_queue()


def choose_and_run(text_widget, run_btn, root):
    initial_dir = PROJECT_ROOT / "data"
    mbox_path = filedialog.askopenfilename(
        title="Select MBOX File",
        initialdir=str(initial_dir) if initial_dir.exists() else None,
        filetypes=[("MBOX Files", "*.mbox"), ("All Files", "*.*")]
    )
    if mbox_path:
        suffix = Path(mbox_path).suffix.lower()
        # If user opened a report file, show it prettified in the log pane
        if suffix in ('.json', '.txt', '.log'):
            try:
                text_widget.delete(1.0, tk.END)
                if suffix == '.json':
                    with open(mbox_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    pretty = json.dumps(data, indent=2, ensure_ascii=False)
                    for line in pretty.splitlines():
                        text_widget.insert(tk.END, line + "\n", 'report')
                else:
                    with open(mbox_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            text_widget.insert(tk.END, line, 'report')
                text_widget.see(tk.END)
                return
            except Exception as e:
                messagebox.showerror('Open File', f'Failed to open file:\n{e}')

        # Only accept .mbox for running the pipeline
        if suffix != '.mbox':
            messagebox.showerror('Wrong Extension', 'Selected file is not a .mbox file. Please select a valid MBOX to run analysis.')
            return

        # fallback: run the pipeline using selected file
        run_pipeline_in_thread(mbox_path, text_widget, run_btn, root)


def main():
    root = tk.Tk()
    root.title("Email Forensics Analyzer ✨")
    root.geometry("960x640")
    root.minsize(800, 500)
    root.configure(bg=PALETTE["bg"])

    # === Header ===
    title = tk.Label(
        root,
        text="Email Forensics Analyzer",
        font=("Segoe UI", 22, "bold"),
        fg=PALETTE["accent_hover"],
        bg=PALETTE["bg"]
    )
    title.pack(pady=(20, 5))

    subtitle = tk.Label(
        root,
        text="Detect spoofing and phishing indicators in email exports",
        font=("Segoe UI Light", 11),
        fg=PALETTE["muted"],
        bg=PALETTE["bg"]
    )
    subtitle.pack(pady=(0, 20))

    # === Magical Button with Glow Effect ===
    btn_frame = tk.Frame(root, bg=PALETTE["bg"])
    btn_frame.pack(pady=10)

    # Background glow (subtle oval behind button)
    canvas = tk.Canvas(btn_frame, width=300, height=80, bg=PALETTE["bg"], highlightthickness=0)
    canvas.pack()
    glow = canvas.create_oval(10, 10, 290, 70, fill="", outline=PALETTE["glow"], width=4, stipple="gray50")

    class MagicButton(tk.Button):
        def __init__(self, master, **kw):
            self.default_bg = PALETTE["accent"]
            self.hover_bg = PALETTE["accent_hover"]
            self.active_bg = PALETTE["accent_active"]
            super().__init__(
                master,
                text="Select MBOX File & Run Analysis",
                font=("Segoe UI", 12, "bold"),
                fg="white",
                bg=self.default_bg,
                activebackground=self.active_bg,
                relief=tk.FLAT,
                padx=30,
                pady=15,
                cursor="hand2",
                command=kw.get("command")
            )
            self.bind("<Enter>", self.on_enter)
            self.bind("<Leave>", self.on_leave)
            self.bind("<ButtonPress>", self.on_press)
            self.bind("<ButtonRelease>", self.on_release)

        def on_enter(self, e):
            self.config(bg=self.hover_bg)
            canvas.itemconfig(glow, stipple="", width=6)

        def on_leave(self, e):
            self.config(bg=self.default_bg)
            canvas.itemconfig(glow, stipple="gray50", width=4)

        def on_press(self, e):
            self.config(bg=self.active_bg)

        def on_release(self, e):
            self.config(bg=self.hover_bg if self["state"] != "disabled" else self.default_bg)

    run_btn = MagicButton(
        canvas,
        command=lambda: choose_and_run(log_text, run_btn, root)
    )
    canvas.create_window(150, 40, window=run_btn)

    # === Log Panel ===
    log_frame = tk.Frame(root, bg=PALETTE["bg"])
    log_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(20, 30))

    log_text = scrolledtext.ScrolledText(
        log_frame,
        wrap=tk.WORD,
        font=("Consolas", 10),
        bg=PALETTE["card"],
        fg=PALETTE["text"],
        insertbackground=PALETTE["text"],
        relief=tk.FLAT,
        bd=8,
        highlightbackground=PALETTE["secondary"],
        highlightcolor=PALETTE["secondary"],
        highlightthickness=2
    )
    log_text.pack(fill=tk.BOTH, expand=True)

    # Color tags
    log_text.tag_config("normal", foreground=PALETTE["text"])
    log_text.tag_config("info", foreground=PALETTE["accent"])
    log_text.tag_config("success", foreground=PALETTE["success"])
    log_text.tag_config("error", foreground=PALETTE["error"])
    log_text.tag_config("exception", foreground=PALETTE["exception"], underline=True)
    log_text.tag_config("report", foreground=PALETTE["report"])

    # Welcome message
    log_text.insert(tk.END, "Email Forensics Analyzer\n\n", "info")
    log_text.insert(tk.END, "Ready to analyze. Click the button above to select your MBOX file.\n\n", "normal")

    # Optional directory watcher (disabled by default for security)
    def start_dir_watcher(text_widget, run_btn, root, poll_interval=5):
        data_dir = PROJECT_ROOT / "data"
        seen = set()
        if not data_dir.exists():
            return
        for p in data_dir.iterdir():
            if p.is_file() and p.suffix.lower() in ('.mbox', '.eml'):
                seen.add(p.resolve())

        def watcher():
            while True:
                try:
                    for p in data_dir.iterdir():
                        if p.is_file() and p.suffix.lower() in ('.mbox', '.eml'):
                            rp = p.resolve()
                            if rp not in seen:
                                seen.add(rp)
                                # schedule UI update only (no auto-run for security)
                                def notify():
                                    text_widget.insert(tk.END, f"\n[+] Detected new file: {p.name}\n", 'info')
                                    text_widget.insert(tk.END, "[INFO] Auto-run disabled for security. Run analysis manually.\n", 'info')
                                    text_widget.see(tk.END)
                                text_widget.after(100, notify)
                    time.sleep(poll_interval)
                except Exception:
                    time.sleep(poll_interval)

        t = threading.Thread(target=watcher, daemon=True)
        t.start()

    # Uncomment to enable directory watcher (not recommended for production)
    # start_dir_watcher(log_text, run_btn, root)
    
    log_text.insert(tk.END, f"Project: {PROJECT_ROOT}\n", "info")
    log_text.insert(tk.END, f"Python: {PYTHON_EXEC}\n\n", "info")
    log_text.insert(tk.END, "Ready for analysis.\n", "info")

    root.mainloop()


if __name__ == "__main__":
    main()