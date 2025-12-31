import os
import hashlib
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import time
import sys
from datetime import datetime

# --- CRASH PROTECTION ---
try:
    import requests
except ImportError:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("Missing Library", "Please install 'requests' via: pip install requests")
    sys.exit()

# ================= CONFIG =================
SIGNATURE_FILE = "signatures.txt"
QUARANTINE_DIR = "quarantine"
LOG_DIR = "logs"
SCAN_INTERVAL = 25
KASPERSKY_API_KEY = "YOUR_KASPERSKY_TOKEN_HERE" 

MY_PATH = os.path.abspath(sys.argv[0])
EXECUTABLE_EXTS = (".exe", ".msi", ".bat", ".cmd", ".scr")
TEXT_EXTS = (".py", ".txt", ".js", ".vbs", ".ps1")
SUSPICIOUS_KEYWORDS = ["powershell", "base64", "os.system", "subprocess", "eval(", "exec("]

os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# ================= CORE ENGINE =================
def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except: return None

def cloud_scan_kaspersky(file_path):
    if not KASPERSKY_API_KEY or "YOUR_KASPERSKY" in KASPERSKY_API_KEY: return None
    file_hash = sha256(file_path)
    url = f"https://opentip.kaspersky.com/api/v1/search/hash?request={file_hash}"
    try:
        response = requests.get(url, headers={"x-api-key": KASPERSKY_API_KEY}, timeout=5)
        if response.status_code == 200:
            return response.json().get('Zone', 'Grey')
    except: pass
    return "Error"

def threat_score(path):
    if os.path.abspath(path) == MY_PATH: return 0
    score = 0
    name = path.lower()
    if name.endswith(EXECUTABLE_EXTS): score += 25
    if name.count(".") >= 2: score += 25
    if "temp" in name or "appdata" in name: score += 20
    if name.endswith(TEXT_EXTS):
        try:
            with open(path, "r", errors="ignore") as f:
                data = f.read()
                for k in SUSPICIOUS_KEYWORDS:
                    if k in data: score += 20
        except: pass
    return score

def classify(score, k_zone):
    if k_zone == "Red" or score >= 70: return "CRITICAL THREAT"
    if k_zone == "Yellow" or score >= 40: return "HIGH RISK"
    if score >= 30: return "MEDIUM RISK"
    if score >= 20: return "LOW RISK"
    return "CLEAN"

def quarantine(path):
    if os.path.abspath(path) == MY_PATH: return False
    try:
        name = os.path.basename(path)
        dest = os.path.join(QUARANTINE_DIR, name)
        shutil.move(path, dest)
        return True
    except: return False

# ================= UI =================
class MiniDefenderX:
    def __init__(self, root):
        self.root = root
        self.root.title("MiniDefender X")
        self.root.geometry("950x600")
        self.dark = tk.BooleanVar(value=True)
        self.auto_quarantine = tk.BooleanVar(value=True)
        self.scan_path = tk.StringVar()
        self.results = []
        self.threats_blocked = 0
        self.build_ui()
        self.apply_theme()

    def build_ui(self):
        main = tk.Frame(self.root)
        main.pack(fill="both", expand=True, padx=10, pady=10)
        
        header = tk.Frame(main); header.pack(fill="x")
        tk.Label(header, text="🛡 MiniDefender X", font=("Segoe UI", 18, "bold")).pack(side="left")
        tk.Checkbutton(header, text="Dark Mode", variable=self.dark, command=self.apply_theme).pack(side="right")
        
        dash = tk.Frame(main); dash.pack(fill="x", pady=5)
        self.status_lbl = tk.Label(dash, text="Protection: ACTIVE"); self.status_lbl.pack(side="left")
        self.threat_lbl = tk.Label(dash, text="Threats Blocked: 0"); self.threat_lbl.pack(side="right")
        
        card = tk.Frame(main, bd=2, relief="groove"); card.pack(fill="x", pady=8)
        row = tk.Frame(card); row.pack(fill="x", padx=10, pady=5)
        tk.Entry(row, textvariable=self.scan_path, width=55).pack(side="left", padx=5)
        tk.Button(row, text="Browse", command=self.browse).pack(side="left")
        tk.Button(row, text="Quick Scan", command=self.scan).pack(side="left", padx=5)
        tk.Button(row, text="Full PC Scan", command=self.full_scan).pack(side="left", padx=5)
        
        self.progress = ttk.Progressbar(main); self.progress.pack(fill="x", pady=5)
        self.listbox = tk.Listbox(main, font=("Consolas", 10), selectbackground="#444")
        self.listbox.pack(fill="both", expand=True)
        
        bottom = tk.Frame(main); bottom.pack(fill="x", pady=5)
        tk.Button(bottom, text="Quarantine Selected", command=self.quarantine_selected).pack(side="left", padx=5)
        tk.Button(bottom, text="View Logs", command=lambda: os.startfile(os.path.join(LOG_DIR, "scan_log.txt"))).pack(side="right")

    def apply_theme(self):
        bg = "#1e1e1e" if self.dark.get() else "#f5f5f5"
        fg = "#ffffff" if self.dark.get() else "#000000"
        self.root.configure(bg=bg)
        def paint(w):
            try: w.configure(bg=bg, fg=fg)
            except: pass
            for c in w.winfo_children(): paint(c)
        paint(self.root)

    def scan_files(self, files):
        self.listbox.delete(0, tk.END)
        self.results.clear()
        self.progress["maximum"] = len(files)

        for i, path in enumerate(files, 1):
            if os.path.abspath(path) == MY_PATH: continue
            try:
                score = threat_score(path)
                k_zone = cloud_scan_kaspersky(path)
                status = classify(score, k_zone)
                
                self.results.append((path, status))
                display = f"[{status}] {path}"
                if k_zone and k_zone != "Grey": display += f" (Cloud: {k_zone})"
                
                self.listbox.insert(tk.END, display)
                
                # --- EXTENDED COLOR LOGIC ---
                if status == "CRITICAL THREAT":
                    self.listbox.itemconfig(tk.END, fg="#ff3333") # Vivid Red
                    if self.auto_quarantine.get():
                        quarantine(path)
                        self.threats_blocked += 1
                elif status == "HIGH RISK":
                    self.listbox.itemconfig(tk.END, fg="#ff8c00") # Dark Orange
                elif status == "MEDIUM RISK":
                    self.listbox.itemconfig(tk.END, fg="#ffff00") # Yellow
                elif status == "LOW RISK":
                    self.listbox.itemconfig(tk.END, fg="#00ffff") # Cyan
                else:
                    self.listbox.itemconfig(tk.END, fg="#00ff00") # Green
                
                self.threat_lbl.config(text=f"Threats Blocked: {self.threats_blocked}")
                self.progress["value"] = i
                self.root.update_idletasks()
            except: continue

    def scan(self):
        folder = self.scan_path.get()
        if folder and os.path.exists(folder):
            files = [os.path.join(r, f) for r, _, fls in os.walk(folder) for f in fls]
            threading.Thread(target=self.scan_files, args=(files,), daemon=True).start()

    def full_scan(self):
        home = os.path.expanduser("~")
        folders = ["Desktop", "Downloads", "Documents"]
        files = []
        for fld in folders:
            p = os.path.join(home, fld)
            if os.path.exists(p):
                for r, _, fls in os.walk(p):
                    for f in fls: files.append(os.path.join(r, f))
        threading.Thread(target=self.scan_files, args=(files,), daemon=True).start()

    def browse(self):
        p = filedialog.askdirectory()
        if p: self.scan_path.set(p)

    def quarantine_selected(self):
        for i in reversed(self.listbox.curselection()):
            quarantine(self.results[i][0])
            self.listbox.delete(i)

if __name__ == "__main__":
    root = tk.Tk()
    MiniDefenderX(root)
    root.mainloop()