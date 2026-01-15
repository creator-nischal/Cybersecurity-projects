#!/usr/bin/env python3
"""
filetype-extension-verifier (GUI)
- Choose a file OR a folder using a window
- Detect file type via magic numbers and warn on mismatches
- Optional recursive folder scan
- Optional export to CSV/JSON
- Shows SHA256 and header hex

Requirements: Python 3.x (Tkinter included on most Windows installs)
"""

import os
import csv
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Tuple, Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

MAGIC: List[Tuple[bytes, Tuple[str, str]]] = [
    (b"%PDF", ("pdf", "PDF document")),
    (b"\x89PNG\r\n\x1a\n", ("png", "PNG image")),
    (b"\xff\xd8\xff", ("jpg", "JPEG image")),
    (b"GIF87a", ("gif", "GIF image")),
    (b"GIF89a", ("gif", "GIF image")),
    (b"PK\x03\x04", ("zip", "ZIP archive (also DOCX/XLSX/PPTX)")),
    (b"Rar!\x1a\x07\x00", ("rar", "RAR archive")),
    (b"\x1f\x8b\x08", ("gz", "GZIP compressed file")),
    (b"MZ", ("exe", "Windows executable")),
]

EXT_ALIASES = {"jpeg": "jpg", "jpe": "jpg"}

OFFICE_HINTS = {
    "docx": [b"word/"],
    "xlsx": [b"xl/"],
    "pptx": [b"ppt/"],
}

DEFAULT_EXT_MAP = {
    "pdf": {"pdf"},
    "png": {"png"},
    "jpg": {"jpg", "jpeg", "jpe"},
    "gif": {"gif"},
    "zip": {"zip"},
    "rar": {"rar"},
    "gz": {"gz"},
    "exe": {"exe"},
    "docx": {"docx"},
    "xlsx": {"xlsx"},
    "pptx": {"pptx"},
}

def get_extension(path: str) -> str:
    _, ext = os.path.splitext(path)
    ext = ext.lower().lstrip(".")
    return EXT_ALIASES.get(ext, ext)

def detect_type(header: bytes) -> Tuple[str, str]:
    for sig, info in MAGIC:
        if header.startswith(sig):
            return info
    return ("unknown", "Unknown")

def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def sniff_office_type(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            chunk = f.read(400_000)
    except Exception:
        return None

    for ext, markers in OFFICE_HINTS.items():
        if any(m in chunk for m in markers):
            return ext
    return None

def classify(path: str) -> Dict:
    ext = get_extension(path)

    try:
        size = os.path.getsize(path)
    except Exception:
        size = None

    try:
        with open(path, "rb") as f:
            header = f.read(16)
    except Exception as e:
        return {
            "path": path,
            "filename": os.path.basename(path),
            "extension": ext or "",
            "detected_id": "error",
            "detected_label": f"ERROR: {e}",
            "match": False,
            "reason": "open_failed",
            "header_hex": "",
            "sha256": "",
            "size_bytes": size,
        }

    if not header:
        return {
            "path": path,
            "filename": os.path.basename(path),
            "extension": ext or "",
            "detected_id": "unknown",
            "detected_label": "Empty file",
            "match": False,
            "reason": "empty_file",
            "header_hex": "",
            "sha256": "",
            "size_bytes": size,
        }

    detected_id, detected_label = detect_type(header)

    if detected_id == "zip":
        office_guess = sniff_office_type(path)
        if office_guess:
            detected_id = office_guess
            detected_label = f"{office_guess.upper()} (Office ZIP container)"

    digest = ""
    try:
        digest = sha256_file(path)
    except Exception:
        digest = ""

    if not ext:
        match = False
        reason = "no_extension"
    elif detected_id in ("unknown", "error"):
        match = False
        reason = "unknown_type"
    else:
        allowed = DEFAULT_EXT_MAP.get(detected_id, {detected_id})
        match = ext in allowed
        reason = "match" if match else "mismatch"

    return {
        "path": path,
        "filename": os.path.basename(path),
        "extension": ext or "",
        "detected_id": detected_id,
        "detected_label": detected_label,
        "match": match,
        "reason": reason,
        "header_hex": header.hex(),
        "sha256": digest,
        "size_bytes": size,
    }

def iter_files(directory: str, recursive: bool) -> List[str]:
    files: List[str] = []
    if recursive:
        for root, _, filenames in os.walk(directory):
            for name in filenames:
                p = os.path.join(root, name)
                if os.path.isfile(p):
                    files.append(p)
    else:
        for name in os.listdir(directory):
            p = os.path.join(directory, name)
            if os.path.isfile(p):
                files.append(p)
    return files

def export_csv(results: List[Dict], out_path: str) -> None:
    if not results:
        return
    fieldnames = list(results[0].keys())
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

def export_json(results: List[Dict], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        style = ttk.Style(self)
        style.configure("Treeview", rowheight=26)
        self.title("filetype-extension-verifier")
        self.geometry("980x560")
        self.minsize(900, 520)

        self.results: List[Dict] = []
        self.target_label_var = tk.StringVar(value="No target selected.")

        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="filetype-extension-verifier", font=("Segoe UI", 16, "bold")).pack(side="left")
        ttk.Label(top, text="(Verify real file type using signatures + warn on extension spoofing)").pack(side="left", padx=10)

        controls = ttk.Frame(self, padding=(10, 0, 10, 10))
        controls.pack(fill="x")

        ttk.Button(controls, text="Select File", command=self.select_file).pack(side="left")
        ttk.Button(controls, text="Select Folder", command=self.select_folder).pack(side="left", padx=8)

        self.recursive_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(controls, text="Recursive scan (for folders)", variable=self.recursive_var).pack(side="left", padx=8)

        ttk.Button(controls, text="Run Scan", command=self.run_scan).pack(side="left", padx=8)
        ttk.Button(controls, text="Clear", command=self.clear).pack(side="left")

        ttk.Separator(controls, orient="vertical").pack(side="left", fill="y", padx=10)

        ttk.Button(controls, text="Export CSV", command=self.export_csv_ui).pack(side="left")
        ttk.Button(controls, text="Export JSON", command=self.export_json_ui).pack(side="left", padx=8)

        ttk.Label(self, textvariable=self.target_label_var, padding=(10, 0, 10, 10)).pack(fill="x")

        table_frame = ttk.Frame(self, padding=10)
        table_frame.pack(fill="both", expand=True)

        cols = ("status", "filename", "extension", "detected", "size", "sha256")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=14)

        self.tree.heading("status", text="Status")
        self.tree.heading("filename", text="File")
        self.tree.heading("extension", text="Ext")
        self.tree.heading("detected", text="Detected")
        self.tree.heading("size", text="Size (bytes)")
        self.tree.heading("sha256", text="SHA256")

        self.tree.column("status", width=80, minwidth=80, stretch=False, anchor="center")
        self.tree.column("filename", width=420, minwidth=220, stretch=True, anchor="w")
        self.tree.column("extension", width=70, minwidth=70, stretch=False, anchor="center")
        self.tree.column("detected", width=220, minwidth=180, stretch=False, anchor="w")
        self.tree.column("size", width=140, minwidth=120, stretch=False, anchor="center")
        self.tree.column("sha256", width=520, minwidth=350, stretch=True, anchor="w")

        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(xscroll=hsb.set)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)

        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")

        self.tree.bind("<Double-1>", self.show_details)

        self.status_var = tk.StringVar(value="Ready.")
        status = ttk.Label(self, textvariable=self.status_var, padding=8, relief="sunken", anchor="w")
        status.pack(fill="x", side="bottom")

        self.target: Optional[Tuple[str, str]] = None

    def select_file(self):
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            self.target = ("file", path)
            self.target_label_var.set(f"Selected file: {path}")
            self.status_var.set("File selected. Click 'Run Scan'.")

    def select_folder(self):
        path = filedialog.askdirectory(title="Select a folder")
        if path:
            self.target = ("dir", path)
            self.target_label_var.set(f"Selected folder: {path}")
            self.status_var.set("Folder selected. Click 'Run Scan'.")

    def clear(self):
        self.results = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.target = None
        self.target_label_var.set("No target selected.")
        self.status_var.set("Cleared. Ready.")

    def run_scan(self):
        if not self.target:
            messagebox.showwarning("No target", "Please select a file or a folder first.")
            return

        kind, path = self.target
        self.status_var.set("Scanning...")

        paths: List[str]
        if kind == "file":
            paths = [path]
        else:
            paths = iter_files(path, recursive=self.recursive_var.get())

        self.results = []
        for p in paths:
            if os.path.isfile(p):
                self.results.append(classify(p))

        for item in self.tree.get_children():
            self.tree.delete(item)

        mismatches = 0
        for r in self.results:
            if r["reason"] == "match":
                status = "OK"
            elif r["reason"] == "mismatch":
                status = "WARN"
                mismatches += 1
            else:
                status = "INFO"

            self.tree.insert("", "end", values=(
                status,
                r["filename"],
                r["extension"] or "(none)",
                r["detected_label"],
                r["size_bytes"] if r["size_bytes"] is not None else "",
                r["sha256"],
            ))

        self.status_var.set(f"Scan complete. Files: {len(self.results)} | Mismatches: {mismatches}")

        if mismatches > 0:
            messagebox.showinfo("Scan complete", f"Scan complete.\nMismatches found: {mismatches}\nDouble-click a row to see details.")
        else:
            messagebox.showinfo("Scan complete", "Scan complete.\nNo mismatches found.")

    def export_csv_ui(self):
        if not self.results:
            messagebox.showwarning("No results", "Run a scan first.")
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = filedialog.asksaveasfilename(
            title="Save CSV report",
            defaultextension=".csv",
            initialfile=f"filetype-extension-verifier_{ts}.csv",
            filetypes=[("CSV files", "*.csv")]
        )
        if out:
            export_csv(self.results, out)
            messagebox.showinfo("Saved", f"CSV saved:\n{out}")

    def export_json_ui(self):
        if not self.results:
            messagebox.showwarning("No results", "Run a scan first.")
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = filedialog.asksaveasfilename(
            title="Save JSON report",
            defaultextension=".json",
            initialfile=f"filetype-extension-verifier_{ts}.json",
            filetypes=[("JSON files", "*.json")]
        )
        if out:
            export_json(self.results, out)
            messagebox.showinfo("Saved", f"JSON saved:\n{out}")

    def show_details(self, _event=None):
        selected = self.tree.focus()
        if not selected:
            return

        idx = self.tree.index(selected)
        if idx < 0 or idx >= len(self.results):
            return

        r = self.results[idx]
        detail = (
            f"Path: {r['path']}\n"
            f"Extension: {r['extension'] or '(none)'}\n"
            f"Detected: {r['detected_label']} ({r['detected_id']})\n"
            f"Match: {r['match']} (reason: {r['reason']})\n"
            f"Size: {r['size_bytes']}\n"
            f"Header (hex): {r['header_hex']}\n"
            f"SHA256: {r['sha256']}\n"
        )
        messagebox.showinfo("File details", detail)

if __name__ == "__main__":
    try:
        App().mainloop()
    except Exception as e:
        try:
            print("FATAL:", repr(e))
            messagebox.showerror("Fatal error", f"{type(e).__name__}: {e}")
        except Exception:
            print("FATAL (messagebox failed):", repr(e))
        raise
