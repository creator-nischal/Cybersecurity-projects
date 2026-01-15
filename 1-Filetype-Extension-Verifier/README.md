
Create README for 1-Filetype-Extension-Verifier
Jan 15
·
Cybersecurity-projects
·
main
·
+36
-5

Archive

Share

Create PR


can you help me write a readme for my project 1-Filetype-Extension-Verifier
Copy
Summary

Expanded the README with requirements, usage guidance, output field descriptions, export notes, and general usage context for the tool.

Testing

Not run (documentation-only change).


File (1)

README.md
1-Filetype-Extension-Verifier/README.md
+36
-5



Diff
Logs

1-Filetype-Extension-Verifier/README.md
1-Filetype-Extension-Verifier/README.md
+36
-5

# Filetype Extension Verifier (Magic Number Checker)

A Python GUI tool that verifies a file’s **real type** using magic numbers (file signatures) and warns when the **extension doesn’t match** (extension spoofing).
A Python GUI tool that verifies a file’s **real type** using magic numbers (file signatures) and warns when the **extension doesn’t match** (extension spoofing). It is useful for quick triage of suspicious files and spotting disguised payloads.

## Features
- Select **file** or **folder**
- Optional **recursive scan**
- Scan a **single file** or **entire folder**
- Optional **recursive** folder scan
- Detects: PDF, PNG, JPG/JPEG, GIF, ZIP, DOCX/XLSX/PPTX, RAR, GZ, EXE
- Shows **SHA256** and header hex
- Export scan results to **CSV/JSON**
- Shows **SHA256** hashes and file header hex
- Export scan results to **CSV** or **JSON**
- Double-click a row to view full details

## Requirements
- Python 3.x
- Tkinter (bundled with most Python installs on Windows/macOS; for some Linux distros you may need to install `python3-tk`)

## Run
```bash
python filetype-extension-verifier.py
```

## How it works
1. Select a file or folder.
2. The app reads the file header and compares it to known magic numbers.
3. It maps known ZIP-based Office signatures (DOCX/XLSX/PPTX) when applicable.
4. It compares the detected signature to the file extension and flags mismatches.

## Output fields
Each scan result includes:
- **Status**: OK / WARN / INFO
- **File**: filename
- **Ext**: file extension (normalized to lower-case)
- **Detected**: detected type label from magic numbers
- **Size (bytes)**: file size
- **SHA256**: content hash

Double-click any row to view full details such as full path, header hex, and the specific mismatch reason.

## Exporting results
Use **Export CSV** or **Export JSON** after a scan to save the results. Files are timestamped by default.

## Notes
- Files with **no extension** or **unknown signatures** are marked as INFO.
- ZIP containers are further inspected for Office-specific paths to detect DOCX/XLSX/PPTX.

## License
Add your preferred license here.
