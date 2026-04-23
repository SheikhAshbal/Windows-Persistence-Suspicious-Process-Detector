# Windows Persistence & Suspicious Process Detector
**Digital Forensics Semester Project — Mehran University of Engineering & Technology**

> Scans a Windows system for common persistence mechanisms and suspicious processes,
> then generates a structured HTML forensic report with MITRE ATT&CK mappings.

---

## Features

| Module | What it checks | MITRE TTP |
|---|---|---|
| Registry Scanner | HKCU/HKLM Run & RunOnce keys | T1547.001 |
| Scheduled Tasks | All auto-trigger tasks | T1053.005 |
| Startup Folder | User & system startup entries | T1547.001 |
| Services Scanner | Unknown auto-start services | T1543.003 |
| Process Scanner | Masquerading & suspicious path processes | T1036.005 |

---

## Requirements

- Python 3.8+
- Windows 10/11 (runs in demo mode on Linux/macOS)
- psutil library

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
python main.py
```

Enter your analyst name when prompted. The tool will:
1. Scan all 5 persistence categories
2. Print a live progress summary
3. Generate `output/forensic_report.html`
4. Auto-open the report in your browser

---

## Output

The HTML report includes:
- Executive summary with severity counts and overall risk rating
- Per-category findings tables with severity badges
- MITRE ATT&CK technique IDs for each category
- Analyst notes for each finding
- Conclusion and recommendations section

---

## Project Structure

```
persistence-detector/
├── main.py                    # Entry point
├── requirements.txt
├── modules/
│   ├── registry_check.py      # Registry Run Keys (T1547.001)
│   ├── scheduled_tasks.py     # Scheduled Tasks (T1053.005)
│   ├── startup_folder.py      # Startup Folder (T1547.001)
│   ├── services_check.py      # Windows Services (T1543.003)
│   └── process_check.py       # Process Masquerading (T1036.005)
├── report/
│   └── report_generator.py    # HTML report builder
└── output/
    └── forensic_report.html   # Generated report
```

---

## Demo Mode

On non-Windows systems, the tool runs with realistic simulated findings
so you can test and view the report on any OS.

---

## Academic Context

This project was developed as part of the Digital Forensics course (6th Semester, BS Cyber Security)
covering topics from the following TryHackMe rooms:
- Windows Forensics 1
- Compromised Windows Analysis
- Windows Threat Detection
- Unattended
- KAPE
- Case B4DM755
