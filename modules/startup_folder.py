"""
Module: Startup Folder Scanner
Checks user and system startup folders for suspicious entries.
MITRE ATT&CK: T1547.001
"""

import os

SUSPICIOUS_EXTENSIONS = [".exe", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".pif", ".jar"]
KNOWN_LEGIT = ["onedrive", "teams", "discord", "zoom", "slack", "steam", "dropbox", "googledrive"]

def get_startup_folders():
    folders = []
    appdata = os.environ.get("APPDATA", "")
    programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")

    user_startup = os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup")
    system_startup = os.path.join(programdata, r"Microsoft\Windows\Start Menu\Programs\Startup")

    if appdata:
        folders.append(("User Startup", user_startup))
    folders.append(("System Startup", system_startup))
    return folders

def assess_severity(filename, filepath):
    fname_lower = filename.lower()
    fpath_lower = filepath.lower()

    if any(k in fname_lower for k in KNOWN_LEGIT):
        return "Low"

    ext = os.path.splitext(fname_lower)[-1]
    if ext in [".vbs", ".ps1", ".bat", ".cmd", ".scr", ".pif"]:
        return "High"
    if ext == ".exe":
        return "Medium"
    if ext in [".lnk", ".url"]:
        return "Low"

    return "Low"

def check_startup_folder(is_windows=True):
    findings = []

    if is_windows:
        folders = get_startup_folders()
        for folder_name, folder_path in folders:
            if not os.path.exists(folder_path):
                continue
            try:
                for fname in os.listdir(folder_path):
                    fpath = os.path.join(folder_path, fname)
                    severity = assess_severity(fname, fpath)
                    size = "N/A"
                    try:
                        size = f"{os.path.getsize(fpath)} bytes"
                    except Exception:
                        pass

                    findings.append({
                        "name": fname,
                        "value": fpath,
                        "location": f"{folder_name}: {folder_path}",
                        "severity": severity,
                        "note": get_note(fname, fpath, severity, size)
                    })
            except PermissionError:
                findings.append({
                    "name": "[Access Denied]",
                    "value": folder_path,
                    "location": folder_name,
                    "severity": "Low",
                    "note": "Insufficient privileges to read startup folder"
                })
    else:
        # Demo mode
        findings = [
            {
                "name": "Discord.lnk",
                "value": r"C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Discord.lnk",
                "location": r"User Startup: C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
                "severity": "Low",
                "note": "Legitimate Discord shortcut — size: 1.2 KB"
            },
            {
                "name": "OneDrive.lnk",
                "value": r"C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\OneDrive.lnk",
                "location": r"User Startup: C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
                "severity": "Low",
                "note": "Legitimate OneDrive shortcut — size: 900 bytes"
            },
            {
                "name": "helper.vbs",
                "value": r"C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\helper.vbs",
                "location": r"User Startup: C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
                "severity": "High",
                "note": "VBScript in startup folder — no legitimate software uses this method. Size: 4.3 KB"
            },
            {
                "name": "sysmon.exe",
                "value": r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\sysmon.exe",
                "location": r"System Startup: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
                "severity": "Medium",
                "note": "Unknown executable in system startup — verify signature and origin"
            },
        ]

    return findings

def get_note(fname, fpath, severity, size):
    ext = os.path.splitext(fname.lower())[-1]
    if severity == "High":
        return f"Script/suspicious executable in startup folder — {size}. Investigate immediately."
    if severity == "Medium":
        return f"Executable in startup folder — verify digital signature. Size: {size}"
    return f"Appears legitimate — Size: {size}"
