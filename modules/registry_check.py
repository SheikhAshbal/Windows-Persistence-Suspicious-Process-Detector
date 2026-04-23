"""
Module: Registry Run Keys Scanner
Checks HKCU and HKLM Run keys for suspicious persistence entries.
MITRE ATT&CK: T1547.001
"""

import os

SUSPICIOUS_PATHS = [
    "temp", "appdata\\local\\temp", "programdata", "%temp%",
    "downloads", "recycle", "public"
]

SUSPICIOUS_EXTENSIONS = [".exe", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".pif"]

KNOWN_LEGIT = [
    "onedrive", "teams", "discord", "steam", "zoom",
    "nvidia", "amd", "realtek", "windows security",
    "microsoft edge", "skype", "dropbox", "googledrive"
]

RUN_KEYS = [
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",        "HKCU"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",    "HKCU"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",        "HKLM"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",    "HKLM"),
    (r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
]

def assess_severity(name, value):
    val_lower = value.lower()
    name_lower = name.lower()

    if any(k in name_lower or k in val_lower for k in KNOWN_LEGIT):
        return "Low"

    if any(p in val_lower for p in SUSPICIOUS_PATHS):
        return "High"

    ext = os.path.splitext(val_lower.split(" ")[0].strip('"'))[-1]
    if ext in [".vbs", ".ps1", ".bat", ".cmd", ".scr", ".pif"]:
        return "High"

    if ext in SUSPICIOUS_EXTENSIONS:
        return "Medium"

    return "Low"

def check_registry(is_windows=True):
    findings = []

    if is_windows:
        try:
            import winreg
            hive_map = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}

            for key_path, hive_name in RUN_KEYS:
                hive = hive_map[hive_name]
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            severity = assess_severity(name, str(value))
                            findings.append({
                                "name": name,
                                "value": str(value),
                                "location": f"{hive_name}\\{key_path}",
                                "severity": severity,
                                "note": get_note(name, str(value))
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except PermissionError:
                    findings.append({
                        "name": "[Access Denied]",
                        "value": "Could not read key",
                        "location": f"{hive_name}\\{key_path}",
                        "severity": "Low",
                        "note": "Insufficient privileges to read this key"
                    })
                except FileNotFoundError:
                    pass
        except ImportError:
            pass
    else:
        # Demo mode — simulated findings
        findings = [
            {
                "name": "OneDrive",
                "value": r"C:\Program Files\Microsoft OneDrive\OneDrive.exe /background",
                "location": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "severity": "Low",
                "note": "Known legitimate Microsoft application"
            },
            {
                "name": "MicrosoftEdgeAutoLaunch",
                "value": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe --no-startup-window",
                "location": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "severity": "Low",
                "note": "Known legitimate browser autostart"
            },
            {
                "name": "svchost32",
                "value": r"C:\Users\Public\Temp\svchost32.exe -s",
                "location": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "severity": "High",
                "note": "Masquerading as Windows service; located in Public\\Temp — highly suspicious"
            },
            {
                "name": "updater",
                "value": r"C:\Users\User\AppData\Local\Temp\updater.vbs",
                "location": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                "severity": "High",
                "note": "VBScript in Temp directory — common malware persistence technique"
            },
            {
                "name": "NvBackend",
                "value": r"C:\Program Files (x86)\NVIDIA Corporation\Update Core\NvBackend.exe",
                "location": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "severity": "Low",
                "note": "Known NVIDIA background service"
            },
        ]

    return findings

def get_note(name, value):
    val_lower = value.lower()
    if any(p in val_lower for p in SUSPICIOUS_PATHS):
        return f"Executable located in suspicious path: {value}"
    if ".vbs" in val_lower or ".ps1" in val_lower:
        return "Script-based autorun — uncommon for legitimate software"
    if any(k in name.lower() for k in KNOWN_LEGIT):
        return "Matches known legitimate application"
    return "Review manually to confirm legitimacy"
