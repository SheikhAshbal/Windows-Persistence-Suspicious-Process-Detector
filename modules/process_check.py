"""
Module: Suspicious Process Scanner  v2.0
- Added TRUSTED_PATHS whitelist to eliminate Windows Defender false positives
MITRE ATT&CK: T1055, T1036
"""

TRUSTED_PATHS = [
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\program files\microsoft",
    r"c:\program files (x86)\microsoft",
    r"c:\programdata\microsoft\windows defender",
    r"c:\programdata\microsoft security client",
    r"c:\windows\microsoft.net",
    r"c:\program files\windows defender",
    r"c:\program files\windowsapps",
]

SUSPICIOUS_PATHS = [
    "\\temp\\", "\\appdata\\local\\temp\\", "\\programdata\\",
    "\\public\\", "\\recycle", "\\downloads\\"
]

MASQUERADE_TARGETS = {
    "svchost":   r"c:\windows\system32\svchost.exe",
    "lsass":     r"c:\windows\system32\lsass.exe",
    "csrss":     r"c:\windows\system32\csrss.exe",
    "winlogon":  r"c:\windows\system32\winlogon.exe",
    "explorer":  r"c:\windows\explorer.exe",
    "taskhostw": r"c:\windows\system32\taskhostw.exe",
    "spoolsv":   r"c:\windows\system32\spoolsv.exe",
    "services":  r"c:\windows\system32\services.exe",
    "wininit":   r"c:\windows\system32\wininit.exe",
}

def is_trusted(exe_path):
    p = (exe_path or "").lower()
    return any(p.startswith(t) for t in TRUSTED_PATHS)

def assess_severity(proc_name, exe_path):
    if is_trusted(exe_path):
        return "Trusted"
    name_lower = proc_name.lower().replace(".exe", "")
    path_lower = (exe_path or "").lower()
    if name_lower in MASQUERADE_TARGETS:
        expected = MASQUERADE_TARGETS[name_lower]
        if path_lower and not path_lower.startswith(expected[:20]):
            return "High"
    if any(p in path_lower for p in SUSPICIOUS_PATHS):
        return "High"
    return "Low"

def check_processes(is_windows=True):
    findings = []
    if is_windows:
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name", "exe", "username", "cmdline"]):
                try:
                    info = proc.info
                    name = info.get("name") or ""
                    exe  = info.get("exe") or ""
                    pid  = info.get("pid")
                    user = info.get("username") or "Unknown"
                    cmdline = " ".join(info.get("cmdline") or [])
                    severity = assess_severity(name, exe)
                    if severity in ("Low", "Trusted"):
                        continue
                    findings.append({
                        "name":     f"{name} (PID: {pid})",
                        "value":    exe or cmdline or "N/A",
                        "location": f"Running Processes — User: {user}",
                        "severity": severity,
                        "note":     get_note(name, exe, severity)
                    })
                except Exception:
                    continue
        except ImportError:
            findings.append({"name": "psutil not installed", "value": "pip install psutil",
                             "location": "Running Processes", "severity": "Low",
                             "note": "Install psutil to enable process scanning"})
    else:
        findings = [
            {"name": "svchost.exe (PID: 4821)",
             "value": r"C:\Users\Public\Temp\svchost.exe",
             "location": "Running Processes — User: DESKTOP-PC\\User",
             "severity": "High",
             "note": "Masquerading as Windows svchost.exe but running from Public\\Temp (T1036)"},
            {"name": "explorer.exe (PID: 7734)",
             "value": r"C:\Windows\Temp\explorer.exe",
             "location": "Running Processes — User: DESKTOP-PC\\Administrator",
             "severity": "High",
             "note": "Masquerading as Windows Explorer but running from Windows\\Temp"},
            {"name": "chrome.exe (PID: 3392)",
             "value": r"C:\Users\User\AppData\Local\Temp\chrome.exe",
             "location": "Running Processes — User: DESKTOP-PC\\User",
             "severity": "High",
             "note": "Browser process in AppData\\Local\\Temp — legitimate Chrome never runs from Temp"},
            {"name": "updater.exe (PID: 9102)",
             "value": r"C:\ProgramData\SystemCheck\updater.exe",
             "location": "Running Processes — User: SYSTEM",
             "severity": "High",
             "note": "Unknown process running as SYSTEM from ProgramData\\SystemCheck"},
        ]
    return findings

def get_note(name, exe, severity):
    name_lower = name.lower().replace(".exe", "")
    if name_lower in MASQUERADE_TARGETS and severity == "High":
        return f"Process name matches Windows system process but path is wrong: {exe} — likely masquerading (T1036)"
    if severity == "High":
        return f"Process running from suspicious path: {exe}"
    return "Within expected parameters"
