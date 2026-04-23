"""
Module: Scheduled Tasks Scanner
Checks for suspicious scheduled tasks using schtasks.
MITRE ATT&CK: T1053.005
"""

import subprocess
import re

SUSPICIOUS_PATHS = ["\\temp\\", "appdata\\local\\temp", "\\public\\", "\\recycle\\"]
SUSPICIOUS_EXTENSIONS = [".vbs", ".ps1", ".bat", ".cmd", ".scr"]
KNOWN_LEGIT_AUTHORS = [
    "microsoft", "windows", "nvidia", "amd", "realtek", "adobe",
    "google", "mozilla", "apple", "intel", "lenovo", "hp", "dell"
]
TRUSTED_TASK_PATHS = [
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\programdata\\microsoft\\windows defender\\",
    "c:\\program files\\windows defender\\",
    "c:\\program files\\microsoft",
    "c:\\program files (x86)\\microsoft",
]
TRUSTED_TASK_NAMES = [
    "windows defender", "mpcmdrun", "msascui",
    "windows update", "updateorchestrator",
    "defrag", "disk cleanup", "windows error reporting",
]

def assess_severity(task):
    task_name   = task.get("task_name", "").lower()
    run_as      = task.get("run_as_user", "").lower()
    task_to_run = task.get("task_to_run", "").lower()
    author      = task.get("author", "").lower()
    if any(leg in author for leg in KNOWN_LEGIT_AUTHORS):
        return "Low"
    if any(t in task_name for t in TRUSTED_TASK_NAMES):
        return "Low"
    if any(task_to_run.startswith(p) for p in TRUSTED_TASK_PATHS):
        return "Low"
    if any(p in task_to_run for p in SUSPICIOUS_PATHS):
        return "High"
    if any(ext in task_to_run for ext in SUSPICIOUS_EXTENSIONS):
        return "High"
    if "system" in run_as or "administrator" in run_as:
        return "Medium"
    return "Low"

def parse_schtasks_output(output):
    tasks = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            if current.get("task_name"):
                tasks.append(current)
            current = {}
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower().replace(" ", "_")
            val = val.strip()
            key_map = {
                "taskname": "task_name",
                "task_to_run": "task_to_run",
                "run_as_user": "run_as_user",
                "author": "author",
                "status": "status",
                "scheduled_task_state": "state",
                "trigger": "trigger",
            }
            mapped = key_map.get(key, key)
            current[mapped] = val
    if current.get("task_name"):
        tasks.append(current)
    return tasks

def check_scheduled_tasks(is_windows=True):
    findings = []

    if is_windows:
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "LIST", "/v"],
                capture_output=True, text=True, timeout=30
            )
            tasks = parse_schtasks_output(result.stdout)
            for task in tasks:
                severity = assess_severity(task)
                name = task.get("task_name", "Unknown")
                to_run = task.get("task_to_run", "N/A")
                author = task.get("author", "Unknown")
                run_as = task.get("run_as_user", "Unknown")
                findings.append({
                    "name": name,
                    "value": to_run,
                    "location": f"Scheduled Tasks — Author: {author} | Run As: {run_as}",
                    "severity": severity,
                    "note": get_note(task, severity)
                })
        except Exception as e:
            findings.append({
                "name": "Error",
                "value": str(e),
                "location": "schtasks",
                "severity": "Low",
                "note": "Could not enumerate scheduled tasks"
            })
    else:
        # Demo mode
        findings = [
            {
                "name": r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
                "value": r"%systemroot%\system32\usoclient.exe StartScan",
                "location": "Scheduled Tasks — Author: Microsoft | Run As: SYSTEM",
                "severity": "Low",
                "note": "Legitimate Windows Update task"
            },
            {
                "name": r"\Microsoft\Windows\Defrag\ScheduledDefrag",
                "value": r"%SystemRoot%\system32\defrag.exe -c -h -k -g -",
                "location": "Scheduled Tasks — Author: Microsoft | Run As: SYSTEM",
                "severity": "Low",
                "note": "Legitimate Windows Defrag task"
            },
            {
                "name": r"\WindowsUpdate",
                "value": r"C:\Users\Public\Temp\win_upd.ps1",
                "location": "Scheduled Tasks — Author: Unknown | Run As: SYSTEM",
                "severity": "High",
                "note": "PowerShell script in Public\\Temp masquerading as Windows Update — highly suspicious"
            },
            {
                "name": r"\GoogleUpdateTaskMachine",
                "value": r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe /ua /installsource scheduler",
                "location": "Scheduled Tasks — Author: Google LLC | Run As: SYSTEM",
                "severity": "Low",
                "note": "Legitimate Google Update task"
            },
            {
                "name": r"\SystemMaintenance",
                "value": r"C:\Windows\Temp\maint.bat",
                "location": "Scheduled Tasks — Author:  | Run As: Administrator",
                "severity": "High",
                "note": "Batch file in Windows Temp with no author — common dropper technique"
            },
        ]

    return findings

def get_note(task, severity):
    to_run = task.get("task_to_run", "").lower()
    author = task.get("author", "").lower()
    if severity == "High":
        return f"Suspicious executable path or script type detected: {task.get('task_to_run', '')}"
    if any(leg in author for leg in KNOWN_LEGIT_AUTHORS):
        return f"Author matches known vendor: {task.get('author', '')}"
    return "Unknown author — verify task legitimacy manually"
