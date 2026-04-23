"""Report Generator v3.0 — PDF download + Remediation section"""
import os, datetime

MITRE_MAP = {
    "Registry Run Keys":    ("T1547.001","Boot or Logon Autostart: Registry Run Keys"),
    "Scheduled Tasks":      ("T1053.005","Scheduled Task/Job: Scheduled Task"),
    "Startup Folder":       ("T1547.001","Boot or Logon Autostart: Startup Folder"),
    "Suspicious Services":  ("T1543.003","Create or Modify System Process: Windows Service"),
    "Suspicious Processes": ("T1036.005","Masquerading: Match Legitimate Name or Location"),
}
CATEGORY_ICONS = {"Registry Run Keys":"KEY","Scheduled Tasks":"CLK","Startup Folder":"DIR","Suspicious Services":"SVC","Suspicious Processes":"PRC"}
SEV_STYLE = {
    "High":   ("border:1px solid #ff4444;background:#2a0808;color:#ff6666;","#ff4444"),
    "Medium": ("border:1px solid #ff9900;background:#2a1800;color:#ffbb44;","#ff9900"),
    "Low":    ("border:1px solid #22aa55;background:#081a0f;color:#44cc77;","#22aa55"),
}

# Remediation steps per category and severity
REMEDIATIONS = {
    "Registry Run Keys": {
        "High": [
            "Open Registry Editor (regedit.exe) as Administrator",
            "Navigate to the flagged key path shown in the Location column",
            "Right-click the suspicious entry and select Delete",
            "Verify the executable file exists — if found in Temp/AppData, delete it",
            "Run a full antivirus scan immediately after removal",
            "Check Event Viewer > Windows Logs > System for related entries",
        ],
        "Medium": [
            "Verify the publisher of the flagged executable (right-click > Properties > Digital Signatures)",
            "If unsigned or unknown publisher, remove the registry entry via regedit.exe",
            "Monitor the key for re-appearance after reboot using Autoruns (Sysinternals)",
        ],
        "Low": [
            "No immediate action required — entry matches known legitimate software",
            "Periodically review with Autoruns (Sysinternals) to track changes",
        ],
    },
    "Scheduled Tasks": {
        "High": [
            "Open Task Scheduler (taskschd.msc) as Administrator",
            "Locate the flagged task in the Task Scheduler Library",
            "Right-click the task and select Disable, then Delete after confirming it is malicious",
            "Delete the associated executable/script if located in Temp or AppData",
            "Run: schtasks /delete /tn \"<TaskName>\" /f  from an admin command prompt",
            "Check for re-creation after reboot — may indicate a dropper is still active",
        ],
        "Medium": [
            "Review the task's action, trigger, and Run As user in Task Scheduler",
            "Verify the binary's digital signature before taking action",
            "If author is blank and binary is unknown, disable the task pending investigation",
        ],
        "Low": [
            "No immediate action required",
            "Verify task details in Task Scheduler if concerned",
        ],
    },
    "Startup Folder": {
        "High": [
            "Open the startup folder: Win+R > shell:startup",
            "Delete the flagged script or executable immediately",
            "Also check: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "Scan the deleted file's hash on VirusTotal before permanent deletion",
            "Check if the file re-appears after reboot",
        ],
        "Medium": [
            "Verify the digital signature of the flagged executable",
            "If unsigned, remove it from the startup folder and monitor",
        ],
        "Low": [
            "No action required — shortcut appears legitimate",
            "Verify the target application is still installed and expected",
        ],
    },
    "Suspicious Services": {
        "High": [
            "Open Services (services.msc) as Administrator",
            "Locate the flagged service, right-click > Properties > set Startup type to Disabled",
            "Stop the service: net stop <ServiceName>",
            "Delete the service: sc delete <ServiceName>  from admin command prompt",
            "Delete the associated binary if located in a suspicious path",
            "Check for related registry key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName>",
        ],
        "Medium": [
            "Review the service binary path and verify its digital signature",
            "If the service is unknown and auto-starting, set to Manual startup type",
            "Monitor with Process Monitor (Sysinternals) to see what it does at runtime",
        ],
        "Low": [
            "No action required — service appears to be a known Windows component",
        ],
    },
    "Suspicious Processes": {
        "High": [
            "Do NOT kill the process immediately — first capture memory: procdump -ma <PID>",
            "Document the full path, PID, parent process, and open network connections",
            "Check parent process in Process Explorer (Sysinternals) to trace origin",
            "Kill the process: taskkill /PID <PID> /F",
            "Delete the executable from the suspicious path",
            "Identify and remove the persistence mechanism that launched it (check registry, tasks, services)",
            "Consider isolating the machine from the network until investigation is complete",
        ],
        "Medium": [
            "Investigate the parent process and launch chain in Process Explorer",
            "Verify the binary's digital signature and hash on VirusTotal",
            "If suspicious, terminate and trace how it was started",
        ],
        "Low": [
            "Process appears to be within expected parameters",
            "Monitor with Process Monitor if behavior seems unusual at runtime",
        ],
    },
}

GENERAL_REMEDIATIONS = [
    ("Immediate — High findings", "#ff4444", [
        "Isolate the machine from the network if active compromise is suspected",
        "Take a memory dump before killing any processes: use ProcDump or WinPmem",
        "Document all High findings with screenshots before making changes",
        "Remove malicious persistence entries (see per-category steps above)",
        "Run a full scan with Windows Defender and Malwarebytes",
    ]),
    ("Short-term — Hardening", "#ff9900", [
        "Enable Windows Defender Tamper Protection (Settings > Windows Security > Virus & threat protection)",
        "Enable Attack Surface Reduction (ASR) rules via Group Policy or Intune",
        "Restrict write access to Temp directories using AppLocker or Software Restriction Policies",
        "Audit scheduled tasks weekly using Autoruns (Sysinternals) — free tool",
        "Enable PowerShell Script Block Logging (HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell)",
    ]),
    ("Long-term — Prevention", "#22aa55", [
        "Deploy Sysmon (Sysinternals) for detailed process creation and registry logging",
        "Forward Windows event logs to a SIEM (Wazuh, Splunk) for continuous monitoring",
        "Implement application whitelisting with Windows Defender Application Control (WDAC)",
        "Establish a baseline of autoruns after clean install and diff on every scan",
        "Run this tool as a scheduled task weekly and review any NEW findings immediately",
    ]),
]

def sev_badge(sev, extra=""):
    style,_=SEV_STYLE.get(sev,("border:1px solid #888;background:#222;color:#aaa;","#888"))
    return f'<span class="badge" style="{style}">{sev}{extra}</span>'

def vt_badge(vt):
    if not vt: return '<span class="badge" style="border:1px solid #444;background:#1a1a1a;color:#666;">No VT</span>'
    m=vt.get("malicious",0); ratio=vt.get("ratio","N/A"); link=vt.get("link","")
    if m==0:   style="border:1px solid #22aa55;background:#081a0f;color:#44cc77;"; label=f"VT:{ratio} ✓"
    elif m<=5: style="border:1px solid #ff9900;background:#2a1800;color:#ffbb44;"; label=f"VT:{ratio} ⚠"
    else:      style="border:1px solid #ff4444;background:#2a0808;color:#ff6666;"; label=f"VT:{ratio} ✗"
    if link: return f'<a href="{link}" target="_blank" class="badge" style="{style}text-decoration:none;">{label}</a>'
    return f'<span class="badge" style="{style}">{label}</span>'

def e(t): return str(t).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def build_remediation_section(findings):
    """Build per-category remediation cards based on actual findings."""
    cards = ""
    for category, items in findings.items():
        if not items: continue
        has_high   = any(f.get("severity")=="High"   for f in items)
        has_medium = any(f.get("severity")=="Medium" for f in items)
        if not has_high and not has_medium: continue

        cat_rems = REMEDIATIONS.get(category, {})
        steps_html = ""

        for sev_label, color, key in [("High","#ff4444","High"),("Medium","#ff9900","Medium")]:
            sev_items = [f for f in items if f.get("severity")==key]
            if not sev_items: continue
            steps = cat_rems.get(key, ["Review and investigate the flagged entry manually."])
            steps_html += f'<div class="rem-sev-block" style="border-left:3px solid {color};padding-left:14px;margin-bottom:14px;">'
            steps_html += f'<div class="rem-sev-label" style="color:{color};">{key} Severity — {len(sev_items)} finding{"s" if len(sev_items)>1 else ""}</div>'
            steps_html += '<ol class="rem-steps">'
            for step in steps:
                steps_html += f'<li>{e(step)}</li>'
            steps_html += '</ol></div>'

        icon = CATEGORY_ICONS.get(category,"···")
        mitre_id = MITRE_MAP.get(category,("N/A",""))[0]
        cards += f'''
<div class="rem-card">
  <div class="rem-card-header">
    <span class="sec-icon">{icon}</span>
    <div>
      <div class="rem-card-title">{e(category)}</div>
      <div class="mitre-tag">MITRE: {e(mitre_id)}</div>
    </div>
  </div>
  <div class="rem-card-body">{steps_html}</div>
</div>'''

    # General remediation panels
    general = ""
    for title, color, steps in GENERAL_REMEDIATIONS:
        items_html = "".join(f"<li>{e(s)}</li>" for s in steps)
        general += f'<div class="rem-general" style="border-left:4px solid {color};"><div class="rem-general-title" style="color:{color};">{e(title)}</div><ul class="rem-steps">{items_html}</ul></div>'

    return f'''
<div class="section" id="remediation">
  <div class="section-header">
    <div class="section-title">
      <span class="sec-icon" style="color:#a78bfa;">REM</span>
      <div>
        <h2>Remediation Guide</h2>
        <div class="mitre-tag">Step-by-step actions for each finding category</div>
      </div>
    </div>
  </div>
  <div class="rem-body">
    <div class="rem-grid">{cards}</div>
    <div class="rem-general-section">
      <div class="rem-general-title-main">General Security Recommendations</div>
      <div class="rem-general-grid">{general}</div>
    </div>
  </div>
</div>'''

def generate_report(findings, hostname, analyst, scan_time,
                    vt_results=None, diff=None, new_findings=None,
                    removed_findings=None, prev_scan_time=None, is_first_scan=True):
    vt_results=vt_results or []; new_findings=new_findings or []; removed_findings=removed_findings or []
    total=sum(len(v) for v in findings.values())
    high=sum(1 for v in findings.values() for f in v if f.get("severity")=="High")
    medium=sum(1 for v in findings.values() for f in v if f.get("severity")=="Medium")
    low=sum(1 for v in findings.values() for f in v if f.get("severity")=="Low")
    new_count=len(new_findings); scan_end=datetime.datetime.now()
    risk_level="CRITICAL" if high>=3 else "HIGH" if high>=1 else "MEDIUM" if medium>=2 else "LOW"
    risk_color={"CRITICAL":"#cc0000","HIGH":"#ff4444","MEDIUM":"#ff9900","LOW":"#22aa55"}[risk_level]

    sb=""
    for cat in findings:
        icon=CATEGORY_ICONS.get(cat,"···"); anchor=cat.lower().replace(" ","-").replace("&","")
        cat_high=sum(1 for f in findings[cat] if f.get("severity")=="High")
        badge=f'<span class="sb-badge">{cat_high}</span>' if cat_high else ""
        sb+=f'<a href="#{anchor}" class="sb-link"><span class="sb-icon">{icon}</span><span class="sb-label">{e(cat)}</span>{badge}</a>\n'
    extra='<a href="#remediation" class="sb-link"><span class="sb-icon" style="color:#a78bfa;">REM</span><span class="sb-label">Remediation</span></a>\n'
    if vt_results: extra+='<a href="#virustotal" class="sb-link"><span class="sb-icon">VT</span><span class="sb-label">VirusTotal</span></a>\n'
    if not is_first_scan:
        ncb=f'<span class="sb-badge sb-new">{new_count}</span>' if new_count else ""
        extra+=f'<a href="#scan-diff" class="sb-link"><span class="sb-icon">DIFF</span><span class="sb-label">Scan Diff</span>{ncb}</a>\n'

    secs=""
    for category,items in findings.items():
        if not items: continue
        mitre_id,mitre_name=MITRE_MAP.get(category,("N/A","N/A"))
        icon=CATEGORY_ICONS.get(category,"···"); anchor=category.lower().replace(" ","-").replace("&","")
        ch=sum(1 for f in items if f.get("severity")=="High")
        cm=sum(1 for f in items if f.get("severity")=="Medium")
        cl=sum(1 for f in items if f.get("severity")=="Low")
        rows=""
        for f in items:
            sev=f.get("severity","Low"); _,lcol=SEV_STYLE.get(sev,("","#888"))
            ntag=' <span class="new-tag">NEW</span>' if f.get("is_new") else ""
            vd=f.get("vt"); sha=f.get("sha256","")
            sha_d=f'<div class="sha">{sha[:20]}…</div>' if sha else ""
            rows+=f'<tr style="border-left:3px solid {lcol};"><td><code>{e(f.get("name",""))}</code>{ntag}</td><td><code class="path">{e(f.get("value",""))}</code>{sha_d}</td><td class="loc-cell">{e(f.get("location",""))}</td><td>{sev_badge(sev)}{("<br>"+vt_badge(vd)) if vd else ""}</td><td>{e(f.get("note",""))}</td></tr>'
        secs+=f'<div class="section" id="{anchor}"><div class="section-header"><div class="section-title"><span class="sec-icon">{icon}</span><div><h2>{e(category)}</h2><div class="mitre-tag">MITRE ATT&CK: <strong>{e(mitre_id)}</strong> — {e(mitre_name)}</div></div></div><div class="sec-counts"><span class="mini-badge high">{ch} High</span><span class="mini-badge medium">{cm} Med</span><span class="mini-badge low">{cl} Low</span></div></div><div class="table-wrap"><table><thead><tr><th style="width:18%">Name</th><th style="width:24%">Value/Path</th><th style="width:20%">Location</th><th style="width:9%">Severity</th><th>Note</th></tr></thead><tbody>{rows}</tbody></table></div></div>'

    vt_sec=""
    if vt_results:
        flagged=sum(1 for r in vt_results if r["vt"].get("malicious",0)>0)
        clean=len(vt_results)-flagged; vtr=""
        for r in vt_results:
            vt=r["vt"]; m=vt.get("malicious",0); link=vt.get("link","")
            rc="#2a0808" if m>5 else "#2a1800" if m>0 else "#081a0f"
            href=f'<a href="{link}" target="_blank" style="color:#4a9eff;font-size:11px;">View</a>' if link else ""
            vtr+=f'<tr style="background:{rc}20;"><td><code>{e(r.get("name",""))}</code></td><td><code class="path">{e(r.get("exe_path",""))}</code></td><td><code style="font-size:10px;">{e(r.get("sha256","")[:28])}…</code></td><td>{sev_badge(r.get("severity","Low"))}</td><td>{vt_badge(vt)}</td><td>{href}</td></tr>'
        vt_sec=f'<div class="section" id="virustotal"><div class="section-header"><div class="section-title"><span class="sec-icon" style="color:#4a9eff;">VT</span><div><h2>VirusTotal Hash Lookup</h2><div class="mitre-tag">SHA256 verification of High &amp; Medium findings</div></div></div><div class="sec-counts"><span class="mini-badge high">{flagged} Flagged</span><span class="mini-badge low">{clean} Clean</span></div></div><div class="table-wrap"><table><thead><tr><th>Name</th><th>Path</th><th>SHA256</th><th>Severity</th><th>VT</th><th>Link</th></tr></thead><tbody>{vtr}</tbody></table></div></div>'

    diff_sec=""
    if not is_first_scan and diff is not None:
        prev_str=prev_scan_time.strftime("%Y-%m-%d %H:%M:%S") if prev_scan_time else "Unknown"
        dr="".join(f'<tr><td>{e(cat)}</td><td>{d["total"]}</td><td><span class="mini-badge {"high" if d["new"] else "low"}">{d["new"]} New</span></td><td><span class="mini-badge {"medium" if d["removed"] else "low"}">{d["removed"]} Removed</span></td><td>{d["unchanged"]}</td></tr>' for cat,d in diff.items())
        nr="".join(f'<tr><td>{e(f.get("category",""))}</td><td><code>{e(f.get("name",""))}</code></td><td><code class="path">{e(f.get("value",""))}</code></td><td>{sev_badge(f.get("severity","Low"))}</td><td>{e(f.get("note",""))}</td></tr>' for f in new_findings)
        nt=(f'<h3 style="color:#ff9900;margin:16px 22px 6px;font-size:12px;font-family:monospace;letter-spacing:1px;">NEW FINDINGS since last scan</h3><div class="table-wrap"><table><thead><tr><th>Category</th><th>Name</th><th>Value</th><th>Severity</th><th>Note</th></tr></thead><tbody>{nr}</tbody></table></div>' if new_findings else '<p style="padding:14px 22px;color:#44cc77;font-family:monospace;">&#10003; No new findings since last scan.</p>')
        diff_sec=f'<div class="section" id="scan-diff"><div class="section-header"><div class="section-title"><span class="sec-icon" style="color:#ff9900;">DIFF</span><div><h2>Scan Comparison</h2><div class="mitre-tag">vs previous scan: {e(prev_str)}</div></div></div><div class="sec-counts"><span class="mini-badge high">{len(new_findings)} New</span><span class="mini-badge medium">{len(removed_findings)} Removed</span></div></div><div class="table-wrap"><table><thead><tr><th>Category</th><th>Total</th><th>New</th><th>Removed</th><th>Unchanged</th></tr></thead><tbody>{dr}</tbody></table></div>{nt}</div>'

    remediation_sec = build_remediation_section(findings)

    conclusion_text = f"Scan on <strong style='color:#e0e8f8'>{e(hostname)}</strong> identified <strong style='color:#e0e8f8'>{total} findings</strong> with <strong style='color:#ff6666'>{high} high-severity</strong> indicators. "
    if not is_first_scan and new_count > 0:
        conclusion_text += f"<strong style='color:#ffbb44'>{new_count} new findings</strong> detected since last scan — investigate immediately. "
    elif not is_first_scan:
        conclusion_text += "No changes detected since last scan. "
    else:
        conclusion_text += "Baseline saved — future scans will highlight new persistence entries. "
    conclusion_text += "Refer to the Remediation Guide section for step-by-step instructions on each finding."

    report_filename = f"forensic_report_{hostname}_{scan_time.strftime('%Y%m%d_%H%M%S')}.html"
    new_stat = f'<div class="sb-stat"><span class="sb-stat-label">NEW</span><span class="sb-stat-val medium">{new_count}</span></div>' if not is_first_scan else ""

    html=f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Forensic Report — {e(hostname)}</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}
body{{font-family:'IBM Plex Sans',sans-serif;background:#0a0e1a;color:#c8d0e0;font-size:14px;line-height:1.6;display:flex;min-height:100vh;}}
.sidebar{{width:210px;flex-shrink:0;background:#080c18;border-right:1px solid #1e3a5f;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto;}}
.sb-logo{{padding:18px 14px 12px;border-bottom:1px solid #1e3a5f;}}
.sb-logo-title{{font-size:11px;font-family:'IBM Plex Mono',monospace;color:#4a9eff;letter-spacing:1.5px;text-transform:uppercase;}}
.sb-logo-sub{{font-size:10px;color:#405060;margin-top:2px;}}
.sb-section-label{{font-size:9px;font-family:'IBM Plex Mono',monospace;color:#304050;letter-spacing:2px;text-transform:uppercase;padding:14px 14px 6px;}}
.sb-link{{display:flex;align-items:center;gap:10px;padding:9px 14px;text-decoration:none;color:#7090b0;font-size:12px;border-left:2px solid transparent;transition:all 0.15s;}}
.sb-link:hover,.sb-link.active{{color:#c8d8f0;background:#0d1526;border-left-color:#4a9eff;}}
.sb-icon{{font-size:9px;font-family:'IBM Plex Mono',monospace;font-weight:600;background:#1a2a40;color:#4a9eff;padding:2px 5px;border-radius:3px;flex-shrink:0;letter-spacing:.5px;min-width:32px;text-align:center;}}
.sb-label{{flex:1;}}
.sb-badge{{font-size:10px;font-family:'IBM Plex Mono',monospace;font-weight:600;background:#3a0a0a;color:#ff6666;border:1px solid #ff444433;padding:1px 6px;border-radius:10px;}}
.sb-badge.sb-new{{background:#2a1800;color:#ffbb44;border-color:#ff990033;}}
.sb-stats{{margin-top:auto;padding:14px;border-top:1px solid #1e3a5f;}}
.sb-stat{{display:flex;justify-content:space-between;font-size:11px;padding:3px 0;}}
.sb-stat-label{{color:#405060;font-family:'IBM Plex Mono',monospace;}}
.sb-stat-val{{font-family:'IBM Plex Mono',monospace;font-weight:600;}}
.sb-stat-val.high{{color:#ff4444;}}.sb-stat-val.medium{{color:#ff9900;}}.sb-stat-val.low{{color:#22aa55;}}
.main{{flex:1;min-width:0;display:flex;flex-direction:column;}}
.report-header{{background:linear-gradient(135deg,#0d1526 0%,#0f1f3d 50%,#0d1526 100%);border-bottom:1px solid #1e3a5f;padding:28px 36px 22px;position:relative;overflow:hidden;}}
.report-header::before{{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background:repeating-linear-gradient(0deg,transparent,transparent 39px,rgba(30,58,95,.25) 39px,rgba(30,58,95,.25) 40px),repeating-linear-gradient(90deg,transparent,transparent 39px,rgba(30,58,95,.25) 39px,rgba(30,58,95,.25) 40px);pointer-events:none;}}
.header-top{{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;position:relative;}}
.brand{{display:flex;align-items:center;gap:12px;}}
.brand-icon{{width:42px;height:42px;background:#1565c0;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 0 20px rgba(21,101,192,.4);flex-shrink:0;}}
.brand-label{{font-size:10px;font-family:'IBM Plex Mono',monospace;color:#4a9eff;letter-spacing:2px;text-transform:uppercase;margin-bottom:2px;}}
.brand-title{{font-size:19px;font-weight:600;color:#e8f0fe;}}
.header-actions{{display:flex;align-items:center;gap:10px;}}
.risk-pill{{background:rgba(0,0,0,.4);border:2px solid {risk_color};border-radius:8px;padding:8px 16px;text-align:center;box-shadow:0 0 16px {risk_color}44;}}
.risk-label{{font-size:9px;font-family:'IBM Plex Mono',monospace;color:#8090a0;letter-spacing:2px;text-transform:uppercase;display:block;margin-bottom:3px;}}
.risk-value{{font-size:15px;font-weight:600;color:{risk_color};font-family:'IBM Plex Mono',monospace;letter-spacing:1px;}}
.download-btn{{background:#1565c0;border:1px solid #1976d2;color:#e8f4ff;font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;padding:9px 16px;border-radius:8px;cursor:pointer;letter-spacing:.5px;text-transform:uppercase;transition:all 0.2s;display:flex;align-items:center;gap:7px;white-space:nowrap;}}
.download-btn:hover{{background:#1976d2;box-shadow:0 0 12px rgba(21,101,192,.5);}}
.download-btn svg{{flex-shrink:0;}}
.header-meta{{display:grid;grid-template-columns:repeat(4,1fr);margin-top:20px;border:1px solid #1e3a5f;border-radius:8px;overflow:hidden;}}
.meta-item{{padding:10px 16px;border-right:1px solid #1e3a5f;}}.meta-item:last-child{{border-right:none;}}
.meta-key{{font-size:9px;font-family:'IBM Plex Mono',monospace;color:#4a9eff;letter-spacing:2px;text-transform:uppercase;display:block;margin-bottom:3px;}}
.meta-val{{font-size:12px;color:#d0daf0;font-weight:500;font-family:'IBM Plex Mono',monospace;}}
.content{{padding:22px 36px;flex:1;}}
.summary-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px;}}
.stat-card{{background:#0f1829;border:1px solid #1e3a5f;border-radius:10px;padding:16px 18px;position:relative;overflow:hidden;}}
.stat-card::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px;}}
.stat-card.total::before{{background:#4a9eff;}}.stat-card.high::before{{background:#ff4444;}}.stat-card.medium::before{{background:#ff9900;}}.stat-card.low::before{{background:#22aa55;}}
.stat-num{{font-size:30px;font-weight:600;font-family:'IBM Plex Mono',monospace;line-height:1;margin-bottom:5px;}}
.stat-card.total .stat-num{{color:#4a9eff;}}.stat-card.high .stat-num{{color:#ff4444;}}.stat-card.medium .stat-num{{color:#ff9900;}}.stat-card.low .stat-num{{color:#22aa55;}}
.stat-label{{font-size:10px;color:#607080;text-transform:uppercase;letter-spacing:1.5px;font-family:'IBM Plex Mono',monospace;}}
.section{{background:#0f1829;border:1px solid #1e3a5f;border-radius:10px;margin-bottom:18px;overflow:hidden;}}
.section-header{{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;border-bottom:1px solid #1a2e4a;background:#0d1626;}}
.section-title{{display:flex;align-items:flex-start;gap:12px;}}
.sec-icon{{font-size:9px;font-family:'IBM Plex Mono',monospace;font-weight:600;background:#1a2a40;color:#4a9eff;padding:3px 6px;border-radius:4px;letter-spacing:.5px;margin-top:2px;flex-shrink:0;}}
.section-title h2{{font-size:14px;font-weight:600;color:#d0daf0;margin-bottom:2px;}}
.mitre-tag{{font-size:11px;color:#4a9eff;font-family:'IBM Plex Mono',monospace;}}
.sec-counts{{display:flex;gap:7px;flex-shrink:0;}}
.mini-badge{{font-size:10px;font-family:'IBM Plex Mono',monospace;padding:3px 9px;border-radius:20px;font-weight:600;letter-spacing:.5px;}}
.mini-badge.high{{background:#3a0a0a;color:#ff6666;border:1px solid #ff444433;}}.mini-badge.medium{{background:#3a2200;color:#ffbb44;border:1px solid #ff990033;}}.mini-badge.low{{background:#0a2a15;color:#44cc77;border:1px solid #22aa5533;}}
.table-wrap{{overflow-x:auto;}}
table{{width:100%;border-collapse:collapse;font-size:12px;}}
thead tr{{background:#0b1422;}}
th{{padding:8px 11px;text-align:left;font-size:10px;font-family:'IBM Plex Mono',monospace;font-weight:600;color:#4a7090;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #1a2e4a;}}
td{{padding:8px 11px;border-bottom:1px solid #141f35;vertical-align:top;color:#b0bcd0;}}
tbody tr:last-child td{{border-bottom:none;}}tbody tr:hover td{{background:#111e38;}}
code{{font-family:'IBM Plex Mono',monospace;font-size:11px;}}.path{{color:#7090b0;word-break:break-all;}}
.sha{{font-size:10px;color:#405060;margin-top:2px;font-family:'IBM Plex Mono',monospace;}}.loc-cell{{font-size:11px;color:#607080;}}
.badge{{font-size:10px;font-family:'IBM Plex Mono',monospace;font-weight:600;padding:3px 7px;border-radius:4px;white-space:nowrap;letter-spacing:.5px;display:inline-block;}}
.new-tag{{font-size:9px;font-family:'IBM Plex Mono',monospace;font-weight:600;background:#2a1800;color:#ffbb44;border:1px solid #ff990055;padding:1px 5px;border-radius:3px;margin-left:6px;letter-spacing:.5px;}}
.conclusion{{background:#0a1520;border:1px solid #1e3a5f;border-left:4px solid #4a9eff;border-radius:0 8px 8px 0;padding:16px 20px;margin-bottom:18px;}}
.conclusion h3{{font-size:12px;color:#4a9eff;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px;font-family:'IBM Plex Mono',monospace;}}
.conclusion p{{color:#90a0b0;font-size:13px;line-height:1.7;}}
.report-footer{{border-top:1px solid #1e3a5f;padding:16px 36px;display:flex;justify-content:space-between;align-items:center;background:#0a0e1a;font-size:11px;color:#405060;font-family:'IBM Plex Mono',monospace;}}
/* Remediation styles */
.rem-body{{padding:20px 22px;}}
.rem-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px;}}
.rem-card{{background:#0a1220;border:1px solid #1a2e4a;border-radius:8px;overflow:hidden;}}
.rem-card-header{{display:flex;align-items:flex-start;gap:10px;padding:12px 16px;background:#0d1626;border-bottom:1px solid #1a2e4a;}}
.rem-card-title{{font-size:13px;font-weight:600;color:#d0daf0;margin-bottom:2px;}}
.rem-card-body{{padding:14px 16px;}}
.rem-sev-label{{font-size:11px;font-weight:600;font-family:'IBM Plex Mono',monospace;letter-spacing:.5px;margin-bottom:8px;}}
.rem-steps{{padding-left:18px;}}
.rem-steps li{{font-size:12px;color:#90a8c0;line-height:1.7;margin-bottom:4px;}}
.rem-steps li code{{font-size:11px;background:#0d1829;padding:1px 5px;border-radius:3px;color:#7abfff;border:1px solid #1e3a5f;}}
.rem-general-section{{margin-top:4px;}}
.rem-general-title-main{{font-size:12px;font-weight:600;color:#8090a0;text-transform:uppercase;letter-spacing:1.5px;font-family:'IBM Plex Mono',monospace;margin-bottom:12px;}}
.rem-general-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;}}
.rem-general{{background:#0a1220;border:1px solid #1a2e4a;border-radius:8px;padding:14px 16px;}}
.rem-general-title{{font-size:11px;font-weight:600;font-family:'IBM Plex Mono',monospace;letter-spacing:.5px;margin-bottom:10px;}}
/* Print styles */
@media print{{
  body{{background:white;color:#111;display:block;}}
  .sidebar{{display:none;}}
  .download-btn{{display:none;}}
  .section{{border:1px solid #ccc;background:#fafafa;break-inside:avoid;}}
  .report-header{{background:#f0f4ff;}}
  .rem-grid{{grid-template-columns:1fr;}}
  .rem-general-grid{{grid-template-columns:1fr 1fr;}}
}}
</style>
</head><body>
<nav class="sidebar">
  <div class="sb-logo"><div class="sb-logo-title">Persistence Detector</div></div>
  <div class="sb-section-label">Scan Modules</div>
  {sb}
  <div class="sb-section-label">Analysis</div>
  {extra}
  <div class="sb-stats">
    <div class="sb-stat"><span class="sb-stat-label">TOTAL</span><span class="sb-stat-val">{total}</span></div>
    <div class="sb-stat"><span class="sb-stat-label">HIGH</span><span class="sb-stat-val high">{high}</span></div>
    <div class="sb-stat"><span class="sb-stat-label">MEDIUM</span><span class="sb-stat-val medium">{medium}</span></div>
    <div class="sb-stat"><span class="sb-stat-label">LOW</span><span class="sb-stat-val low">{low}</span></div>
    {new_stat}
  </div>
</nav>
<div class="main">
  <div class="report-header">
    <div class="header-top">
      <div class="brand"><div class="brand-icon">🛡️</div><div><div class="brand-title">Windows Persistence &amp; Suspicious Process Detector</div></div></div>
      <div class="header-actions">
        <button class="download-btn" onclick="downloadReport()">
          <svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><path d="M10 2a1 1 0 011 1v9.586l2.293-2.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 111.414-1.414L9 12.586V3a1 1 0 011-1zM3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z"/></svg>
          Download PDF
        </button>
        <div class="risk-pill"><span class="risk-label">Overall Risk</span><span class="risk-value">{risk_level}</span></div>
      </div>
    </div>
    <div class="header-meta">
      <div class="meta-item"><span class="meta-key">Hostname</span><span class="meta-val">{e(hostname)}</span></div>
      <div class="meta-item"><span class="meta-key">Analyst</span><span class="meta-val">{e(analyst)}</span></div>
      <div class="meta-item"><span class="meta-key">Scan Date</span><span class="meta-val">{scan_time.strftime('%Y-%m-%d')}</span></div>
      <div class="meta-item"><span class="meta-key">Scan Time</span><span class="meta-val">{scan_time.strftime('%H:%M:%S')}</span></div>
    </div>
  </div>
  <div class="content">
    <div class="summary-grid">
      <div class="stat-card total"><div class="stat-num">{total}</div><div class="stat-label">Total Findings</div></div>
      <div class="stat-card high"><div class="stat-num">{high}</div><div class="stat-label">High Severity</div></div>
      <div class="stat-card medium"><div class="stat-num">{medium}</div><div class="stat-label">Medium Severity</div></div>
      <div class="stat-card low"><div class="stat-num">{low}</div><div class="stat-label">Low Severity</div></div>
    </div>
    {secs}
    {remediation_sec}
    {vt_sec}
    {diff_sec}
    <div class="conclusion"><h3>Analyst Conclusion &amp; Recommendations</h3><p>{conclusion_text}</p></div>
  </div>
  <div class="report-footer">
    <span>Generated: {scan_end.strftime('%Y-%m-%d %H:%M:%S')}</span>
  </div>
</div>
<script>
function downloadReport(){{
  const btn = document.querySelector('.download-btn');
  btn.textContent = 'Preparing...';
  setTimeout(()=>{{
    window.print();
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><path d="M10 2a1 1 0 011 1v9.586l2.293-2.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 111.414-1.414L9 12.586V3a1 1 0 011-1zM3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z"/></svg> Download PDF';
  }}, 200);
}}
const sections=document.querySelectorAll('.section');
const links=document.querySelectorAll('.sb-link');
const obs=new IntersectionObserver(entries=>{{
  entries.forEach(entry=>{{
    if(entry.isIntersecting){{
      links.forEach(l=>l.classList.remove('active'));
      const a=document.querySelector('.sb-link[href="#'+entry.target.id+'"]');
      if(a)a.classList.add('active');
    }}
  }});
}},{{threshold:0.2}});
sections.forEach(s=>obs.observe(s));
links.forEach(l=>{{l.addEventListener('click',ev=>{{ev.preventDefault();const t=document.querySelector(l.getAttribute('href'));if(t)t.scrollIntoView({{behavior:'smooth',block:'start'}});}});}});
</script>
</body></html>"""

    out_dir=os.path.join(os.path.dirname(os.path.dirname(__file__)),"output")
    os.makedirs(out_dir,exist_ok=True)
    report_path=os.path.join(out_dir,"forensic_report.html")
    with open(report_path,"w",encoding="utf-8") as f: f.write(html)
    return report_path
