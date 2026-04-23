"""
Windows Persistence & Suspicious Process Detector  v3.0
"""

import sys, os, datetime, socket

def check_windows():
    if sys.platform != "win32":
        print("[!] This tool is designed for Windows systems.")
        print("[*] Running in DEMO MODE with simulated findings...\n")
        return False
    return True

def main():
    # Handle --reset flag to clear saved config
    if "--reset" in sys.argv:
        from modules.config_manager import reset_config
        reset_config()
        return

    print("=" * 60)
    print("  Windows Persistence & Suspicious Process Detector v3.0")
    print("=" * 60)
    print()

    is_windows = check_windows()

    # Load analyst name and VT key from config (asks once, saves forever)
    from modules.config_manager import get_analyst_name, get_virustotal_key
    analyst   = get_analyst_name()
    vt_api_key = get_virustotal_key()

    hostname  = socket.gethostname()
    scan_time = datetime.datetime.now()

    print(f"[*] Hostname     : {hostname}")
    print(f"[*] Analyst      : {analyst}")
    print(f"[*] Scan Started : {scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    all_findings = {}

    print("[1/5] Scanning registry run keys...")
    from modules.registry_check import check_registry
    all_findings["Registry Run Keys"] = check_registry(is_windows)
    print(f"      Found {len(all_findings['Registry Run Keys'])} entries\n")

    print("[2/5] Scanning scheduled tasks...")
    from modules.scheduled_tasks import check_scheduled_tasks
    all_findings["Scheduled Tasks"] = check_scheduled_tasks(is_windows)
    print(f"      Found {len(all_findings['Scheduled Tasks'])} entries\n")

    print("[3/5] Scanning startup folders...")
    from modules.startup_folder import check_startup_folder
    all_findings["Startup Folder"] = check_startup_folder(is_windows)
    print(f"      Found {len(all_findings['Startup Folder'])} entries\n")

    print("[4/5] Scanning Windows services...")
    from modules.services_check import check_services
    all_findings["Suspicious Services"] = check_services(is_windows)
    print(f"      Found {len(all_findings['Suspicious Services'])} entries\n")

    print("[5/5] Scanning running processes...")
    from modules.process_check import check_processes
    all_findings["Suspicious Processes"] = check_processes(is_windows)
    print(f"      Found {len(all_findings['Suspicious Processes'])} entries\n")

    print("[*] Comparing with previous scan...")
    from modules.scan_compare import compare_scans
    diff, new_findings, removed_findings, prev_scan_time, is_first_scan = compare_scans(
        all_findings, hostname, scan_time
    )
    if is_first_scan:
        print("    [DIFF] First scan — baseline saved. Future scans will show changes.\n")
    else:
        print()

    from modules.virustotal import enrich_with_vt
    all_findings, vt_results = enrich_with_vt(
        all_findings, vt_api_key if vt_api_key else "DEMO", is_windows
    )

    print("[*] Generating HTML report...")
    from report.report_generator import generate_report
    report_path = generate_report(
        findings=all_findings, hostname=hostname, analyst=analyst, scan_time=scan_time,
        vt_results=vt_results, diff=diff, new_findings=new_findings,
        removed_findings=removed_findings, prev_scan_time=prev_scan_time, is_first_scan=is_first_scan
    )

    scan_end = datetime.datetime.now()
    duration = (scan_end - scan_time).seconds
    total  = sum(len(v) for v in all_findings.values())
    high   = sum(1 for v in all_findings.values() for f in v if f.get("severity") == "High")
    medium = sum(1 for v in all_findings.values() for f in v if f.get("severity") == "Medium")
    low    = sum(1 for v in all_findings.values() for f in v if f.get("severity") == "Low")

    print("\n" + "=" * 60)
    print("  SCAN COMPLETE")
    print("=" * 60)
    print(f"  Total Findings : {total}")
    print(f"  High Severity  : {high}")
    print(f"  Medium Severity: {medium}")
    print(f"  Low Severity   : {low}")
    if not is_first_scan:
        nc = len(new_findings)
        print(f"  New Since Last : {nc}  {'*** INVESTIGATE' if nc > 0 else '(no changes)'}")
    if vt_results:
        flagged = sum(1 for r in vt_results if r["vt"].get("malicious", 0) > 0)
        print(f"  VT Flagged     : {flagged}/{len(vt_results)} files")
    print(f"  Duration       : {duration}s")
    print(f"  Report         : {report_path}")
    print("=" * 60)
    print()
    print("  Tip: Run 'python main.py --reset' to change your name or API key.")
    print()

    try:
        import webbrowser
        webbrowser.open(f"file:///{os.path.abspath(report_path)}")
    except Exception:
        print("[*] Open the report manually in your browser.")

if __name__ == "__main__":
    main()
