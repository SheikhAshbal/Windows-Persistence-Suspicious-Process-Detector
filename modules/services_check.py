"""
Module: Windows Services Scanner
Flags suspicious auto-start services not in the known-legit whitelist.
MITRE ATT&CK: T1543.003
"""

import subprocess

KNOWN_LEGIT_SERVICES = {
    "wuauserv", "bits", "spooler", "dnscache", "eventlog", "lanmanserver",
    "lanmanworkstation", "netlogon", "rpcss", "samss", "schedule", "seclogon",
    "sens", "sharedaccess", "shellhwdetection", "themes", "winmgmt", "wscsvc",
    "wdiservicehost", "diagtrack", "nsi", "iphlpsvc", "cryptsvc", "dcomlaunch",
    "lsa", "msiserver", "trustedinstaller", "defragsvc", "healthservice",
    "wlanautocfg", "mpssvc", "bfe", "dot3svc", "eaphost", "wermgr",
    "nvidiadisplaycontainerls", "nvdispsvc", "amdextensionmanagerservice",
    "audiosrv", "audioendpointbuilder", "wiaservc", "stisvc",
    "gpsvc", "lmhosts", "netman", "nla", "tapisrv", "termservice",
    "w32tm", "webclient", "wmpnetworksvc", "wbiosrvc", "wcsvc",
    "wsearch", "wudfrd", "xblgamesave", "xbox*",
    "appidsvc", "appinfo", "applockerfltr", "appmagmt",
    "bthserv", "bthavctpsvc", "btagservice",
    "clipsvc", "camsvc", "cbdhsvc", "cdpsvc",
    "dps", "dimsvc", "dmwappushservice", "dosvc",
    "edgeupdate", "edgeupdatem",
    "fontcache", "fdrespub", "fax", "ftpsvc",
    "hidserv", "hvsics", "hvhost",
    "icssvc", "idsvc",
    "lfsvc", "lltdsvc", "lxssmanager",
    "mapsbroker", "msdtc",
    "netbt", "netprofm", "nlasvc",
    "p2pimsvc", "p2psvc", "peerdsvc", "pla",
    "rassec", "remoteaccess", "remoteregistry", "regsvc",
    "sensorservice", "smphost", "snmptrap", "sppsvc",
    "ssdpsrv", "storsvc", "svc*", "swprv",
    "tapisrv", "tibssvc", "tiledatamodelsvc",
    "uevagentservice", "upnphost", "uxsms",
    "vaultcvc", "vmicheartbeat", "vmicrdv",
    "wecsvc", "wefrsvc", "wer",
    "xboxgipsvc",
}

SUSPICIOUS_PATHS = ["temp", "appdata", "public", "recycle", "downloads", "programdata\\temp"]

def parse_sc_output(output):
    services = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            if current:
                services.append(current)
            current = {"service_name": line.split(":", 1)[1].strip()}
        elif line.startswith("DISPLAY_NAME:"):
            current["display_name"] = line.split(":", 1)[1].strip()
        elif "START_TYPE" in line:
            current["start_type"] = line.split(":", 1)[1].strip()
        elif "BINARY_PATH_NAME" in line:
            current["binary_path"] = line.split(":", 1)[1].strip()
        elif "STATE" in line and "state" not in current:
            current["state"] = line.split(":", 1)[1].strip()
    if current:
        services.append(current)
    return services

def assess_severity(service):
    name = service.get("service_name", "").lower()
    binary = service.get("binary_path", "").lower()
    start = service.get("start_type", "").lower()

    if name in KNOWN_LEGIT_SERVICES:
        return "Low"
    if any(p in binary for p in SUSPICIOUS_PATHS):
        return "High"
    if "auto" in start and name not in KNOWN_LEGIT_SERVICES:
        return "Medium"
    return "Low"

def check_services(is_windows=True):
    findings = []

    if is_windows:
        try:
            result = subprocess.run(
                ["sc", "query", "type=", "all", "state=", "all"],
                capture_output=True, text=True, timeout=30
            )
            services = parse_sc_output(result.stdout)
            for svc in services:
                start = svc.get("start_type", "").lower()
                if "auto" not in start and "boot" not in start:
                    continue
                severity = assess_severity(svc)
                findings.append({
                    "name": svc.get("service_name", "Unknown"),
                    "value": svc.get("binary_path", "N/A"),
                    "location": f"Windows Services — Display: {svc.get('display_name', 'N/A')} | Start: {svc.get('start_type', 'N/A')}",
                    "severity": severity,
                    "note": get_note(svc, severity)
                })
        except Exception as e:
            findings.append({
                "name": "Error",
                "value": str(e),
                "location": "sc query",
                "severity": "Low",
                "note": "Could not enumerate services"
            })
    else:
        # Demo mode
        findings = [
            {
                "name": "Spooler",
                "value": r"C:\Windows\System32\spoolsv.exe",
                "location": "Windows Services — Display: Print Spooler | Start: AUTO_START",
                "severity": "Low",
                "note": "Legitimate Windows Print Spooler service"
            },
            {
                "name": "WSearch",
                "value": r"C:\Windows\system32\SearchIndexer.exe /Embedding",
                "location": "Windows Services — Display: Windows Search | Start: AUTO_START",
                "severity": "Low",
                "note": "Legitimate Windows Search indexer"
            },
            {
                "name": "SysHelper64",
                "value": r"C:\ProgramData\Temp\syshelper64.exe --service",
                "location": "Windows Services — Display: System Helper Service | Start: AUTO_START",
                "severity": "High",
                "note": "Unknown service binary in ProgramData\\Temp — not a known Windows service. Possible malware."
            },
            {
                "name": "NetService",
                "value": r"C:\Windows\Temp\netservice.exe",
                "location": "Windows Services — Display: Network Service Helper | Start: AUTO_START",
                "severity": "High",
                "note": "Service binary located in Windows\\Temp — highly anomalous. Investigate immediately."
            },
            {
                "name": "NVDisplay.ContainerLocalSystem",
                "value": r"C:\Program Files\NVIDIA Corporation\Display.NvContainer\NVDisplay.Container.exe -s NVDisplay.ContainerLocalSystem",
                "location": "Windows Services — Display: NVIDIA Display Container LS | Start: AUTO_START",
                "severity": "Low",
                "note": "Legitimate NVIDIA display service"
            },
        ]

    return findings

def get_note(service, severity):
    name = service.get("service_name", "")
    binary = service.get("binary_path", "")
    if severity == "High":
        return f"Service binary in suspicious path: {binary}"
    if severity == "Medium":
        return f"Unknown auto-start service — verify: {binary}"
    return f"Known or expected service: {name}"
