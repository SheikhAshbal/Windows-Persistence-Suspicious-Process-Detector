"""
Module: Scan Comparison
Saves each scan as a JSON snapshot and compares with the previous scan.
Highlights NEW findings that weren't present before.
"""

import json
import os
import datetime
import hashlib

SNAPSHOTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "snapshots")

def finding_id(finding):
    """Create a stable unique ID for a finding based on name + value."""
    key = f"{finding.get('name', '')}|{finding.get('value', '')}|{finding.get('location', '')}"
    return hashlib.md5(key.encode()).hexdigest()

def save_snapshot(findings_dict, hostname, scan_time):
    """Save current scan findings as a JSON snapshot."""
    os.makedirs(SNAPSHOTS_DIR, exist_ok=True)

    snapshot = {
        "hostname":  hostname,
        "scan_time": scan_time.isoformat(),
        "findings":  {}
    }

    for category, items in findings_dict.items():
        snapshot["findings"][category] = [
            {
                "id":       finding_id(f),
                "name":     f.get("name", ""),
                "value":    f.get("value", ""),
                "location": f.get("location", ""),
                "severity": f.get("severity", ""),
                "note":     f.get("note", "")
            }
            for f in items
        ]

    # Save with timestamp filename
    ts = scan_time.strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{hostname}_{ts}.json"
    path = os.path.join(SNAPSHOTS_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2)

    return path

def load_latest_snapshot(hostname, current_scan_time):
    """Load the most recent previous snapshot for this hostname."""
    if not os.path.exists(SNAPSHOTS_DIR):
        return None

    snapshots = []
    for fname in os.listdir(SNAPSHOTS_DIR):
        if fname.startswith(f"scan_{hostname}_") and fname.endswith(".json"):
            fpath = os.path.join(SNAPSHOTS_DIR, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                snap_time = datetime.datetime.fromisoformat(data["scan_time"])
                # Only consider snapshots BEFORE current scan
                if snap_time < current_scan_time:
                    snapshots.append((snap_time, data, fpath))
            except Exception:
                continue

    if not snapshots:
        return None

    # Return most recent
    snapshots.sort(key=lambda x: x[0], reverse=True)
    return snapshots[0][1], snapshots[0][2]

def compare_scans(current_findings, hostname, scan_time):
    """
    Compare current findings against the previous snapshot.
    Returns:
        - diff: dict with 'new', 'removed', 'unchanged' counts per category
        - new_findings: list of brand new findings not seen before
        - removed_findings: list of findings that disappeared since last scan
        - previous_scan_time: datetime of previous scan (or None)
        - is_first_scan: True if no previous snapshot exists
    """
    # Save current snapshot first
    snapshot_path = save_snapshot(current_findings, hostname, scan_time)

    result = load_latest_snapshot(hostname, scan_time)
    if result is None:
        return None, [], [], None, True

    prev_snapshot, prev_path = result
    previous_scan_time = datetime.datetime.fromisoformat(prev_snapshot["scan_time"])

    # Build set of previous finding IDs
    prev_ids = set()
    prev_by_id = {}
    for category, items in prev_snapshot.get("findings", {}).items():
        for item in items:
            fid = item.get("id", finding_id(item))
            prev_ids.add(fid)
            prev_by_id[fid] = {**item, "category": category}

    # Build set of current finding IDs
    curr_ids = set()
    curr_by_id = {}
    for category, items in current_findings.items():
        for item in items:
            fid = finding_id(item)
            curr_ids.add(fid)
            curr_by_id[fid] = {**item, "category": category}

    new_ids     = curr_ids - prev_ids
    removed_ids = prev_ids - curr_ids

    new_findings     = [curr_by_id[fid] for fid in new_ids]
    removed_findings = [prev_by_id[fid] for fid in removed_ids]

    # Per-category diff stats
    diff = {}
    all_categories = set(list(current_findings.keys()) + list(prev_snapshot.get("findings", {}).keys()))
    for category in all_categories:
        curr_cat_ids = {finding_id(f) for f in current_findings.get(category, [])}
        prev_cat_ids = {f.get("id", finding_id(f)) for f in prev_snapshot.get("findings", {}).get(category, [])}
        diff[category] = {
            "new":       len(curr_cat_ids - prev_cat_ids),
            "removed":   len(prev_cat_ids - curr_cat_ids),
            "unchanged": len(curr_cat_ids & prev_cat_ids),
            "total":     len(curr_cat_ids)
        }

    # Tag new findings in the main findings dict
    for category, items in current_findings.items():
        for item in items:
            fid = finding_id(item)
            if fid in new_ids:
                item["is_new"] = True

    total_new     = len(new_findings)
    total_removed = len(removed_findings)

    if total_new > 0:
        print(f"    [DIFF] {total_new} NEW findings since last scan ({previous_scan_time.strftime('%Y-%m-%d %H:%M')})")
    if total_removed > 0:
        print(f"    [DIFF] {total_removed} findings REMOVED since last scan")
    if total_new == 0 and total_removed == 0:
        print(f"    [DIFF] No changes since last scan ({previous_scan_time.strftime('%Y-%m-%d %H:%M')})")

    return diff, new_findings, removed_findings, previous_scan_time, False
