import os
import json
from hasher import calculate_file_hash

def check_integrity(directory_path, baseline_file="baseline.json"):
    """
    Compares current file states against the saved baseline.
    """
    if not os.path.exists(baseline_file):
        return "Error: Baseline not found. Please create one first."

    # 1. Load Baseline
    try:
        with open(baseline_file, 'r') as f:
            baseline_data = json.load(f)
    except:
        return "Error: Baseline file is corrupted."

    # 2. Scan Live Data
    live_data = {}
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = calculate_file_hash(filepath)
            if not file_hash.startswith("ERROR"):
                live_data[filepath] = file_hash

    # 3. Compare
    report = {
        "modified": [],
        "added": [],
        "deleted": []
    }

    # Check for Modified and Deleted
    for filepath, stored_hash in baseline_data.items():
        if filepath not in live_data:
            report["deleted"].append(filepath)
        elif live_data[filepath] != stored_hash:
            report["modified"].append(filepath)

    # Check for Added
    for filepath in live_data:
        if filepath not in baseline_data:
            report["added"].append(filepath)

    return report