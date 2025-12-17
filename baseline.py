import os
import json
from hasher import calculate_file_hash

def create_baseline(directory_path, baseline_file="baseline.json"):
    """
    Scans a directory, hashes every file, and saves results to JSON.
    """
    if not os.path.exists(directory_path):
        return f"Error: Directory '{directory_path}' does not exist."

    baseline_data = {}

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = calculate_file_hash(filepath)
            
            if not file_hash.startswith("ERROR"):
                baseline_data[filepath] = file_hash

    try:
        with open(baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=4)
        return f"Success: Baseline saved with {len(baseline_data)} files."
    except Exception as e:
        return f"Error saving baseline: {e}"