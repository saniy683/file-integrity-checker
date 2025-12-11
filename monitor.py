import os
import time
from hasher import calculate_file_hash
from baseline import load_baseline

def check_integrity(directory_path, baseline_file="baseline.json"):
    """
    Compares the current state of files against the saved baseline.
    Returns a dictionary with lists of 'modified', 'added', and 'deleted' files.
    """
    
    # 1. Load the old data (Baseline)
    baseline_data = load_baseline(baseline_file)
    if not baseline_data:
        return "Error: Baseline file not found or empty. Please create a baseline first."

    # 2. Scan the current data (Live State)
    live_data = {}
    
    # We re-scan the folder just like we did in baseline.py
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = calculate_file_hash(filepath)
            if not file_hash.startswith("ERROR"):
                live_data[filepath] = file_hash

    # 3. Compare Logic
    report = {
        "modified": [],
        "added": [],
        "deleted": []
    }

    # Check for Modified and Deleted files
    for filepath, stored_hash in baseline_data.items():
        if filepath not in live_data:
            report["deleted"].append(filepath)
        elif live_data[filepath] != stored_hash:
            report["modified"].append(filepath)

    # Check for Added files
    for filepath in live_data:
        if filepath not in baseline_data:
            report["added"].append(filepath)

    return report

# --- TEST CODE (To verify this file works) ---
if __name__ == "__main__":
    from baseline import create_baseline
    
    # Setup: Create a test folder and a file
    test_dir = "monitor_test_folder"
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
    
    file_a = os.path.join(test_dir, "file_A.txt")
    with open(file_a, "w") as f: f.write("Original Content")
    
    # 1. Create Baseline
    print("1. Creating Baseline...")
    create_baseline(test_dir)
    
    # 2. Simulate Attacks/Changes
    print("2. Simulating Changes (Hacking)...")
    
    # Modify File A
    with open(file_a, "w") as f: f.write("MALICIOUS CONTENT")
    
    # Add File B
    with open(os.path.join(test_dir, "virus.exe"), "w") as f: f.write("Bad code")
    
    # 3. Run Integrity Check
    print("3. Running Integrity Check...")
    results = check_integrity(test_dir)
    
    print("\n--- REPORT RESULTS ---")
    print(f"Modified: {results['modified']}") # Should show file_A.txt
    print(f"Added:    {results['added']}")    # Should show virus.exe
    print(f"Deleted:  {results['deleted']}")  # Should be empty
    
    # Cleanup
    import shutil
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    if os.path.exists("baseline.json"):
        os.remove("baseline.json")
    print("\nTest Cleanup Complete.")