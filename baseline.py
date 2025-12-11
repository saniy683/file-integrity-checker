import os
import json
from hasher import calculate_file_hash

def create_baseline(directory_path, baseline_file="baseline.json"):
    """
    Scans a directory, hashes every file, and saves the results to a JSON file.
    """
    if not os.path.exists(directory_path):
        return f"Error: Directory '{directory_path}' does not exist."

    baseline_data = {}
    print(f"Scanning directory: {directory_path} ...")

    # os.walk allows us to look into subfolders too (recursive scan)
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            # Get the full path of the file
            filepath = os.path.join(root, file)
            
            # Calculate the hash
            file_hash = calculate_file_hash(filepath)
            
            # Store it in our dictionary
            if not file_hash.startswith("ERROR"):
                baseline_data[filepath] = file_hash

    # Save the dictionary to a JSON file
    try:
        with open(baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=4)
        return f"Success: Baseline saved to {baseline_file} with {len(baseline_data)} files."
    except Exception as e:
        return f"Error saving baseline: {e}"

def load_baseline(baseline_file="baseline.json"):
    """
    Reads the saved baseline file back into memory.
    """
    if not os.path.exists(baseline_file):
        return {}
    
    try:
        with open(baseline_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        return {}

# --- TEST CODE (To verify this file works) ---
if __name__ == "__main__":
    # 1. Create a dummy test folder
    test_dir = "test_folder"
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
    
    # 2. Create a dummy file inside it
    with open(os.path.join(test_dir, "secret.txt"), "w") as f:
        f.write("Top Secret Data")

    # 3. Run the scan
    print("--- Starting Baseline Test ---")
    result_message = create_baseline(test_dir)
    print(result_message)

    # 4. Check if the JSON file was actually created
    if os.path.exists("baseline.json"):
        print("Verification: baseline.json was created successfully.")
        # Optional: Print content
        # print(load_baseline())
        
        # Cleanup (delete test file/folder/json)
        os.remove("baseline.json")
        os.remove(os.path.join(test_dir, "secret.txt"))
        os.rmdir(test_dir)
        print("Test Cleanup Complete.")
    else:
        print("Verification Failed: baseline.json NOT found.")