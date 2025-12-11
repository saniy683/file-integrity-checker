import hashlib

def calculate_file_hash(filepath):
    """
    Takes a file path and returns its SHA-256 hash string.
    """
    # We use SHA-256 as required by your project proposal (Page 3)
    hasher = hashlib.sha256()
    
    try:
        # Open the file in 'rb' (Read Binary) mode
        with open(filepath, 'rb') as f:
            # Read the file in chunks (4KB) to avoid memory crashes on large files
            chunk = f.read(4096)
            while chunk:
                hasher.update(chunk)
                chunk = f.read(4096)
                
        # Return the hexadecimal signature
        return hasher.hexdigest()
        
    except FileNotFoundError:
        return "ERROR: File not found"
    except PermissionError:
        return "ERROR: Permission denied"
    except Exception as e:
        return f"ERROR: {e}"

# --- TEMPORARY TEST CODE (To verify this file works) ---
if __name__ == "__main__":
    import os
    
    # 1. Create a dummy file to test
    test_file = "test_data.txt"
    with open(test_file, "w") as f:
        f.write("Cyber Security Project Test")
    
    # 2. Run the hasher
    print(f"Testing SHA-256 on '{test_file}'...")
    file_hash = calculate_file_hash(test_file)
    print(f"Generated Hash: {file_hash}")
    
    # 3. Cleanup (delete the test file)
    if os.path.exists(test_file):
        os.remove(test_file)
        print("Test file cleaned up.")