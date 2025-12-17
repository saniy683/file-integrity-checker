import hashlib

def calculate_file_hash(filepath):
    """
    Takes a file path and returns its SHA-256 hash string.
    """
    hasher = hashlib.sha256()
    
    try:
        with open(filepath, 'rb') as f:
            # Read in 4KB chunks
            chunk = f.read(4096)
            while chunk:
                hasher.update(chunk)
                chunk = f.read(4096)
        return hasher.hexdigest()
        
    except FileNotFoundError:
        return "ERROR: File not found"
    except PermissionError:
        return "ERROR: Permission denied"
    except Exception as e:
        return f"ERROR: {e}"

def calculate_string_hash(content_bytes):
    """
    Takes raw bytes (like website content) and returns SHA-256 hash.
    Required for the Web Analyzer feature.
    """
    return hashlib.sha256(content_bytes).hexdigest()

# --- TEST CODE ---
if __name__ == "__main__":
    import os
    test_file = "test_data.txt"
    with open(test_file, "w") as f: f.write("Security Test")
    print(f"File Hash: {calculate_file_hash(test_file)}")
    print(f"String Hash: {calculate_string_hash(b'Security Test')}")
    os.remove(test_file)