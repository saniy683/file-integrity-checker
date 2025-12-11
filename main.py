import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
import logging
from datetime import datetime
# Import logic modules
import baseline 
import monitor

# --- CONFIGURATION FOR LOGGING ---
# This creates a file named 'audit_log.txt' and saves all events there with timestamps
logging.basicConfig(filename='audit_log.txt', level=logging.INFO, 
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

class FileIntegrityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Security Project: File Integrity Checker")
        self.root.geometry("700x550")
        
        self.folder_path = tk.StringVar()

        # --- UI LAYOUT ---
        title_label = tk.Label(root, text="File Integrity Checker", font=("Arial", 16, "bold"), fg="#333")
        title_label.pack(pady=10)

        # Folder Selection
        frame_select = tk.Frame(root)
        frame_select.pack(pady=5, padx=20, fill="x")
        
        lbl_folder = tk.Label(frame_select, text="Target Folder:")
        lbl_folder.pack(side="left")
        
        entry_folder = tk.Entry(frame_select, textvariable=self.folder_path, width=50)
        entry_folder.pack(side="left", padx=5)
        
        btn_browse = tk.Button(frame_select, text="Browse", command=self.browse_folder, bg="#ddd")
        btn_browse.pack(side="left")

        # Buttons
        frame_actions = tk.Frame(root)
        frame_actions.pack(pady=15)
        
        btn_baseline = tk.Button(frame_actions, text="Update Baseline", command=self.run_baseline_creation, 
                                 bg="#4CAF50", fg="white", width=20, height=2)
        btn_baseline.pack(side="left", padx=10)
        
        btn_check = tk.Button(frame_actions, text="Check Integrity", command=self.run_verification, 
                              bg="#2196F3", fg="white", width=20, height=2)
        btn_check.pack(side="left", padx=10)

        # Log Area
        lbl_log = tk.Label(root, text="System Logs & Reports:", font=("Arial", 10, "bold"))
        lbl_log.pack(pady=(10, 0), anchor="w", padx=20)
        
        self.log_area = scrolledtext.ScrolledText(root, width=80, height=20, state='disabled')
        self.log_area.pack(pady=5, padx=20)

        self.log("System Initialized. Ready to monitor.")

    def log(self, message):
        """Writes to both the GUI and the hidden log file"""
        # 1. Update GUI
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')
        
        # 2. Update Permanent File
        # We strip symbols to keep the text file clean
        clean_msg = message.replace("✅", "").replace("⚠️", "")
        logging.info(clean_msg)

    def browse_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_path.set(folder_selected)
            self.log(f"Selected Target: {folder_selected}")

    def run_baseline_creation(self):
        target_dir = self.folder_path.get()
        if not target_dir:
            messagebox.showwarning("Warning", "Please select a folder first!")
            return
        
        self.log("Action: Creating New Baseline...")
        result_msg = baseline.create_baseline(target_dir)
        self.log(result_msg)
        messagebox.showinfo("Success", "Baseline updated successfully.")

    def run_verification(self):
        target_dir = self.folder_path.get()
        if not target_dir:
            messagebox.showwarning("Warning", "Please select a folder first!")
            return

        self.log("Action: Running Integrity Check...")
        report = monitor.check_integrity(target_dir)
        
        if isinstance(report, str):
            self.log(report)
            return

        self.log("Scan Complete. Report:")
        if not report['modified'] and not report['added'] and not report['deleted']:
             self.log("✅ STATUS: SECURE (No changes detected)")
        else:
             self.log("⚠️ WARNING: CHANGES DETECTED!")
             for f in report['modified']: self.log(f"   [MODIFIED] {f}")
             for f in report['added']: self.log(f"   [ADDED]    {f}")
             for f in report['deleted']: self.log(f"   [DELETED]  {f}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileIntegrityApp(root)
    root.mainloop()