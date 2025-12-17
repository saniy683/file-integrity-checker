import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import logging
from datetime import datetime
import smtplib
from email.message import EmailMessage
import threading
import urllib.request
import json

# Import logic modules
import baseline 
import monitor
import hasher

# --- CONFIGURATION ---
logging.basicConfig(filename='audit_log.txt', level=logging.INFO, 
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# --- EMAIL CONFIGURATION ---
EMAIL_SENDER = "your_email@gmail.com"
EMAIL_PASSWORD = "your_app_password"  
EMAIL_RECEIVER = "your_email@gmail.com"

# --- WEB BASELINE STORAGE ---
WEB_BASELINE_FILE = "web_baseline.json"

class FileIntegrityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hybrid Integrity Monitor (System + Web)")
        self.root.geometry("1000x750")
        
        # Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", font=('Segoe UI', 10), rowheight=25)
        style.configure("Treeview.Heading", font=('Segoe UI', 11, 'bold'))

        self.folder_path = tk.StringVar()
        self.url_target = tk.StringVar()

        # ==================== SECTION 1: FILE MONITORING ====================
        lbl_files = tk.Label(root, text="📂 FILE SYSTEM MONITOR", font=("Segoe UI", 12, "bold"), bg="#ddd", anchor="w", padx=10)
        lbl_files.pack(fill="x", pady=(0, 5))

        top_frame = tk.Frame(root, padx=10, pady=5)
        top_frame.pack(fill="x")

        tk.Label(top_frame, text="Directory:").pack(side="left")
        tk.Entry(top_frame, textvariable=self.folder_path, width=40).pack(side="left", padx=5)
        tk.Button(top_frame, text="Browse", command=self.browse_folder).pack(side="left")

        tk.Button(top_frame, text="✅ Update Baseline", command=self.run_baseline_creation, bg="#5bc0de", fg="white", font=("Segoe UI", 9, "bold")).pack(side="right", padx=5)
        tk.Button(top_frame, text="⚠️ Check Files", command=self.run_verification, bg="#d9534f", fg="white", font=("Segoe UI", 9, "bold")).pack(side="right", padx=5)

        # Table
        table_frame = tk.Frame(root, padx=10, pady=5)
        table_frame.pack(fill="both", expand=True)

        columns = ("status", "time", "path")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=12)
        
        self.tree.heading("status", text="Event Status")
        self.tree.heading("time", text="Time Detected")
        self.tree.heading("path", text="Source Path / URL")
        
        self.tree.column("status", width=120, anchor="center")
        self.tree.column("time", width=150, anchor="center")
        self.tree.column("path", width=600, anchor="w")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        self.tree.tag_configure("modified", foreground="#d9534f")
        self.tree.tag_configure("added", foreground="#0275d8")
        self.tree.tag_configure("deleted", foreground="#f0ad4e")
        self.tree.tag_configure("secure", foreground="#5cb85c")
        self.tree.tag_configure("web_change", foreground="purple")

        # ==================== SECTION 2: WEB MONITORING ====================
        lbl_web = tk.Label(root, text="🌐 WEB INTEGRITY ANALYZER", font=("Segoe UI", 12, "bold"), bg="#ddd", anchor="w", padx=10)
        lbl_web.pack(fill="x", pady=(10, 5))

        web_frame = tk.Frame(root, padx=10, pady=10)
        web_frame.pack(fill="x")

        tk.Label(web_frame, text="Target URL:").pack(side="left")
        tk.Entry(web_frame, textvariable=self.url_target, width=40).pack(side="left", padx=5)
        
        tk.Button(web_frame, text="Set Web Baseline", command=self.set_web_baseline, bg="#5bc0de", fg="white").pack(side="left", padx=5)
        tk.Button(web_frame, text="Analyze Web", command=self.check_web_integrity, bg="#8a2be2", fg="white").pack(side="left", padx=5)

        self.status_bar = tk.Label(root, text="Ready to monitor.", bd=1, relief=tk.SUNKEN, anchor="w")
        self.status_bar.pack(side="bottom", fill="x")

    def log_event(self, status, path, tag):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.tree.insert("", 0, values=(status, timestamp, path), tags=(tag,))
        logging.info(f"{status}: {path}")
        self.status_bar.config(text=f"Last Event: {status}")

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder: self.folder_path.set(folder)

    def run_baseline_creation(self):
        if not self.folder_path.get(): 
            messagebox.showwarning("Warning", "Select a folder first!")
            return
        self.tree.delete(*self.tree.get_children())
        msg = baseline.create_baseline(self.folder_path.get())
        self.log_event("BASELINE", "File System Baseline Updated", "secure")
        messagebox.showinfo("Success", msg)

    def run_verification(self):
        if not self.folder_path.get(): 
            messagebox.showwarning("Warning", "Select a folder first!")
            return
        
        report = monitor.check_integrity(self.folder_path.get())
        
        if isinstance(report, str): 
            messagebox.showerror("Error", report)
            return
        
        if not report['modified'] and not report['added'] and not report['deleted']:
             self.log_event("SECURE", "Files Verified - No Changes", "secure")
        else:
             # Process changes
             details_text = ""
             
             if report['modified']:
                 details_text += "MODIFIED FILES:\n"
                 for f in report['modified']: 
                     self.log_event("MODIFIED", f, "modified")
                     details_text += f" - {f}\n"
             
             if report['added']:
                 details_text += "\nADDED FILES:\n"
                 for f in report['added']:    
                     self.log_event("NEW FILE", f, "added")
                     details_text += f" - {f}\n"

             if report['deleted']:
                 details_text += "\nDELETED FILES:\n"
                 for f in report['deleted']:  
                     self.log_event("DELETED", f, "deleted")
                     details_text += f" - {f}\n"

             # Trigger Alerts with Specific Details
             self.trigger_red_alert("FILE SYSTEM COMPROMISED", details_text)
             threading.Thread(target=self.send_email_alert, args=("Files", details_text)).start()

    def get_web_content_hash(self, url):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                return hasher.calculate_string_hash(response.read())
        except Exception:
            return None

    def set_web_baseline(self):
        url = self.url_target.get()
        if not url: return
        web_hash = self.get_web_content_hash(url)
        if not web_hash: 
            messagebox.showerror("Error", "Could not reach website.")
            return

        data = {url: web_hash}
        with open(WEB_BASELINE_FILE, 'w') as f: json.dump(data, f)
        self.log_event("WEB BASELINE", f"Baseline set for {url}", "secure")
        messagebox.showinfo("Success", "Web Baseline Saved.")

    def check_web_integrity(self):
        url = self.url_target.get()
        if not os.path.exists(WEB_BASELINE_FILE): return
        with open(WEB_BASELINE_FILE, 'r') as f: stored_data = json.load(f)
        
        if url not in stored_data: 
            messagebox.showerror("Error", "URL not in baseline.")
            return

        current_hash = self.get_web_content_hash(url)
        if current_hash == stored_data[url]:
            self.log_event("WEB SECURE", f"{url} (No Changes)", "secure")
        else:
            self.log_event("WEB CHANGE", f"{url} (Content Modified!)", "web_change")
            details = f"WEBSITE CONTENT CHANGED:\n{url}\n\nThe digital signature of the website no longer matches the baseline."
            self.trigger_red_alert("WEBSITE DEFACEMENT DETECTED", details)
            threading.Thread(target=self.send_email_alert, args=("Web", details)).start()

    # --- UPDATED ALERT SYSTEM ---
    def trigger_red_alert(self, title, details):
        alert = tk.Toplevel(self.root)
        alert.title("SECURITY ALERT")
        alert.geometry("600x400") # Made larger to fit details
        alert.configure(bg="#b90e0a")
        
        # Header
        tk.Label(alert, text="⚠️ SECURITY ALERT ⚠️", font=("Arial", 20, "bold"), fg="white", bg="#b90e0a").pack(pady=(20, 10))
        tk.Label(alert, text=title, font=("Arial", 14, "bold"), fg="white", bg="#b90e0a").pack(pady=5)
        
        # Scrollable Text Area for Details
        text_area = scrolledtext.ScrolledText(alert, width=60, height=10, font=("Consolas", 10))
        text_area.pack(pady=10, padx=20)
        
        # Insert details and make read-only
        text_area.insert(tk.END, details)
        text_area.config(state='disabled')
        
        # Button
        tk.Button(alert, text="ACKNOWLEDGE", command=alert.destroy, font=("Arial", 10, "bold"), bg="white", fg="red").pack(pady=15)

    def send_email_alert(self, type_alert, details):
        if "your_email" in EMAIL_SENDER: return
        try:
            msg = EmailMessage()
            msg.set_content(f"URGENT SECURITY ALERT\n\nType: {type_alert}\nTime: {datetime.now()}\n\nDETAILED REPORT:\n{details}")
            msg['Subject'] = f'CRITICAL: {type_alert} Alert'
            msg['From'] = EMAIL_SENDER
            msg['To'] = EMAIL_RECEIVER
            
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
            server.quit()
        except Exception as e:
            print(f"Email failed: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileIntegrityApp(root)
    root.mainloop()