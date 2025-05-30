# --- Begin admin check block ---
import ctypes, sys, os

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# def relaunch_as_admin():
#     script = os.path.abspath(sys.argv[0])
#     params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
#     python = os.path.join(os.path.dirname(sys.executable), "python.exe")
#     ctypes.windll.shell32.ShellExecuteW(
#         None, "runas", python, f'"{script}" {params}', None, 1
#     )

def relaunch_as_admin():
    script = os.path.abspath(sys.argv[0])
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    python = os.path.join(os.path.dirname(sys.executable), "python.exe")

    # Use cmd to set VWAR_ELEVATED and launch Python script
    cmd = f'set VWAR_ELEVATED=1 && "{python}" "{script}" {params}'
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", "cmd.exe", f'/c {cmd}', None, 1
    )

# Only do elevation on first run

if __name__ == "__main__":
    if not is_admin() and not os.environ.get("VWAR_ELEVATED"):
        # Set a flag so child process knows it's already elevated
        os.environ["VWAR_ELEVATED"] = "1"
        script = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        python = os.path.join(os.path.dirname(sys.executable), "python.exe")
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", python, f'"{script}" {params}', None, 1
        )
        sys.exit()


# --- End admin check block ---

import threading
import yara
import shutil
from tkinter import Tk, Frame, Canvas, Label, Text, Button, filedialog, messagebox, Scrollbar, StringVar, Toplevel, Listbox, ttk, Entry
from tkinter.ttk import Progressbar
import requests
import time
import base64
from datetime import datetime
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
import json
from plyer import notification

# ...rest of your code follows







class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.show)
        self.widget.bind("<Leave>", self.hide)

    def show(self, event=None):
        if self.tooltip or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 20
        self.tooltip = tw = Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.geometry(f"+{x}+{y}")
        label = Label(tw, text=self.text, justify='left',
                      background="#ffffe0", relief='solid', borderwidth=1,
                      font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hide(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None



def decode_base64(encoded_string):
        """Decodes a base64-encoded string, fixing padding if necessary."""
        encoded_string = encoded_string.replace(".quarantined", "")  # Remove extension if present
        padding_needed = len(encoded_string) % 4
        if padding_needed:
            encoded_string += "=" * (4 - padding_needed)  # Fix base64 padding

        try:
            return base64.urlsafe_b64decode(encoded_string).decode()
        except Exception as e:
            return f"Decoding Error: {e}"
        
        



class VWARScannerGUI:
    
    def __init__(self, root):
        print("[DEBUG] Entering VWARScannerGUI")
        self.root = root
        self.root.title("VWAR Scanner")
        print("[DEBUG] Tk root and title set")
        # self.watch_path = "C:/"  # Change this to the directory you want to monitor
        self.watch_paths = self.get_all_accessible_drives()
        print(f"[DEBUG] Watching all drives: {self.watch_paths}")
        self.monitor = RealTimeMonitor(self, self.watch_paths)
                
        
        
        # try:
        #     print("[DEBUG] Initializing RealTimeMonitor")
        #     self.monitor = RealTimeMonitor(self, self.watch_path)
        #     print("[DEBUG] RealTimeMonitor initialized")
        # except Exception as e:
        #     print(f"[ERROR] RealTimeMonitor init failed: {e}")
        #     import traceback
        #     traceback.print_exc()
        # self.monitor =RealTimeMonitor(self,self.watch_path)
        # self.monitor = RealTimeMonitor(self, self.watch_path)
        # self.monitor.start()  # Start real-time monitoring
        
        
        
        # Initialize monitoring state
        self.monitoring_active = False  # Must be False so scanning actually starts
        self.auto_scan_button_text = StringVar(value="Start Auto Scanning")  # Initial label
        print("[DEBUG] Basic variables initialized")
        
        
        # Create the status label
        self.auto_scan_status_label = Label(
            self.root,
            text="Status: Running ●",
            font=("Inter", 12, "bold"),
            bg="#009AA5",
            fg="green"
        )
        print("[DEBUG] Status label created")
        self.auto_scan_status_label.place(x=20, y=470)
        
        print("[DEBUG] Status label placed")
            # Create the home scan status label
        self.home_scan_status_label = Label(
            self.root,
            text="Status: Running ●",
            font=("Inter", 12, "bold"),
            bg="#009AA5",
            fg="green"
        )
        self.home_scan_status_label.place(x=110, y=570)

        # Create the button for auto scanning toggle
        Button(self.root, textvariable=self.auto_scan_button_text,
            command=self.toggle_auto_scanning, bg="#004953", fg="white",
            font=("Inter", 12, "bold")).place(x=20, y=420, width=200, height=40)
        
        
        
        
        
        
        self.rule_folder = os.path.join(os.getcwd(), "yara")
        self.quarantine_folder = os.path.join(os.getcwd(), "quarantine")
        self.backup_folder = os.path.join(os.getcwd(), "Vwarbackup")
        self.target_path = None
        self.rules = None
        self.stop_scan = False
        self.quarantined_files = {}

        self.selected_files = []
        self.selected_backup_folder = ""

        self.selected_vwar_folder = ""
        self.selected_restore_file = ""
        self.selected_restore_folder = ""
        
        self.auto_backup_frame = Frame(self.root, bg="white")
        self.backup_time_var = StringVar()
        self.auto_backup_folders = []
        self.auto_backup_running = False
        self.auto_backup_thread = None
        self.selected_backup_folder = ""
    

                
        # GUI Configuration
        root.geometry("1043x722")
        root.configure(bg="#009AA5")

        # Canvas for background and elements
        canvas = Canvas(
            root,
            bg="#009AA5",
            height=722,
            width=1043,
            bd=0,
            highlightthickness=0,
            relief="ridge")
        canvas.place(x=0, y=0)

        canvas.create_rectangle(
            0.0, 0.0, 1043.0, 52.0, fill="#055DA4", outline="")

        canvas.create_text(
            477.0, 9.0, anchor="nw", text="VWAR", fill="#FFFCFC", font=("Inter", 24 * -1))

        self.LOAD_TEXT = Text(
            bd=0,
            bg="#D9D9D9",
            fg="#000716",
            highlightthickness=0
        )
        self.LOAD_TEXT.place(
            x=302.0,
            y=73.0,
            width=440.0,
            height=60.0
        )

        # Create necessary folders
        self.create_folders()

        # Pages
        self.pages = {}
        self.create_home_page()
        self.create_scanning_page()
        self.create_backup_page()
        self.create_auto_scanning_page()
        # self.start_auto_scanning()
        self.build_auto_backup_page()

        # Show home page initially
        self.show_page("home")



        print("[DEBUG] VWARScannerGUI setup complete")  # ✅ Helps confirm init is done
        self.root.lift()                                # 🔼 Bring window to top
        self.root.attributes("-topmost", True)          # 🔒 Force it on top
        self.root.after(0, lambda: self.root.attributes("-topmost", False))  # 🔓 Let it behave normally after that
          # ✅ Auto start the real-time monitoring
        self.start_auto_scanning()
        

    # def get_all_accessible_drives(self):
    #     drives = []
    #     for p in psutil.disk_partitions(all=False):
    #         if os.path.exists(p.mountpoint) and os.access(p.mountpoint, os.R_OK):
    #             drives.append(p.mountpoint)
    #             # print(drives)
    #     return drives       
   
   
    def get_all_accessible_drives(self):
        drives = []
        for p in psutil.disk_partitions(all=False):
            if os.path.exists(p.mountpoint) and os.access(p.mountpoint, os.R_OK):
                drives.append(p.mountpoint)

        # Add the current user profile (Downloads, Desktop, etc.)
        user_home = os.path.expanduser("~")
        if os.path.exists(user_home):
            drives.append(user_home)

        return drives 

    
    
    
    def update_quarantine_listbox(self):
        """Refresh the quarantine listbox with latest quarantined files and metadata."""
        self.quarantine_listbox.delete(0, "end")
        index = 1

        for file_name in os.listdir(self.quarantine_folder):
            if not file_name.endswith(".quarantined"):
                continue

            quarantined_path = os.path.join(self.quarantine_folder, file_name)
            meta_path = quarantined_path + ".meta"

            if not os.path.exists(meta_path):
                continue  # Skip files without metadata

            try:
                with open(meta_path, "r") as meta_file:
                    metadata = json.load(meta_file)

                original_path = metadata.get("original_path", "Unknown")
                timestamp = metadata.get("timestamp", "Unknown")
                matched_rules = metadata.get("matched_rules", [])

                # Format timestamp for display
                if len(timestamp) == 14:
                    formatted_time = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]} {timestamp[8:10]}:{timestamp[10:12]}:{timestamp[12:]}"
                else:
                    formatted_time = "Unknown"

                # rules_str = ", ".join(matched_rules) if matched_rules else "Unknown"
                rules_str = matched_rules

                # Build display text
                display_text = (
                    f"{index}. File: {file_name.split('__')[0]}\n"
                    f"   → Quarantined: {formatted_time}\n"
                    f"   → From: {original_path}\n"
                    f"   → Matched Rules: {rules_str}"
                )

                self.quarantine_listbox.insert("end", display_text)
                index += 1

            except Exception as e:
                self.log(f"[ERROR] Failed to read metadata for {file_name}: {e}", "load")
        
        
    def log(self, message, log_type):
        if log_type == "load":
            self.LOAD_TEXT.insert("end", message + "\n")
            self.LOAD_TEXT.see("end")
        if log_type == "matched":
            self.matched_text.insert("end", message + "\n")
            self.matched_text.see("end")
        elif log_type == "tested":
            self.tested_text.insert("end", message + "\n")
            self.tested_text.see("end")   
       
       
    def notify_threat_detected(self,file_name, threat_type):
        notification.notify(
            title="Threat Detected",
            message=f"A threat was detected in {file_name}.\nType: {threat_type}",
            app_name="VWAR",
            timeout=10  # duration in seconds
        )     
            
    # def notify_match(self, file_path, matches):
    #     """Show a popup notification when a match is found."""
    #     try:
    #         filename = os.path.basename(file_path)
    #         match_text = ", ".join(matches)
    #         messagebox.showwarning(
    #             "⚠️ Match Detected!",
    #             f"File: {filename}\nMatched Rule(s): {match_text}\nThe file has been quarantined."
    #         )
    #     except Exception as e:
    #         self.log(f"[ERROR] Notification failed: {e}", "load")

    def create_folders(self):
        """Ensure required folders exist."""
        os.makedirs(self.rule_folder, exist_ok=True)
        os.makedirs(self.quarantine_folder, exist_ok=True)
        os.makedirs(self.backup_folder, exist_ok=True)

    # def show_page(self, page_name):
    #     """Display the requested page."""
    #     for page in self.pages.values():
    #         page.place_forget()
    #     self.pages[page_name].place(x=0, y=0, width=1043, height=722)
    
    def show_page(self, page_name):
        # """Display the requested page."""
        for page in self.pages.values():
            page.place_forget()
        self.pages[page_name].place(x=0, y=0, width=1043, height=722)

        # Auto-refresh the quarantine list when navigating to the auto scanning page
        if page_name == "auto_scanning":
            self.update_quarantine_listbox()

    def create_home_page(self):
        """Create the Home Page with navigation buttons."""
        home_page = Frame(self.root, bg="#009AA5")
        self.pages["home"] = home_page

        Label(home_page, text="VWAR Scanner", font=("Inter", 24), bg="#009AA5", fg="white").place(x=420, y=50)

        Button(home_page, text="Scanning", command=lambda: self.show_page("scanning"), bg="blue", fg="white",
               font=("Inter", 16)).place(x=400, y=200, width=200, height=50)

        Button(home_page, text="Backup", command=lambda: self.show_page("backup"), bg="orange", fg="white",
               font=("Inter", 16)).place(x=400, y=300, width=200, height=50)

        Button(home_page, text="auto_scanning", command=lambda: self.show_page("auto_scanning"), bg="green", fg="white",
               font=("Inter", 16)).place(x=400, y=400, width=200, height=50)
        

        
        
        # Label title for clarity
        Label(
            self.root,
            text="Auto Scanning Status",
            font=("Inter", 10, "bold"),
            bg="#009AA5",
            fg="white"
        ).place(x=110, y=540)

        # Blinking status label
        self.home_scan_status_label = Label(
            self.root,
            text="Status: Stopped",
            font=("Inter", 12, "bold"),
            bg="#009AA5",
            fg="red"
        )
        self.home_scan_status_label.place(x=110, y=570)
        
        
  

    def create_scanning_page(self):
        
        

        self.fetch_and_generate_yara_rules()
        self.root.after(100, self.load_rules)
        
        
        """Create the Scanning Page with scan controls."""
        scanning_page = Frame(self.root, bg="#009AA5")
        self.pages["scanning"] = scanning_page
        


        Button(scanning_page, text="Back", command=lambda: self.show_page("home"), bg="gold", fg="white",
               font=("Inter", 12)).place(x=10, y=10, width=80, height=30)

        Button(scanning_page, text="Select Target File", command=self.select_file).place(x=302.0, y=139.0, width=125.0, height=40.0)    
        label_help = Label(scanning_page, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
        label_help.place(x=432, y=139)
        Tooltip(label_help, "Choose a file to scan with YARA rules.")
        
        
        Button(scanning_page, text="Select Target Folder", command=self.select_folder).place(x=302.0, y=195.0, width=125.0, height=40.0)
        label_help = Label(scanning_page, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
        label_help.place(x=432, y=195)
        Tooltip(label_help, "Choose a folder to scan recursively")
        
        Button(scanning_page, text="Scan", command=self.start_scan_thread, bg="green", fg="white").place(x=485, y=150, width=73, height=25)
        label_help = Label(scanning_page, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
        label_help.place(x=570, y=150)
        Tooltip(label_help, "Start the scanning immediately.")
        
        Button(scanning_page, text="Stop", command=self.stop_scanning, bg="red", fg="white").place(x=485, y=195, width=73, height=25)
        label_help = Label(scanning_page, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
        label_help.place(x=570, y=195)
        Tooltip(label_help, "Stop the scanning immediately.")
        
        Button(scanning_page, text="Show Quarantined Files", command=lambda: self.show_page("auto_scanning"), bg="purple", fg="white",
       font=("Inter", 12)).place(x=700, y=195, width=200, height=40)
        label_help = Label(scanning_page, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
        label_help.place(x=910, y=195)
        Tooltip(label_help, "View files moved to quarantine after detection")
        
        self.progress_label = Label(scanning_page, text="PROGRESS : 0%", bg="#12e012", fg="#000000", font=("Inter", 12 * -1))
        self.progress_label.place(x=476.0, y=311.0)

        
        self.progress = Progressbar(scanning_page, orient="horizontal", length=350, mode="determinate")
        self.progress.place(x=354, y=350)

        
        
        self.LOAD_TEXT = Text(scanning_page, bg="#D9D9D9", fg="black", wrap="word")
        self.LOAD_TEXT.place(x=302.0, y=73.0, width=440.0, height=60.0)
        
        
        # Matched and Tested Files Sections
        canvas_matched = Canvas(scanning_page, bg="#AE0505", height=54, width=485, bd=0, highlightthickness=0, relief="ridge")
        canvas_matched.place(x=0, y=432)
        canvas_matched.create_text(164, 15, anchor="nw", text="MATCHED FILES", fill="#FFFFFF", font=("Inter", 20 * -1))

        self.matched_text = Text(scanning_page, bg="#D9D9D9", fg="#000000", wrap="word")
        self.matched_text.place(x=0, y=488, width=485, height=232)

        canvas_tested = Canvas(scanning_page, bg="#001183", height=54, width=485, bd=0, highlightthickness=0, relief="ridge")
        canvas_tested.place(x=557, y=432)
        canvas_tested.create_text(731 - 557, 15, anchor="nw", text="TESTED FILES", fill="#FFFFFF", font=("Inter", 20 * -1))

        self.tested_text = Text(scanning_page, bg="#D9D9D9", fg="#000000", wrap="word")
        self.tested_text.place(x=557, y=488, width=485, height=232)

 

    def fetch_and_generate_yara_rules(self):
            """Fetch YARA rules from a URL and write them into categorized .yar files."""
            try:
                url = "https://library.bitss.fr/windows.php"
                response = requests.get(url)
                response.raise_for_status()  # Check for request errors

                json_data = response.json()
                if not json_data:
                    self.log("[WARNING] No YARA rules found.", "load")
                    return

                # rule_files = {}

                for rule in json_data:
                    category = rule.get("categoryname", "uncategorized")  # Default to 'uncategorized' if no category
                    rule_name = rule.get("rulename", "unknown_rule")  # Use 'unknown_rule' if no name is provided
                    rule_content = rule.get("conditions", [{}])[0].get("string", "")
                    category_dir = os.path.join(self.rule_folder, category)
                    os.makedirs(category_dir, exist_ok=True)  # Create category directory if it doesn't exist

                    file_path = os.path.join(category_dir, f"{rule_name}.yar")

                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(rule_content)
                    
                  
                self.log("[INFO] YARA rules categorized and saved successfully.", "load")

            except requests.RequestException as e:
                self.log(f"[ERROR] Failed to fetch YARA rules: {e}", "load")
            except Exception as e:
                self.log(f"[ERROR] An error occurred: {e}", "load")


 
    
    
    def load_rules(self):
        try:
            # Initialize a dictionary to store valid rule files
            valid_rule_files = {}
            failed_files = []  # To store information about failed files

            # Loop through each subdirectory (category) in the 'yara' directory
            for root, dirs, files in os.walk(self.rule_folder):
                for file in files:
                    if file.endswith(".yar"):
                        file_path = os.path.join(root, file)

                        # Try to compile each YARA rule file
                        try:
                            yara.compile(filepath=file_path)
                            valid_rule_files[os.path.basename(file_path)] = file_path
                            # print(f"[INFO] Successfully compiled {file_path}")
                        except Exception as e:
                            # Add the failed file to the list
                            failed_files.append(f"Failed to compile {file_path}: {e}")
                            # print(f"[ERROR] Failed to compile YARA file {file_path}: {e}")

            if valid_rule_files:
                # If there are valid rule files, compile them all together
                self.rules = yara.compile(filepaths=valid_rule_files)
                self.log(f"[INFO] Successfully compiled {len(valid_rule_files)} YARA rule files.", "load")
            else:
                self.log("[ERROR] No valid YARA rules to compile.", "load")

            # If there were any failed files, log them to a text file
            if failed_files:
                failed_log_path = os.path.join(self.rule_folder, "failed_loads.txt")
                # print(failed_log_path)
                with open(failed_log_path, "w", encoding="utf-8") as log_file:
                    for failed_file in failed_files:
                        log_file.write(f"{failed_file}\n")
                self.log(f"[INFO] Failed to load {len(failed_files)} YARA rule files. See 'failed_loads.txt' for details.", "load")
            else:
                self.log("[INFO] All YARA files loaded successfully.", "load")

        except Exception as e:
            self.log(f"[ERROR] Failed to load YARA rules: {e}", "load")
        
    def select_file(self):
        target = filedialog.askopenfilename(
            title="Select File to Scan",
            filetypes=(("All files", "*.*"),),
        )
        if target:
            self.target_path = target
            self.LOAD_TEXT.delete("1.0", "end")
            self.log(f"[INFO] Selected file for scanning: {target}", "load")
    
    def select_folder(self):
        target = filedialog.askdirectory(title="Select Folder to Scan")
        if target:
            self.target_path = target
            self.LOAD_TEXT.delete("1.0", "end")
            self.log(f"[INFO] Selected folder for scanning: {target}", "load")
   
    def start_scan_thread(self):
        """Start scanning in a new thread to keep the GUI responsive."""
        scan_thread = threading.Thread(target=self.scan, daemon=True)
        scan_thread.start()

    def scan(self):
        if not self.rules:
            messagebox.showerror("Error", "Please ensure valid VWAR rules are loaded.")
            return
        if not self.target_path:
            messagebox.showerror("Error", "Please select a file or folder to scan.")
            return
        self.stop_scan = False
        self.matched_text.delete("1.0", "end")
        self.tested_text.delete("1.0", "end")
        if os.path.isfile(self.target_path):
            self.scan_file(self.target_path)
        elif os.path.isdir(self.target_path):
            self.scan_directory(self.target_path)
        self.progress.stop()
        self.progress_label.config(text="Scan Complete!")
    
    def scan_directory(self, directory):
        files = []
        
        # Collect all files in the directory and subdirectories
        for root, _, file_names in os.walk(directory):
            files.extend([os.path.join(root, file) for file in file_names])
        
        total_files = len(files)
        if total_files == 0:
            self.log("[INFO] No files found in the selected directory.", "load")
            return

        self.progress["maximum"] = total_files
        self.progress["value"] = 0  # Reset progress bar
        self.stop_scan = False  # Ensure scanning isn't prematurely stopped

        for i, file_path in enumerate(files, start=1):
            if self.stop_scan:
                self.log("[INFO] Scan stopped by user.", "load")
                break
            
            self.scan_file(file_path)  # Calls the modified scan_file method
            
            # Update progress
            self.progress["value"] = i
            progress_percent = int((i / total_files) * 100)
            self.progress_label.config(text=f"Progress: {progress_percent}%")
            self.root.update_idletasks()

        if not self.stop_scan:
            self.log("[INFO] Directory scan completed.", "load")

 
        
        
        
    # def scan_file(self, file_path):
    #     if self.stop_scan:
    #         return
    #     try:
    #         matches = self.rules.match(file_path, timeout=60)
    #         self.log(f"{file_path} \n", "tested")
            
    #         if matches:
              
    #             yara_file = os.path.splitext(os.path.basename(matches[0].namespace))[0]  # Remove .yar extension

    #             # Get the folder name where the YARA rule is located
    #             rule_folder = os.path.dirname(matches[0].namespace)
    #             folder_name = os.path.basename(rule_folder)

                
    #             # Log the match information with the folder name
    #             self.log(f"[MATCH] {file_path}\nRule: {matches[0].rule}\nMalware Type: {yara_file}\nRule Folder: {folder_name}\n\n", "matched")

    #             # Quarantine the file
    #             self.quarantine_file(file_path,yara_file) # Move matched file to quarantine
               
    #             self.notify_threat_detected(file_path, yara_file)

    #     except Exception as e:
    #         self.log(f"[ERROR] Failed to scan file '{file_path}': {e}", "tested")

    def scan_file(self, file_path):
        if self.stop_scan:
            return
        try:
            matches = self.rules.match(file_path, timeout=60)
            self.log(f"{file_path} \n", "tested")
            if matches:
                yara_file = os.path.splitext(os.path.basename(matches[0].namespace))[0]
                rule_folder = os.path.basename(os.path.dirname(matches[0].namespace))
                self.log(f"[MATCH] {file_path}\nRule: {matches[0].rule}\nMalware Type: {yara_file}\nRule Folder: {rule_folder}\n\n", "matched")
                self.quarantine_file(file_path, yara_file)
                self.notify_threat_detected(file_path, yara_file)
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            self.log(f"[ERROR] Failed to scan file: {file_path}\n{tb}", "tested")

    
    
    def quarantine_file(self, file_path, matched_rules):
        """Move matched files to a quarantine folder and save metadata."""
        if not os.path.exists(self.quarantine_folder):
            os.makedirs(self.quarantine_folder)

        file_name = os.path.basename(file_path)
        file_p = os.path.dirname(file_path)
        timestamp = time.strftime("%Y%m%d%H%M%S")
        MAX_ENCODED_LENGTH = 100

        # Encode path
        encoded_path = base64.urlsafe_b64encode(file_p.encode()).decode()[:MAX_ENCODED_LENGTH]
        quarantined_name = f"{file_name}__{timestamp}__{encoded_path}.quarantined"
        quarantined_path = os.path.join(self.quarantine_folder, quarantined_name)

        try:
            shutil.move(file_path, quarantined_path)
            self.log(f"[QUARANTINED] {file_path} → {quarantined_path} at {timestamp}", "matched")

            # Create metadata file
            metadata = {
                "original_path": file_path,
                "timestamp": timestamp,
                "matched_rules": matched_rules or []  # If None, default to empty list
            }
            meta_path = quarantined_path + ".meta"
            with open(meta_path, "w") as meta_file:
                json.dump(metadata, meta_file)
            
        except Exception as e:
            self.log(f"[ERROR] Failed to quarantine {file_path}: {e}", "matched")
        self.update_quarantine_listbox()
    

    def stop_scanning(self):
        """Stop the scanning process."""
        self.stop_scan = True



    def p(self):
        print ("button working")

    def create_auto_scanning_page(self):
        """Create the Auto Scanning Page for real-time file monitoring."""
        auto_scanning_page = Frame(self.root, bg="#009AA5")
        self.pages["auto_scanning"] = auto_scanning_page
        
        
    

        Button(auto_scanning_page, text="Back", command=lambda: self.show_page("home"),
            bg="purple", fg="white", font=("Inter", 12)).place(x=10, y=10, width=80, height=30)
        
       
        
        Label(auto_scanning_page, text="Quarantined Files", font=("Inter", 16, "bold"),
            bg="#009AA5", fg="white").place(x=20, y=60)


       
        # Quarantine Listbox
        self.quarantine_listbox = Listbox(
            auto_scanning_page,
            font=("Inter", 11),
        )
        self.quarantine_listbox.place(x=20, y=100, width=550, height=300)

        # Vertical Scrollbar
        y_scrollbar = Scrollbar(auto_scanning_page, orient="vertical", command=self.quarantine_listbox.yview)
        y_scrollbar.place(x=570, y=100, height=300)
        self.quarantine_listbox.config(yscrollcommand=y_scrollbar.set)

        # Horizontal Scrollbar
        x_scrollbar = Scrollbar(auto_scanning_page, orient="horizontal", command=self.quarantine_listbox.xview)
        x_scrollbar.place(x=20, y=400, width=550)
        self.quarantine_listbox.config(xscrollcommand=x_scrollbar.set)

        # Details Panel
        Label(auto_scanning_page, text="File Metadata", font=("Inter", 16, "bold"),
            bg="#009AA5", fg="white").place(x=600, y=60)

        self.detail_text = Text(auto_scanning_page, font=("Inter", 11), wrap="word", state="disabled",
                                bg="white", fg="black")
        self.detail_text.place(x=600, y=100, width=400, height=300)

        # Button Controls
        self.auto_scan_button_text = StringVar(value="Start Auto Scanning")
        self.monitoring_active = False
        
        
        # self.auto_scan_progress = ttk.Progressbar(
        #     auto_scanning_page,
        #     mode='indeterminate',
        #     length=200
        # )
        # self.auto_scan_progress.place(x=20, y=470)

    # Add a new status label for auto scanning status animation
        self.auto_scan_status_label = Label(
            auto_scanning_page,
            text="Status: Stopped",
            font=("Inter", 12, "bold"),
            bg="#009AA5",
            fg="red"
        )
        self.auto_scan_status_label.place(x=20, y=470)
        
        
        # def start_auto_scanning():
        #     if not self.monitoring_active:
        #         self.monitor = RealTimeMonitor(self, self.watch_path)
        #         self.monitor.start()
        #         self.monitoring_active = True
        #         self.auto_scan_button_text.set("Stop Auto Scanning")
        #         self.auto_scan_progress.start(10)  # Start the animation with a 10ms interval
        #         self.home_scan_progress.start(10)  # Start home page animation
        #         self.log("[INFO] Auto scanning started.", "load")

        # def stop_auto_scanning():
        #     if self.monitoring_active and hasattr(self, 'monitor'):
        #         self.monitor.stop()
        #         self.monitoring_active = False
        #         self.auto_scan_button_text.set("Start Auto Scanning")
        #         self.auto_scan_progress.stop()  # Stop the animation
        #         self.home_scan_progress.stop()  # Stop home page animation
        #         self.log("[INFO] Auto scanning stopped.", "load")
        
        



  

        Button(auto_scanning_page, textvariable=self.auto_scan_button_text, command=self.toggle_auto_scanning, bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=20, y=420, width=200, height=40)
        label_help = Label(auto_scanning_page, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
        label_help.place(x=220, y=420)
        Tooltip(label_help, "Toggle automatic scanning of newly created files.")
        
        
        
        
        def delete_selected_quarantined_files():
            selected_indices = self.quarantine_listbox.curselection()
            if not selected_indices:
                return

            for index in selected_indices[::-1]:
                display_text = self.quarantine_listbox.get(index)
                try:
                    line_start = display_text.split("File: ")[1].split("\n")[0].strip()
                except IndexError:
                    self.log(f"[ERROR] Could not parse filename from: {display_text}", "load")
                    continue

                matched_file = None
                for file in os.listdir(self.quarantine_folder):
                    if file.startswith(line_start) and file.endswith(".quarantined"):
                        matched_file = file
                        break

                if matched_file:
                    quarantined_path = os.path.join(self.quarantine_folder, matched_file)
                    meta_path = quarantined_path + ".meta"

                    try:
                        if os.path.exists(quarantined_path):
                            os.remove(quarantined_path)
                        if os.path.exists(meta_path):
                            os.remove(meta_path)

                        self.quarantine_listbox.delete(index)
                        # self.log(f"[INFO] Deleted quarantined file and metadata: {matched_file}", "load")
                        print(f"[INFO] Deleted quarantined file and metadata: {matched_file}", "load")
                    except Exception as e:
                        # self.log(f"[ERROR] Failed to delete {matched_file} or metadata: {e}", "load")
                        print(f"[ERROR] Failed to delete {matched_file} or metadata: {e}", "load")

        Button(auto_scanning_page, text="Delete Selected", command=delete_selected_quarantined_files, bg="#B22222", fg="white", font=("Inter", 12)).place(x=250, y=470, width=180, height=40)
        label_help = Label(auto_scanning_page, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
        label_help.place(x=430, y=470)
        Tooltip(label_help, "Permanently delete the selected quarantined file.")
        
        def restore_quarantined_file_from_backup():
            selected_index = self.quarantine_listbox.curselection()
            if not selected_index:
                messagebox.showwarning("No Selection", "Please select a file from the quarantine list.")
                return

            selected_item = self.quarantine_listbox.get(selected_index)
           
            # Extract the file path from the log entry (assumes format "[QUARANTINED] filepath")

            match = re.search(r"→ From:\s*(.+)", selected_item)
            if match:
                from_path = match.group(1)
                print(from_path)
            # match = re.search(r"\[QUARANTINED\] (.+)", selected_item)
            print(f"line 653 {selected_item}")
            if not match:
                messagebox.showerror("Error", "Could not parse the file path from the selected entry.")
                return

            original_path = match.group(1)
            filename = os.path.basename(original_path)

            # === Step 1: Ask for VWARbackup folder ===
            vwarbackup_folder = filedialog.askdirectory(title="Select VWARbackup Folder")
            if not vwarbackup_folder or not vwarbackup_folder.endswith("VWARbackup"):
                messagebox.showerror("Invalid Folder", "Please select a valid VWARbackup folder.")
                return

            # === Step 2: Search for the backup file ===
            found_files = []
            for root, _, files in os.walk(vwarbackup_folder):
                for f in files:
                    if f == filename + ".backup":
                        found_files.append(os.path.join(root, f))

            # === Step 5: No backup file found ===
            if not found_files:
                messagebox.showinfo("Not Found", f"No backup found for '{filename}' in VWARbackup.")
                return

            # === Step 3: Multiple backup files found, ask user to choose ===
            selected_backup = found_files[0]
            if len(found_files) > 1:
                choice_window = Toplevel(self.root)
                choice_window.title("Choose Backup Version")
                choice_window.geometry("500x300")

                Label(choice_window, text="Select a backup version to restore:", font=("Inter", 12)).pack(pady=10)
                listbox = Listbox(choice_window, width=80, height=10)
                listbox.pack(padx=10)

                for path in found_files:
                    listbox.insert("end", path)

                def confirm_choice():
                    nonlocal selected_backup
                    selection = listbox.curselection()
                    if not selection:
                        messagebox.showwarning("No Selection", "Please select a backup file.")
                        return
                    selected_backup = listbox.get(selection[0])
                    choice_window.destroy()

                Button(choice_window, text="Restore This Version", command=confirm_choice,
                    bg="blue", fg="white", font=("Inter", 12)).pack(pady=10)

                choice_window.transient(self.root)
                choice_window.grab_set()
                self.root.wait_window(choice_window)

            # === Step 4: Restore to original path ===
            try:
                os.makedirs(os.path.dirname(original_path), exist_ok=True)
                shutil.copy(selected_backup, original_path)
                messagebox.showinfo("Restored", f"Backup restored to:\n{original_path}")
                self.log(f"[RESTORED] {selected_backup} -> {original_path}", "load")
            except Exception as e:
                messagebox.showerror("Restore Failed", str(e))
                self.log(f"[ERROR] Restore failed: {e}", "load")

        
        Button(auto_scanning_page, text="Restore file from Backup", command=restore_quarantined_file_from_backup, bg="blue", fg="white", font=("Inter", 12)).place(x=250, y=420, width=180, height=40)
        label_help = Label(auto_scanning_page, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
        label_help.place(x=430, y=420)
        Tooltip(label_help, "Restore quarantined file using matching backup.")


        # Mapping display index to metadata path
        self.display_index_to_meta = {}

        def refresh_quarantine_list():
            self.quarantine_listbox.delete(0, "end")
            self.display_index_to_meta.clear()
            index = 1

            for file_name in os.listdir(self.quarantine_folder):
                if not file_name.endswith(".quarantined"):
                    continue

                quarantined_path = os.path.join(self.quarantine_folder, file_name)
                meta_path = quarantined_path + ".meta"

                if not os.path.exists(meta_path):
                    continue

                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        metadata = json.load(f)

                    original_path = metadata.get("original_path", "Unknown")
                    timestamp = metadata.get("timestamp", "")
                    matched_rules = metadata.get("matched_rules", [])

                    formatted_time = "Unknown"
                    if len(timestamp) == 14:
                        formatted_time = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]} {timestamp[8:10]}:{timestamp[10:12]}:{timestamp[12:]}"
                    # rules_str = ", ".join(matched_rules) if matched_rules else "Unknown"
                    rules_str = matched_rules
                    fname = file_name.split("__")[0]

                    display_text = (
                        f"{index}. File: {fname}\n"
                        f"   → Quarantined: {formatted_time}\n"
                        f"   → From: {original_path}\n"
                        f"   → Matched Rules: {rules_str}\n"
                        f"   → Type: {rules_str}"
                    )

                    self.quarantine_listbox.insert("end", display_text)
                    self.display_index_to_meta[index - 1] = meta_path
                    index += 1

                except Exception as e:
                    self.log(f"[ERROR] Failed to read metadata for {file_name}: {e}", "load")

        def on_quarantine_select(event):
            selected_indices = self.quarantine_listbox.curselection()
            if not selected_indices:
                return

            index = selected_indices[0]
            meta_path = self.display_index_to_meta.get(index)

            self.detail_text.config(state="normal")
            self.detail_text.delete("1.0", "end")

            if not meta_path or not os.path.exists(meta_path):
                self.detail_text.insert("end", "No metadata available.")
            else:
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        metadata = json.load(f)

                    original_path = metadata.get("original_path", "Unknown")
                    timestamp = metadata.get("timestamp", "Unknown")
                    matched_rules = metadata.get("matched_rules", [])
                    formatted_time = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]} {timestamp[8:10]}:{timestamp[10:12]}:{timestamp[12:]}" if len(timestamp) == 14 else "Unknown"
                    rules_str = "".join(matched_rules) if matched_rules else "None"

                    detail_text = (
                        f"Original Path:\n{original_path}\n\n"
                        f"Quarantined At:\n{formatted_time}\n\n"
                        f"Matched Rules:\n{rules_str}"
                    )
                    self.detail_text.insert("end", detail_text)

                except Exception as e:
                    self.detail_text.insert("end", f"Failed to load metadata.\nError: {e}")

            self.detail_text.config(state="disabled")

        self.quarantine_listbox.bind("<<ListboxSelect>>", on_quarantine_select)

        Button(auto_scanning_page, text="Refresh", command=refresh_quarantine_list,
            bg="#006666", fg="white", font=("Inter", 12)).place(x=470, y=420, width=100, height=40)

        # Initial load
        self.update_quarantine_listbox()
    
    
    
    
        refresh_quarantine_list()
        
    
    
    
    
    
    

    
    # def start_auto_scanning(self):
    #     if not self.monitoring_active:
    #         self.monitor = RealTimeMonitor(self, self.watch_path)
    #         self.monitor.start()
    #         self.monitoring_active = True
    #         self.auto_scan_button_text.set("Stop Auto Scanning")
    #         # Instead of starting a progress bar, start the blinking animation:
    #         self.animate_auto_scan_status()
    #         # Optionally, keep the home page animation if desired:
    #         # self.home_scan_progress()
    #         self.log("[INFO] Auto scanning started.", "load")
            
    # def stop_auto_scanning(self):
    #     if self.monitoring_active and hasattr(self, 'monitor'):
    #         self.monitor.stop()  # Properly stop the observer
    #         self.monitoring_active = False
    #         self.auto_scan_button_text.set("Start Auto Scanning")
    #         self.auto_scan_status_label.config(text="Status: Stopped", fg="red")
    #         self.log("[INFO] Auto scanning stopped.", "load")   
    
    # def start_auto_scanning(self):
    #     if not self.monitoring_active:
    #         self.monitor = RealTimeMonitor(self, self.watch_path)
    #         self.monitor.start()
    #         self.monitoring_active = True
    #         self.auto_scan_button_text.set("Stop Auto Scanning")
    #         self.auto_scan_status_label.config(text="Status: Running ●", fg="green")
    #         self.animate_auto_scan_status()
    #         # self.log("[INFO] Auto scanning started.", "load")
    #         print("[INFO] Auto scanning started.", "load")
    
    
    def start_auto_scanning(self):
        if not self.monitoring_active:
            print("[DEBUG] Starting RealTimeMonitor...")  # ✅ Debug log
            self.monitor = RealTimeMonitor(self, self.watch_paths)
            self.monitor.start()
            self.monitoring_active = True
            self.auto_scan_button_text.set("Stop Auto Scanning")
            self.auto_scan_status_label.config(text="Status: Running ●", fg="green")
            self.animate_auto_scan_status()
                
    def stop_auto_scanning(self):
        if self.monitoring_active and hasattr(self, 'monitor'):
            self.monitor.stop()
            self.monitoring_active = False
            self.auto_scan_button_text.set("Start Auto Scanning")
            self.auto_scan_status_label.config(text="Status: Stopped", fg="red")
            # self.log("[INFO] Auto scanning stopped.", "load")
            print("[INFO] Auto scanning stopped.", "load")
    
    def toggle_auto_scanning(self):
        if self.monitoring_active:
            self.stop_auto_scanning()
        else:
            self.start_auto_scanning()
    
    
    def animate_auto_scan_status(self):
        if self.monitoring_active:
            current = self.auto_scan_status_label.cget("text")
            # Toggle dot for blinking effect
            if "●" in current:
                new_text = "Status: Running   "
            else:
                new_text = "Status: Running ●"
            # Update both labels
            self.auto_scan_status_label.config(text=new_text, fg="green")
            self.home_scan_status_label.config(text=new_text, fg="green")
            self.root.after(500, self.animate_auto_scan_status)
        else:
            self.auto_scan_status_label.config(text="Status: Stopped", fg="red")
            self.home_scan_status_label.config(text="Status: Stopped", fg="red")


   
   
   
   
   
   
   
   
   
   
   
        

    def create_backup_page(self):
            """Create the Backup Page with Menu, Manual Backup, Restore, Auto Backup."""
            backup_page = Frame(self.root, bg="#009AA5")
            self.pages["backup"] = backup_page

            # Button(backup_page, text="Back", command=lambda: self.show_page("home"),
            #     bg="blue", fg="white", font=("Inter", 12)).place(x=10, y=10, width=80, height=30)

            # Create internal frames
            self.menu_frame = Frame(backup_page, bg="#009AA5")
            self.menu_frame.place(x=0, y=50, relwidth=1, relheight=1)

            # === Menu Frame contents ===
            Button(self.menu_frame, text="Manual Backup", command=self.show_manual_backup,
                bg="#004953", fg="white", font=("Inter", 14, "bold")).place(relx=0.3, rely=0.2, width=200, height=60)

            Button(self.menu_frame, text="Restore Backup Files", command=self.show_restore_backup,
                bg="#004953", fg="white", font=("Inter", 14, "bold")).place(relx=0.3, rely=0.4, width=200, height=60)

            Button(self.menu_frame, text="Auto Backup", command=self.show_auto_backup,
                bg="#004953", fg="white", font=("Inter", 14, "bold")).place(relx=0.3, rely=0.6, width=200, height=60)
            # Back button to return to Home
            Button(self.menu_frame, text="Back", command=lambda: self.show_page("home"),
                bg="blue", fg="white", font=("Inter", 12)).place(x=10, y=10, width=80, height=30)
            # === Manual Backup Frame contents ===
            # ===  backup Button ===
            self.manual_backup_frame = Frame(backup_page, bg="#009AA5")
            self.manual_backup_frame.place(x=0, y=50, relwidth=1, relheight=1)
            self.manual_backup_frame.place_forget()  # Hide manual backup at start


            Button(self.manual_backup_frame, text="Back", command=self.show_menu_frame,
                bg="red", fg="white", font=("Inter", 12)).place(x=10, y=10, width=80, height=30)
            
            Label(self.manual_backup_frame, text="Manual Backup", font=("Inter", 14, "bold"),
                bg="#009AA5", fg="black").place(x=400, y=10)

            Label(self.manual_backup_frame, text="Selected Files to Backup", font=("Inter", 14, "bold"),
                bg="#009AA5", fg="white").place(x=20, y=70)

            self.backup_file_listbox = Listbox(
                self.manual_backup_frame,
                font=("Inter", 11),
                selectmode="multiple"
            )
            self.backup_file_listbox.place(x=20, y=110, width=500, height=200)

            scrollbar = Scrollbar(self.manual_backup_frame, orient="vertical", command=self.backup_file_listbox.yview)
            scrollbar.place(x=520, y=110, height=200)
            self.backup_file_listbox.config(yscrollcommand=scrollbar.set)

            Label(self.manual_backup_frame, text="Backup Destination:", font=("Inter", 14, "bold"),
                bg="#009AA5", fg="white").place(x=20, y=320)

            self.backup_destination_label = Label(
                self.manual_backup_frame,
                text="No folder selected",
                font=("Inter", 11),
                bg="white",
                fg="black",
                anchor="w",
                relief="sunken"
            )
            self.backup_destination_label.place(x=20, y=360, width=500, height=30)
            
            Button(self.manual_backup_frame, text="Select Files", command=self.select_backup_files, bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=110, width=180, height=40)
            label_help = Label(self.manual_backup_frame, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
            label_help.place(x=790, y=110)
            Tooltip(label_help, "Choose one or more files to back up manually.")



            Button(self.manual_backup_frame, text="Select Destination", command=self.select_backup_destination, bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=170, width=180, height=40)
            label_help = Label(self.manual_backup_frame, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
            label_help.place(x=790, y=170)
            Tooltip(label_help, "Choose or create the VWARbackup folder.")

            self.start_backup_button = Button(self.manual_backup_frame, text="Start Backup", command=self.perform_backup, state="disabled", bg="#006666", fg="white", font=("Inter", 12, "bold"))
            self.start_backup_button.place(x=600, y=230, width=180, height=40)
            label_help = Label(self.manual_backup_frame, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
            label_help.place(x=790, y=230)
            Tooltip(label_help, "Back up selected files into today's dated folder.")

           
            # ===  backup Button ===
            #  === Manual Backup Frame contents ===
            
            # === Restore Backup Frame contents ===
            
            self.restore_backup_frame = Frame(backup_page, bg="#009AA5")
            self.restore_backup_frame.place(x=0, y=30, relwidth=1, relheight=1)
            self.restore_backup_frame.place_forget()  # Initially hidden
            
            
            
            
            
            
            # === Restore Backup Frame contents ===
            Button(self.restore_backup_frame, text="Back", command=self.show_menu_frame,
                bg="yellow", fg="white", font=("Inter", 12)).place(x=10, y=10, width=80, height=30)

            Label(self.restore_backup_frame, text="Restore Backup", font=("Inter", 14, "bold"),
                bg="#009AA5", fg="black").place(x=400, y=10)
            # Step 1: Select VWARbackup Folder
            Label(self.restore_backup_frame, text="Step 1: Select VWARbackup Folder", font=("Inter", 14, "bold"),
                bg="#009AA5", fg="white").place(x=20, y=40)

            self.vwar_folder_label = Label(
                self.restore_backup_frame,
                text="No folder selected",
                font=("Inter", 11),
                bg="white",
                fg="black",
                anchor="w",
                relief="sunken"
            )
            self.vwar_folder_label.place(x=20, y=70, width=500, height=30)

            # Button(self.restore_backup_frame, text="Select Folder", command=self.select_vwarbackup_folder,
            #     bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=60, width=180, height=40)

            Button(self.restore_backup_frame, text="Select Folder", command=self.select_vwarbackup_folder, bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=60, width=180, height=40)
            label_help = Label(self.restore_backup_frame, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
            label_help.place(x=790, y=60)
            Tooltip(label_help, "Select the main VWARbackup folder where your .backup files are stored.")

            # Step 2: Select Backup File
            Label(self.restore_backup_frame, text="Step 2: Select Backup File", font=("Inter", 14, "bold"),
                bg="#009AA5", fg="white").place(x=20, y=120)

            self.restore_file_label = Label(
                self.restore_backup_frame,
                text="No backup file selected",
                font=("Inter", 11),
                bg="white",
                fg="black",
                anchor="w",
                relief="sunken"
            )
            self.restore_file_label.place(x=20, y=160, width=500, height=30)

            # Button(self.restore_backup_frame, text="Select Backup File", command=self.select_restore_file,
            #     bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=160, width=180, height=40)
            Button(self.restore_backup_frame, text="Select Backup File", command=self.select_restore_file, bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=160, width=180, height=40)
            label_help = Label(self.restore_backup_frame, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
            label_help.place(x=790, y=160)
            Tooltip(label_help, "Pick the specific .backup file you want to restore.")
            # Step 3: Select Restore Location
            Label(self.restore_backup_frame, text="Step 3: Select Restore Location", font=("Inter", 14, "bold"),
                bg="#009AA5", fg="white").place(x=20, y=210)

            self.restore_location_label = Label(
                self.restore_backup_frame,
                text="No restore location selected",
                font=("Inter", 11),
                bg="white",
                fg="black",
                anchor="w",
                relief="sunken"
            )
            self.restore_location_label.place(x=20, y=250, width=500, height=30)

            # Button(self.restore_backup_frame, text="Select Location", command=self.select_restore_location,
            #     bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=250, width=180, height=40)


            Button(self.restore_backup_frame, text="Select Location", command=self.select_restore_location, bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=250, width=180, height=40)
            label_help = Label(self.restore_backup_frame, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
            label_help.place(x=790, y=250)
            Tooltip(label_help, "Choose where the restored file should be saved.")

            # Step 4: Start Restore
            self.start_restore_button = Button(self.restore_backup_frame, text="Start Restore", command=self.perform_restore,
                state="disabled", bg="#006666", fg="white", font=("Inter", 12, "bold"))
            self.start_restore_button.place(x=600, y=320, width=180, height=40)
            
             # === Restore Backup Frame contents ===
                
           
           
           # === Auto Backup Frame ===

            
            self.auto_backup_frame = Frame(backup_page, bg="#009AA5")
            self.auto_backup_frame.place(x=0, y=30, relwidth=1, relheight=1)
            self.auto_backup_frame.place_forget() 

            # === Auto Backup Frame ===

    # def hide_all_frames(self):
    #     for frame in [self.menu_frame, self.manual_backup_frame, self.restore_backup_frame, self.auto_backup_frame]:
    #         frame.place_forget()     
    def hide_all_frames(self):
        for frame in [self.menu_frame, self.manual_backup_frame, self.restore_backup_frame, self.auto_backup_frame]:
            frame.place_forget()


           
    # === Frame switchers ===

    def show_manual_backup(self):
        self.hide_all_frames()
        self.manual_backup_frame.place(x=0, y=50, relwidth=1, relheight=1)

    def show_menu_frame(self):
        self.hide_all_frames()
        self.menu_frame.place(x=0, y=50, relwidth=1, relheight=1)
        
        
    def show_restore_backup(self):
        self.hide_all_frames()
        self.restore_backup_frame.place(x=0, y=50, relwidth=1, relheight=1)


    def show_auto_backup(self):
        self.hide_all_frames()
        # self.menu_frame.place_forget()
        self.auto_backup_frame.place(x=0, y=50, relwidth=1, relheight=1)
        # === Helper backup methods ===

        # def show_manual_backup(self):
        #     """Focus on manual backup area. (Placeholder for now since always visible)"""
        #     pass  # Later you can hide/show areas here

 # === Helper backup methods ===

    def select_backup_files(self):
        files = filedialog.askopenfilenames(
            title="Select Files to Backup",
            filetypes=(("All files", "*.*"),)
        )
        if not files:
            return
        self.selected_files = list(files)
        self.backup_file_listbox.delete(0, "end")
        for f in self.selected_files:
            self.backup_file_listbox.insert("end", f)
        self.check_ready_to_backup()

    def select_backup_destination(self):
        destination = filedialog.askdirectory(
            title="Select Destination Folder for Backup"
        )
        if not destination:
            return
        if os.path.basename(destination) == "VWARbackup":
            self.selected_backup_folder = destination
        else:
            self.selected_backup_folder = os.path.join(destination, "VWARbackup")
            os.makedirs(self.selected_backup_folder, exist_ok=True)
        self.backup_destination_label.config(text=self.selected_backup_folder)
        self.check_ready_to_backup()

    def check_ready_to_backup(self):
        if self.selected_files and self.selected_backup_folder:
            self.start_backup_button.config(state="normal")
        else:
            self.start_backup_button.config(state="disabled")

    def perform_backup(self):
        today = datetime.now().strftime("%Y-%m-%d")
        date_folder_path = os.path.join(self.selected_backup_folder, today)
        os.makedirs(date_folder_path, exist_ok=True)

        try:
            for source_path in self.selected_files:
                filename = os.path.basename(source_path)
                backup_file_path = os.path.join(date_folder_path, filename + ".backup")
                shutil.copy2(source_path, backup_file_path)
                self.log(f"[BACKUP] {source_path} -> {backup_file_path}", "load")
            
            messagebox.showinfo("Backup Completed", f"Successfully backed up {len(self.selected_files)} files.")
        except Exception as e:
            self.log(f"[ERROR] Failed to backup files: {e}", "load")
            messagebox.showerror("Backup Error", f"Failed to backup files:\n{e}")


 # === Helper backup methods ===
 
 
 
  # === Helper restore methods ===
 
    def select_restore_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Backup File",
            filetypes=(("Backup files", "*.backup"),)
        )
        if not file_path:
            return
        self.selected_restore_file = file_path
        self.restore_file_label.config(text=file_path)
        self.check_ready_to_restore()

    def select_restore_location(self):
        folder_path = filedialog.askdirectory(title="Select Restore Location")
        if not folder_path:
            return
        self.selected_restore_folder = folder_path
        self.restore_location_label.config(text=folder_path)
        self.check_ready_to_restore()

    def check_ready_to_restore(self):
        if self.selected_restore_file and self.selected_restore_folder:
            self.start_restore_button.config(state="normal")
        else:
            self.start_restore_button.config(state="disabled")

    def perform_restore(self):
        original_name = os.path.basename(self.selected_restore_file).replace(".backup", "")
        restore_path = os.path.join(self.selected_restore_folder, original_name)
        try:
            shutil.copy(self.selected_restore_file, restore_path)
            self.log(f"[RESTORED] {self.selected_restore_file} -> {restore_path}", "load")
            messagebox.showinfo("Restore Completed", f"File restored to:\n{restore_path}")
        except Exception as e:
            self.log(f"[ERROR] Failed to restore file: {e}", "load")
            messagebox.showerror("Restore Error", f"Failed to restore file:\n{e}")
    def select_vwarbackup_folder(self):
        folder_path = filedialog.askdirectory(title="Select VWARbackup Folder")
        if not folder_path:
            return
        if not folder_path.endswith("VWARbackup"):
            messagebox.showerror("Error", "Please select a valid VWARbackup folder.")
            return
        self.selected_vwar_folder = folder_path
        self.vwar_folder_label.config(text=folder_path)
        self.selected_restore_file = ""
        self.restore_file_label.config(text="No backup file selected")
        self.check_ready_to_restore()

  # === Helper restore methods ===


    def build_auto_backup_page(self):
        self.auto_backup_frame.config(bg="#009AA5")

        Label(self.auto_backup_frame, text="Auto Backup Settings", font=("Inter", 18, "bold"),
            bg="#009AA5", fg="white").place(x=300, y=10)

        # Step 1: Select folders
        Label(self.auto_backup_frame, text="Step 1: Select Folders to Backup", font=("Inter", 14, "bold"),
            bg="#009AA5", fg="white").place(x=20, y=60)

        self.selected_folders_label = Label(self.auto_backup_frame, text="No folders selected", font=("Inter", 11),
                                            bg="white", fg="black", anchor="w", relief="sunken")
        self.selected_folders_label.place(x=20, y=100, width=500, height=30)

        # Button(self.auto_backup_frame, text="Select Folders", command=self.select_auto_backup_folders,
        #     bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=100, width=180, height=40)


        Button(self.auto_backup_frame, text="Select Folders", command=self.select_auto_backup_folders, bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=110, width=180, height=40)
        label_help = Label(self.auto_backup_frame, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
        label_help.place(x=790, y=110)
        Tooltip(label_help, "Choose folders that should be backed up automatically every day.")

        # Step 2: Select Time
        Label(self.auto_backup_frame, text="Step 2: Set Daily Backup Time (HH:MM) 24 hour clock", font=("Inter", 14, "bold"),
            bg="#009AA5", fg="white").place(x=20, y=160)

        # self.backup_time_entry = Entry(self.auto_backup_frame, textvariable=self.backup_time_var, font=("Inter", 12))
        # self.backup_time_entry.place(x=20, y=200, width=120, height=30)
        # Label(self.auto_backup_frame, text="Time (HH:MM):", bg="#333333", fg="white", font=("Arial", 12)).place(x=20, y=200)
        # self.auto_backup_time_entry = Entry(self.auto_backup_frame, font=("Arial", 12))
        # self.auto_backup_time_entry.place(x=20, y=200, width=120, height=30)
        self.backup_time_var = StringVar()
        self.auto_backup_time_entry = Entry(self.auto_backup_frame, textvariable=self.backup_time_var, font=("Arial", 12))
        self.auto_backup_time_entry.place(x=20, y=200, width=120, height=30)

        
        label_help = Label(self.auto_backup_frame, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
        label_help.place(x=170, y=200)
        Tooltip(label_help, "Set the time of day when automatic backup will run (24-hour format, e.g. 14:30).")

        # Step 3: Select Backup Destination
        Label(self.auto_backup_frame, text="Step 3: Select Backup Destination", font=("Inter", 14, "bold"),
            bg="#009AA5", fg="white").place(x=20, y=250)

        self.auto_backup_dest_label = Label(self.auto_backup_frame, text="No destination selected",
                                            font=("Inter", 11), bg="white", fg="black", anchor="w", relief="sunken")
        self.auto_backup_dest_label.place(x=20, y=290, width=500, height=30)

        # Button(self.auto_backup_frame, text="Select Backup Destination", command=self.select_auto_backup_destination,
        #     bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=290, width=230, height=40)
        Button(self.auto_backup_frame, text="Select Destination", command=self.select_auto_backup_destination, bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=290, width=180, height=40)
        label_help = Label(self.auto_backup_frame, text="?", bg="#009AA5", fg="white", font=("Arial", 12, "bold"))
        label_help.place(x=790, y=290)
        Tooltip(label_help, "Choose the VWARbackup folder where automatic backups will be saved.")

        # Step 4: Control Buttons
        Label(self.auto_backup_frame, text="Step 4: Start or Stop Auto Backup", font=("Inter", 14, "bold"),
            bg="#009AA5", fg="white").place(x=20, y=340)

        self.start_button = Button(self.auto_backup_frame, text="Start Auto Backup", command=self.start_auto_backup,
                                bg="#006666", fg="white", font=("Inter", 12, "bold"))
        self.start_button.place(x=20, y=380, width=180, height=40)

        self.stop_button = Button(self.auto_backup_frame, text="Stop Auto Backup", command=self.stop_auto_backup,
                                state="disabled", bg="#993333", fg="white", font=("Inter", 12, "bold"))
        self.stop_button.place(x=220, y=380, width=180, height=40)

        # Back Button
        Button(self.auto_backup_frame, text="Back", command=self.show_menu_frame,
            bg="pink", fg="black", font=("Inter", 12)).place(x=10, y=10, width=80, height=30)
        
        
        self.auto_status_label = Label(self.auto_backup_frame, text="Status: Stopped", font=("Inter", 12, "bold"),
                               bg="#009AA5", fg="white")
        self.auto_status_label.place(x=420, y=400)

        self.load_auto_backup_settings()


    def select_auto_backup_folders(self):
        folders = filedialog.askdirectory(mustexist=True, title="Select Folder to Backup")
        if folders:
            self.auto_backup_folders = [folders]
            self.selected_folders_label.config(text="\n".join(self.auto_backup_folders))



    def auto_backup_worker(self):
        day_index = 0  # 0 to 6

        while self.auto_backup_running:
            now = datetime.now()
            target_time = self.backup_time_var.get()

            try:
                backup_hour, backup_minute = map(int, target_time.split(":"))
            except ValueError:
                self.log("[ERROR] Invalid time format.", "load")
                break

            while self.auto_backup_running:
                now = datetime.now()
                if now.hour == backup_hour and now.minute == backup_minute:
                    # self.perform_rotating_backup(day_index)
                    self.perform_rotating_backup()
                    day_index = (day_index + 1) % 7
                    time.sleep(60)  # Wait a minute before checking again
                time.sleep(5)


    def start_auto_backup(self):
        if not self.auto_backup_folders or not self.backup_time_var.get() or not hasattr(self, 'auto_backup_destination'):
            messagebox.showwarning("Missing Info", "Please select folders, destination, and set time.")
            return
        self.auto_backup_running = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        self.auto_backup_thread = threading.Thread(target=self.auto_backup_worker, daemon=True)
        self.auto_backup_thread.start()
        self.log("[AUTO BACKUP] Started", "load")
        self.save_auto_backup_settings()
        
        self.animate_auto_backup_status()


    def stop_auto_backup(self):
        self.auto_backup_running = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.log("[AUTO BACKUP] Stopped", "load")
        self.save_auto_backup_settings()
        
        

    # def perform_rotating_backup(self):
    #     today = datetime.now().strftime("%d-%m-%Y")
    #     state_file = os.path.join(self.auto_backup_destination, "AutoBackup", "auto_backup_state.json")
    #     backup_root = os.path.join(self.auto_backup_destination, "AutoBackup")
    #     os.makedirs(backup_root, exist_ok=True)

    #     # Load or initialize state
    #     if os.path.exists(state_file):
    #         with open(state_file, "r") as f:
    #             state = json.load(f)
    #         last_index = state.get("last_index", 0)
    #         last_date = state.get("last_date", "")
    #     else:
    #         state = {}
    #         last_index = 0
    #         last_date = ""

    #     # If today is already backed up, do nothing
    #     today_already_done = False
    #     for folder in os.listdir(backup_root):
    #         if folder.endswith(today):
    #             self.log(f"[AUTO BACKUP] Skipped - Already backed up today in {folder}", "load")
    #             today_already_done = True
    #             break

    #     if today_already_done:
    #         return

    #     # Determine next day index (rotate 1-7)
    #     next_index = (last_index % 7) + 1
    #     folder_name = f"day{next_index}_{today}"
    #     day_folder = os.path.join(backup_root, folder_name)
    #     os.makedirs(day_folder, exist_ok=True)

    #     try:
    #         for folder in self.auto_backup_folders:
    #             for root_dir, _, files in os.walk(folder):
    #                 for file in files:
    #                     src_file = os.path.join(root_dir, file)
    #                     rel_path = os.path.relpath(src_file, folder)
    #                     dest_file = os.path.join(day_folder, rel_path + ".backup")

    #                     os.makedirs(os.path.dirname(dest_file), exist_ok=True)
    #                     shutil.copy2(src_file, dest_file)

    #         # Save new state
    #         state["last_index"] = next_index
    #         state["last_date"] = today
    #         with open(state_file, "w") as f:
    #             json.dump(state, f)

    #         self.log(f"[AUTO BACKUP] Completed in {folder_name}", "load")
    #     except Exception as e:
    #         self.log(f"[ERROR] Auto Backup failed: {e}", "load")



    # def perform_rotating_backup(self):
    #     from datetime import datetime

    #     today = datetime.now().strftime("%d-%m-%Y")
    #     current_time = datetime.now().time()

    #     backup_root = os.path.join(self.auto_backup_destination, "AutoBackup")
    #     os.makedirs(backup_root, exist_ok=True)

    #     # Regex pattern to match folders like: day3_12-05-25
    #     pattern = re.compile(r"day(\d)_(\d{2}-\d{2}-\d{2})")

    #     last_day = 0
    #     last_date_str = ""
    #     last_date_obj = None
    #     latest_folder_path = ""

    #     for folder in os.listdir(backup_root):
    #         match = pattern.match(folder)
    #         if match:
    #             day_num = int(match.group(1))
    #             folder_date = match.group(2)

    #             # Convert date format from DD-MM-YY to datetime object
    #             try:
    #                 folder_date_obj = datetime.strptime(folder_date, "%d-%m-%y")
    #             except:
    #                 continue

    #             if not last_date_obj or folder_date_obj > last_date_obj:
    #                 last_day = day_num
    #                 last_date_str = folder_date
    #                 last_date_obj = folder_date_obj
    #                 latest_folder_path = os.path.join(backup_root, folder)

    #     # Decide whether to create a new folder or reuse today's
    #     today_obj = datetime.strptime(today, "%d-%m-%Y")
    #     today_short = today_obj.strftime("%d-%m-%y")  # To compare with folder format

    #     target_folder = ""

    #     if last_date_str == today_short:
    #         # Reuse today's folder if current time > previous time
    #         target_folder = latest_folder_path
    #         self.log(f"[AUTO BACKUP] Appending to existing {os.path.basename(target_folder)}", "load")
    #     else:
    #         # Rotate to next day number (1–7)
    #         next_day = 1 if last_day >= 7 else last_day + 1
    #         folder_name = f"day{next_day}_{today_short}"
    #         target_folder = os.path.join(backup_root, folder_name)
    #         os.makedirs(target_folder, exist_ok=True)
    #         self.log(f"[AUTO BACKUP] Created new folder {folder_name}", "load")

    #     try:
    #         for folder in self.auto_backup_folders:
    #             for root_dir, _, files in os.walk(folder):
    #                 for file in files:
    #                     src_file = os.path.join(root_dir, file)
    #                     rel_path = os.path.relpath(src_file, folder)
    #                     dest_file = os.path.join(target_folder, rel_path + ".backup")

    #                     os.makedirs(os.path.dirname(dest_file), exist_ok=True)
    #                     shutil.copy2(src_file, dest_file)

    #         self.log(f"[AUTO BACKUP] Backup completed in {target_folder}", "load")
    #     except Exception as e:
    #         self.log(f"[ERROR] Auto Backup failed: {e}", "load")

    # def perform_rotating_backup(self):
    #     from datetime import datetime

    #     today = datetime.now().strftime("%d-%m-%Y")
    #     today_short = datetime.now().strftime("%d-%m-%y")
    #     current_time = datetime.now().time()

    #     backup_root = os.path.join(self.auto_backup_destination, "AutoBackup")
    #     os.makedirs(backup_root, exist_ok=True)

    #     pattern = re.compile(r"day(\d)_(\d{2}-\d{2}-\d{2})")
    #     last_day = 0
    #     last_date_obj = None
    #     latest_folder_path = ""

    #     for folder in os.listdir(backup_root):
    #         match = pattern.match(folder)
    #         if match:
    #             day_num = int(match.group(1))
    #             folder_date_str = match.group(2)

    #             try:
    #                 folder_date_obj = datetime.strptime(folder_date_str, "%d-%m-%y")
    #             except:
    #                 continue

    #             if not last_date_obj or folder_date_obj > last_date_obj:
    #                 last_day = day_num
    #                 last_date_obj = folder_date_obj
    #                 latest_folder_path = os.path.join(backup_root, folder)

    #     # Decide whether to reuse or create new
    #     target_folder = ""
    #     if last_date_obj and last_date_obj.date() == datetime.now().date():
    #         target_folder = latest_folder_path
    #         self.log(f"[AUTO BACKUP] Appending to existing {os.path.basename(target_folder)}", "load")
    #     else:
    #         next_day = 1 if last_day >= 7 else last_day + 1
    #         folder_name = f"day{next_day}_{today_short}"
    #         target_folder = os.path.join(backup_root, folder_name)
    #         os.makedirs(target_folder, exist_ok=True)
    #         self.log(f"[AUTO BACKUP] Created new folder {folder_name}", "load")

    #     try:
    #         for folder in self.auto_backup_folders:
    #             for root_dir, _, files in os.walk(folder):
    #                 for file in files:
    #                     src_file = os.path.join(root_dir, file)
    #                     rel_path = os.path.relpath(src_file, folder)
    #                     dest_file = os.path.join(target_folder, rel_path + ".backup")

    #                     os.makedirs(os.path.dirname(dest_file), exist_ok=True)
    #                     shutil.copy2(src_file, dest_file)

    #         self.log(f"[AUTO BACKUP] Backup completed in {target_folder}", "load")
    #     except Exception as e:
    #         self.log(f"[ERROR] Auto Backup failed: {e}", "load")



    # def perform_rotating_backup(self):
    #     from datetime import datetime

    #     today_full = datetime.now().strftime("%d-%m-%Y")  # → 12-05-2025
    #     current_time = datetime.now().time()

    #     backup_root = os.path.join(self.auto_backup_destination, "AutoBackup")
    #     os.makedirs(backup_root, exist_ok=True)

    #     # Match folders like day3_12-05-2025
    #     pattern = re.compile(r"day(\d)_(\d{2}-\d{2}-\d{4})")
    #     last_day = 0
    #     last_date_obj = None
    #     latest_folder_path = ""

    #     for folder in os.listdir(backup_root):
    #         match = pattern.match(folder)
    #         if match:
    #             day_num = int(match.group(1))
    #             folder_date_str = match.group(2)

    #             try:
    #                 folder_date_obj = datetime.strptime(folder_date_str, "%d-%m-%Y")
    #             except:
    #                 continue

    #             if not last_date_obj or folder_date_obj > last_date_obj:
    #                 last_day = day_num
    #                 last_date_obj = folder_date_obj
    #                 latest_folder_path = os.path.join(backup_root, folder)

    #     # Reuse or create folder
    #     target_folder = ""
    #     if last_date_obj and last_date_obj.date() == datetime.now().date():
    #         target_folder = latest_folder_path
    #         self.log(f"[AUTO BACKUP] Appending to existing {os.path.basename(target_folder)}", "load")
    #     else:
    #         next_day = 1 if last_day >= 7 else last_day + 1
    #         folder_name = f"day{next_day}_{today_full}"
    #         target_folder = os.path.join(backup_root, folder_name)
    #         os.makedirs(target_folder, exist_ok=True)
    #         self.log(f"[AUTO BACKUP] Created new folder {folder_name}", "load")

    #     try:
    #         for folder in self.auto_backup_folders:
    #             for root_dir, _, files in os.walk(folder):
    #                 for file in files:
    #                     src_file = os.path.join(root_dir, file)
    #                     rel_path = os.path.relpath(src_file, folder)
    #                     dest_file = os.path.join(target_folder, rel_path + ".backup")

    #                     os.makedirs(os.path.dirname(dest_file), exist_ok=True)
    #                     shutil.copy2(src_file, dest_file)

    #         self.log(f"[AUTO BACKUP] Backup completed in {target_folder}", "load")
    #     except Exception as e:
    #         self.log(f"[ERROR] Auto Backup failed: {e}", "load")



    def perform_rotating_backup(self):
        today = datetime.now().strftime("%d-%m-%Y")
        today_obj = datetime.strptime(today, "%d-%m-%Y")
        backup_root = os.path.join(self.auto_backup_destination, "AutoBackup")
        os.makedirs(backup_root, exist_ok=True)

        pattern = re.compile(r"day(\d)_(\d{2}-\d{2}-\d{4})")
        existing_folders = []

        for folder in os.listdir(backup_root):
            match = pattern.match(folder)
            if match:
                day_num = int(match.group(1))
                folder_date = match.group(2)
                try:
                    folder_date_obj = datetime.strptime(folder_date, "%d-%m-%Y")
                    existing_folders.append((day_num, folder_date_obj, folder))
                except:
                    continue

        # Check if today's backup already exists
        for _, date_obj, folder in existing_folders:
            if date_obj.date() == today_obj.date():
                self.log(f"[AUTO BACKUP] Skipped - Already backed up today in {folder}", "load")
                return

        # Sort by date to find the oldest
        existing_folders.sort(key=lambda x: x[1])

        if len(existing_folders) < 7:
            next_day = len(existing_folders) + 1
        else:
            # Rotate: reuse the oldest folder slot (overwrite)
            next_day = existing_folders[0][0]
            # Delete the old folder
            shutil.rmtree(os.path.join(backup_root, existing_folders[0][2]), ignore_errors=True)

        folder_name = f"day{next_day}_{today}"
        target_folder = os.path.join(backup_root, folder_name)
        os.makedirs(target_folder, exist_ok=True)

        try:
            for folder in self.auto_backup_folders:
                for root_dir, _, files in os.walk(folder):
                    for file in files:
                        src_file = os.path.join(root_dir, file)
                        rel_path = os.path.relpath(src_file, folder)
                        dest_file = os.path.join(target_folder, rel_path + ".backup")
                        os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                        shutil.copy2(src_file, dest_file)

            self.log(f"[AUTO BACKUP] Backup completed in {folder_name}", "load")
        except Exception as e:
            self.log(f"[ERROR] Auto Backup failed: {e}", "load")


    def select_auto_backup_destination(self):
        destination = filedialog.askdirectory(title="Select Destination for Auto Backup")
        if not destination:
            return
        if os.path.basename(destination) == "VWARbackup":
            self.auto_backup_destination = destination
        else:
            self.auto_backup_destination = os.path.join(destination, "VWARbackup")
            os.makedirs(self.auto_backup_destination, exist_ok=True)
        
        self.auto_backup_dest_label.config(text=self.auto_backup_destination)



    # def save_auto_backup_settings(self):
    #     config = {
    #         "folders": self.auto_backup_folders,
    #         "time": self.backup_time_var.get(),
    #         "destination": self.auto_backup_destination
    #     }
    #     with open("auto_backup_config.json", "w") as f:
    #         json.dump(config, f)


    def save_auto_backup_settings(self):
        config = {
            "running": self.auto_backup_running,
            "time": self.backup_time_var.get(),
            "destination": getattr(self, "auto_backup_destination", ""),
            "folders": self.auto_backup_folders
        }
        config_path = os.path.join(os.getcwd(), "auto_backup_config.json")
        with open(config_path, "w") as f:
            json.dump(config, f)

    # def load_auto_backup_settings(self):
    #     try:
    #         with open("auto_backup_config.json", "r") as f:
    #             config = json.load(f)
    #             self.auto_backup_folders = config.get("folders", [])
    #             self.backup_time_var.set(config.get("time", ""))
    #             self.auto_backup_destination = config.get("destination", "")

    #             # Update UI labels
    #             if self.auto_backup_folders:
    #                 self.selected_folders_label.config(text="\n".join(self.auto_backup_folders))
    #             if self.auto_backup_destination:
    #                 self.auto_backup_dest_label.config(text=self.auto_backup_destination)

    #             # Automatically start if settings are valid
    #             if self.auto_backup_folders and self.backup_time_var.get() and self.auto_backup_destination:
    #                 self.start_auto_backup()

    #     except Exception as e:
    #         self.log(f"[AUTO BACKUP] Failed to load settings: {e}", "load")

    # def load_auto_backup_settings(self):
    #     try:
    #         with open("auto_backup_config.json", "r") as f:
    #             config = json.load(f)
    #             self.auto_backup_folders = config.get("folders", [])
    #             self.backup_time_var.set(config.get("time", ""))
    #             self.auto_backup_destination = config.get("destination", "")

    #             # Update UI
    #             if self.auto_backup_folders:
    #                 self.selected_folders_label.config(text="\n".join(self.auto_backup_folders))
    #             if self.auto_backup_destination:
    #                 self.auto_backup_dest_label.config(text=self.auto_backup_destination)

    #             # Start auto backup thread
    #             if self.auto_backup_folders and self.backup_time_var.get() and self.auto_backup_destination:
    #                 self.auto_backup_running = True
    #                 self.start_button.config(state="disabled")
    #                 self.stop_button.config(state="normal")
    #                 self.auto_backup_thread = threading.Thread(target=self.auto_backup_worker, daemon=True)
    #                 self.auto_backup_thread.start()
    #                 self.animate_auto_backup_status()
    #                 self.log("[AUTO BACKUP] Auto-started based on saved settings.", "load")

    #     except Exception as e:
    #         self.log(f"[AUTO BACKUP] Failed to load settings: {e}", "load")

    def load_auto_backup_settings(self):
        config_path = os.path.join(os.getcwd(), "auto_backup_config.json")
        if not os.path.exists(config_path):
            return
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
            self.backup_time_var.set(config.get("time", ""))
            self.auto_backup_folders = config.get("folders", [])
            self.selected_folders_label.config(text="\n".join(self.auto_backup_folders))
            self.auto_backup_destination = config.get("destination", "")
            self.auto_backup_dest_label.config(text=self.auto_backup_destination)
            if config.get("running", False):
                self.start_auto_backup()
        except Exception as e:
            print(f"[ERROR] Failed to load auto backup config: {e}")

    def animate_auto_backup_status(self):
        if self.auto_backup_running:
            current = self.auto_status_label.cget("text")
            if "●" in current:
                self.auto_status_label.config(text="Status: Running   ", fg="green")
            else:
                self.auto_status_label.config(text="Status: Running ●" ,fg="green")
            self.root.after(500, self.animate_auto_backup_status)
        else:
            self.auto_status_label.config(text="Status: Stopped", fg="red")


# EXCLUDED_PATHS = [
#     # "C:\\Windows",
#     # "C:\\Program Files",
#     # "C:\\Program Files (x86)",
#     "C:\\$Recycle.Bin",
#     "C:\\System Volume Information"
# ]







class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, scanner):
        self.scanner = scanner  # Reference to the VWAR scanner instance
    
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            self.prompt_scan(file_path)

    def prompt_scan(self, file_path):
        def scan_decision():
            threading.Thread(target=self.scanner.scan_file, args=(file_path,), daemon=True).start()
        self.scanner.root.after(0, scan_decision)
        



# class RealTimeMonitor:
#     def __init__(self, app_ref, paths=None):
#         self.app = app_ref
#         self.observer = Observer()
#         self.paths = paths or []
#         self.event_handler = self.create_event_handler()
#         self.running = False

#     def create_event_handler(self):
#         class Handler(FileSystemEventHandler):
#             def on_created(inner_self, event):
#                 if not event.is_directory:
#                     file_path = os.path.abspath(event.src_path)
#                     # Skip excluded paths
#                     if any(file_path.startswith(ex) for ex in EXCLUDED_PATHS):
#                         return
#                     self.app.log(f"[MONITOR] New file detected: {file_path}", "load")
#                     self.app.scan_file(file_path)
#         return Handler()

#     def start(self):
#         self.running = True
#         for path in self.paths:
#             for root, dirs, _ in os.walk(path):
#                 if any(root.startswith(ex) for ex in EXCLUDED_PATHS):
#                     continue
#                 try:
#                     self.observer.schedule(self.event_handler, root, recursive=True)
#                 except Exception as e:
#                     print(f"[WARNING] Cannot watch {root}: {e}")
#         self.observer.start()

#     def stop(self):
#         self.running = False
#         self.observer.stop()
#         self.observer.join()




# class RealTimeMonitor(FileSystemEventHandler):
#     def __init__(self, gui, watch_paths):
#         self.gui = gui
#         self.watch_paths = watch_paths if isinstance(watch_paths, list) else [watch_paths]
#         self.observer = Observer()
#         self.recent_events = {}
#         self.excluded_folders = ["quarantine", "yara", "VWARbackup","C:\\$Recycle.Bin","C:\\System Volume Information"]

#     def start(self):
#         for path in self.watch_paths:
#             try:
#                 self.observer.schedule(self, path=path, recursive=True)
#                 print(f"[DEBUG] Monitoring started on: {path}")
#             except Exception as e:
#                 print(f"[ERROR] Could not start monitoring on {path}: {e}")
#         self.observer.start()

#     def stop(self):
#         self.observer.stop()
#         self.observer.join()

#     def is_excluded(self, path):
#         return any(folder.lower() in path.lower() for folder in self.excluded_folders)

#     def on_created(self, event):
#         if event.is_directory:
#             return

#         path = event.src_path
#         now = time.time()

#         # Debounce
#         last_time = self.recent_events.get(path, 0)
#         if now - last_time < 5:
#             return
#         self.recent_events[path] = now

#         # Skip excluded folders
#         if self.is_excluded(path):
#             print(f"[DEBUG] Skipping excluded path: {path}")
#             return

#         # Filter file types (optional)
#         # if not path.lower().endswith((".exe", ".dll", ".docx")):
#         #     return

#         print(f"[DEBUG] New file detected: {path}")
#         self.gui.log(f"[INFO] New file created: {path}", "load")
#         self.gui.scan_file(path)


class RealTimeMonitor(FileSystemEventHandler):
    def __init__(self, gui, watch_paths):
        
        self.gui = gui
        self.watch_paths = watch_paths if isinstance(watch_paths, list) else [watch_paths]
        self.observer = Observer()
        self.recent_events = {}
        print()

        # Folders to exclude
        # self.excluded_folders = [
        #     "quarantine", "yara", "VWARbackup",
        #     "C:\\$Recycle.Bin", "C:\\System Volume Information",
        #     "C:\\Windows", "C:\\ProgramData"
        # ]
        
        
        self.excluded_folders = [
            "quarantine", "backup", "yara", "VWARbackup",
            "C:\\$Recycle.Bin", "C:\\System Volume Information",
            "C:\\Windows", "C:\\ProgramData", "AppData\\Local\\Packages", "Cache", "Temp"
        ]

        # Unwanted file types and patterns
        self.excluded_extensions = (
            ".tmp", ".log", ".lock", ".crdownload", ".part", ".ds_store", "thumbs.db"
        )
        self.excluded_prefixes = ("~$",)

    # def start(self):
    #     for path in self.watch_paths:
    #         try:
    #             self.observer.schedule(self, path=path, recursive=True)
    #             print(f"[DEBUG] Monitoring started on: {path}")
    #         except Exception as e:
    #             print(f"[ERROR] Could not start monitoring on {path}: {e}")
    #     self.observer.start()
    
    
    def start(self):
        print("[DEBUG] Watching paths:")
        for path in self.watch_paths:
            print("  ➤", path)
            try:
                self.observer.schedule(self, path=path, recursive=True)
                print(f"[DEBUG] Monitoring started on: {path}")
            except Exception as e:
                print(f"[ERROR] Could not start monitoring on {path}: {e}")
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()

    def is_excluded(self, path):
        return any(folder.lower() in path.lower() for folder in self.excluded_folders)

    def is_excluded_file(self, path):
        filename = os.path.basename(path).lower()
        if filename.endswith(self.excluded_extensions) or filename.startswith(self.excluded_prefixes):
            return True
        try:
            if os.path.exists(path) and os.path.getsize(path) == 0:
                return True
        except Exception as e:
            print(f"[WARNING] Could not check file size: {path} ({e})")
            return True
        return False

    def on_created(self, event):
        if event.is_directory:
            return

        path = event.src_path
        print(f"[DEBUG] File event detected: {path}")  # ✅ always print the path

        now = time.time()
        last_time = self.recent_events.get(path, 0)
        if now - last_time < 5:
            return
        self.recent_events[path] = now

        if self.is_excluded(path):
            # print(f"[DEBUG] Skipping excluded path: {path}")
            return

        if self.is_excluded_file(path):
            # print(f"[DEBUG] Skipping excluded file: {path}")
            return

        print(f"[DEBUG] New file detected and scanned: {path}")
        self.gui.log(f"[INFO] New file created: {path}", "load")
        self.gui.scan_file(path)





# class RealTimeMonitor(FileSystemEventHandler):
#     def __init__(self, gui, watch_paths):
#         self.gui = gui
#         self.watch_paths = watch_paths if isinstance(watch_paths, list) else [watch_paths]
#         self.observer = Observer()
#         self.recent_events = {}

#         # ✅ Folders to exclude (system + app)
#         self.excluded_folders = [
#             "quarantine", "backup", "yara", "VWARbackup",
#             "C:\\$Recycle.Bin", "C:\\System Volume Information",
#             "C:\\Windows", "C:\\ProgramData", "AppData"
#         ]

#         # ✅ File types or patterns to exclude
#         self.excluded_extensions = (
#             ".tmp", ".log", ".lock", ".crdownload", ".part", ".ds_store", "thumbs.db"
#         )
#         self.excluded_prefixes = ("~$",)

#     def start(self):
#         for path in self.watch_paths:
#             try:
#                 self.observer.schedule(self, path=path, recursive=True)
#                 print(f"[DEBUG] Monitoring started on: {path}")
#             except Exception as e:
#                 print(f"[ERROR] Could not start monitoring on {path}: {e}")
#         self.observer.start()

#     def stop(self):
#         self.observer.stop()
#         self.observer.join()

#     def is_excluded(self, path):
#         return any(folder.lower() in path.lower() for folder in self.excluded_folders)

#     def is_excluded_file(self, path):
#         filename = os.path.basename(path).lower()
#         # Skip based on extension or prefix
#         if filename.endswith(self.excluded_extensions) or filename.startswith(self.excluded_prefixes):
#             return True
#         # Skip empty files
#         try:
#             if os.path.exists(path) and os.path.getsize(path) == 0:
#                 return True
#         except Exception as e:
#             print(f"[WARNING] Could not check file size: {path} ({e})")
#             return True
#         return False

#     def on_created(self, event):
#         if event.is_directory:
#             return

#         path = event.src_path
#         now = time.time()

#         # Debounce repeated triggers
#         last_time = self.recent_events.get(path, 0)
#         if now - last_time < 5:
#             return
#         self.recent_events[path] = now

#         if self.is_excluded(path):
#             print(f"[DEBUG] Skipping excluded folder path: {path}")
#             return

#         if self.is_excluded_file(path):
#             print(f"[DEBUG] Skipping excluded file type or empty file: {path}")
#             return

#         print(f"[DEBUG] New file detected: {path}")
#         self.gui.log(f"[INFO] New file created: {path}", "load")
#         self.gui.scan_file(path)


# class RealTimeMonitor:
#     def __init__(self, scanner, watch_path):
#         self.scanner = scanner  # VWAR scanner instance
#         self.watch_path = watch_path  # Directory to monitor
#         self.observer = Observer()

#     # def start(self):
#     #     """Start monitoring for new files."""
#     #     event_handler = FileMonitorHandler(self.scanner)
#     #     self.observer.schedule(event_handler, self.watch_path, recursive=True)
#     #     monitoring_thread = threading.Thread(target=self.observer.start, daemon=True)
#     #     monitoring_thread.start()
    
#     def start(self):
#         event_handler = FileMonitorHandler(self.scanner)
#         self.observer.schedule(event_handler, self.watch_path, recursive=True)
#         self.observer.start()  # Start directly — NOT in a new thread

#     def stop(self):
#         """Stop monitoring for new files."""
#         self.observer.stop()
#         self.observer.join()


# 



if __name__ == "__main__":
    if not is_admin() and not os.environ.get("VWAR_ELEVATED"):
        relaunch_as_admin()
        sys.exit()

    print("Launching VWAR Scanner GUI...")
    try:
        root = Tk()
        print("Tk window created")

        app = VWARScannerGUI(root)
        print("GUI object created")  # ✅ You must see this now
        root.resizable(False, False)
        root.deiconify()  # 🔓 Ensure root is not hidden
        root.mainloop()
    except Exception as e:
        print(f"[CRITICAL ERROR] GUI launch failed: {e}")