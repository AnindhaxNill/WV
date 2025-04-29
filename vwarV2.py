import threading
import yara
import os
import shutil
from tkinter import Tk, Frame, Canvas, Label, Text, Button, filedialog, messagebox,Scrollbar,StringVar,Toplevel, Listbox,ttk
from tkinter.ttk import Progressbar
import requests
import time
import base64
from datetime import datetime
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import threading


import json
from plyer import notification



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
        self.root = root
        self.root.title("VWAR Scanner")
        # self.watch_path = "C:/"  # Change this to the directory you want to monitor
        self.watch_path="D:\soft"
        self.monitor = RealTimeMonitor(self, self.watch_path)
        self.monitor.start()  # Start real-time monitoring
        self.rule_folder = os.path.join(os.getcwd(), "yara")
        self.quarantine_folder = os.path.join(os.getcwd(), "quarantine")
        self.backup_folder = os.path.join(os.getcwd(), "backup")
        self.target_path = None
        self.rules = None
        self.stop_scan = False
        self.quarantined_files = {}
        
        
        
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

        # Show home page initially
        self.show_page("home")
        
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

                rules_str = ", ".join(matched_rules) if matched_rules else "Unknown"

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
        
        self.home_scan_progress = ttk.Progressbar(
            home_page,
            mode='indeterminate',
            length=200
                    )
        self.home_scan_progress.place(x=20, y=470)
        
        
        

    def create_scanning_page(self):
        
        

        self.fetch_and_generate_yara_rules()
        self.root.after(100, self.load_rules)
        
        
        """Create the Scanning Page with scan controls."""
        scanning_page = Frame(self.root, bg="#009AA5")
        self.pages["scanning"] = scanning_page
        


        Button(scanning_page, text="Back", command=lambda: self.show_page("home"), bg="gray", fg="white",
               font=("Inter", 12)).place(x=10, y=10, width=80, height=30)

        Button(scanning_page, text="Select Target File", command=self.select_file).place(x=302.0, y=139.0, width=125.0, height=40.0)
        Button(scanning_page, text="Select Target Folder", command=self.select_folder).place(x=302.0, y=195.0, width=125.0, height=40.0)
        Button(scanning_page, text="Scan", command=self.start_scan_thread, bg="green", fg="white").place(x=485, y=150, width=73, height=25)
        Button(scanning_page, text="Stop", command=self.stop_scanning, bg="red", fg="white").place(x=485, y=195, width=73, height=25)
        
        
        Button(scanning_page, text="Show Quarantined Files", command=lambda: self.show_page("auto_scanning"), bg="purple", fg="white",
       font=("Inter", 12)).place(x=700, y=195, width=200, height=40)

        
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
                    # Default to 'uncategorized' category if not found
                    # category = rule.get("categoryname", "uncategorized").replace(" ", "_").lower()
                    # conditions = rule.get("conditions", [])
                    category = rule.get("categoryname", "uncategorized")  # Default to 'uncategorized' if no category
                    rule_name = rule.get("rulename", "unknown_rule")  # Use 'unknown_rule' if no name is provided
                    rule_content = rule.get("conditions", [{}])[0].get("string", "")
                    category_dir = os.path.join(self.rule_folder, category)
                    os.makedirs(category_dir, exist_ok=True)  # Create category directory if it doesn't exist

                    file_path = os.path.join(category_dir, f"{rule_name}.yar")

                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(rule_content)
                    
                    # print(f"Saved: {file_path}")

                    # if category not in category:
                    #     rule_files[category] = []

                    # for condition in rule_content:
                    #     rule_string = condition.get("string", "")
                    #     if rule_string:
                    #         # Removing unnecessary quote marks around rule string
                    #         rule_files[category].append(rule_string.strip('""'))

                # Now save the categorized rules into individual .yar files
                # for category, rules in rule_files.items():
                #     # Create the category folder if it doesn't exist
                #     category_folder = os.path.join(self.rule_folder, category)
                #     os.makedirs(category_folder, exist_ok=True)

                #     output_file = os.path.join(category_folder, f"{category}.yar")
                #     with open(output_file, "w", encoding="utf-8") as file:
                #         for rule in rules:
                #             file.write(rule + "\n\n")

                    
                # self.log(f"[INFO] Rules for '{category}' saved in {output_file}.", "load")
                self.log("[INFO] YARA rules categorized and saved successfully.", "load")

            except requests.RequestException as e:
                self.log(f"[ERROR] Failed to fetch YARA rules: {e}", "load")
            except Exception as e:
                self.log(f"[ERROR] An error occurred: {e}", "load")


    # def load_rules(self):
    #     try:
    #         rule_files = [
    #             os.path.join(self.rule_folder, file)
    #             for file in os.listdir(self.rule_folder)
    #             if file.endswith(".yar")
    #         ]
    #         if not rule_files:
    #             raise FileNotFoundError("No .yar files found in the 'yara' folder.")
            
    #         valid_rule_files = {}
    #         for file_path in rule_files:
    #             try:
    #                 yara.compile(filepath=file_path)
    #                 valid_rule_files[os.path.basename(file_path)] = file_path
              
    #             except (yara.SyntaxError, yara.CompileError) as e:
    #                 print(f"[ERROR] Failed to compile YARA file {file_path}: {e}")

    #         if valid_rule_files:
    #             self.rules = yara.compile(filepaths=valid_rule_files)
    #             self.log(f"[INFO] Successfully compiled {len(valid_rule_files)} YARA rule files.", "load")
    #         else:
    #             self.log("[ERROR] No valid YARA rules to compile.", "load")
    #     except Exception as e:
    #         self.log(f"[ERROR] Failed to load YARA rules: {e}", "load")
    

    # def load_rules(self):
    #     try:
    #         # Initialize a dictionary to store valid rule files
    #         valid_rule_files = {}

    #         # Loop through each subdirectory (category) in the 'yara' directory
    #         for root, dirs, files in os.walk(self.rule_folder):
    #             for file in files:
    #                 if file.endswith(".yar"):
    #                     file_path = os.path.join(root, file)
                        
    #                     # Try to compile each YARA rule file
    #                     try:
    #                         yara.compile(filepath=file_path)
    #                         valid_rule_files[os.path.basename(file_path)] = file_path
    #                         print(f"[INFO] Successfully compiled {file_path}")
    #                     except (yara.SyntaxError, yara.CompileError) as e:
    #                         print(f"[ERROR] Failed to compile YARA file {file_path}: {e}")

    #         if valid_rule_files:
    #             # If there are valid rule files, compile them all together
    #             self.rules = yara.compile(filepaths=valid_rule_files)
    #             self.log(f"[INFO] Successfully compiled {len(valid_rule_files)} YARA rule files.", "load")
    #         else:
    #             self.log("[ERROR] No valid YARA rules to compile.", "load")

    #     except Exception as e:
    #         self.log(f"[ERROR] Failed to load YARA rules: {e}", "load")
    
    
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
    #             print(matches)
    #             yara_file = os.path.splitext(os.path.basename(matches[0].namespace))[0]  # Remove .yar extension

    #             self.log(f"[MATCH] {file_path}\nRule: {matches[0].rule}\nMalware Type: {yara_file}\n\n", "matched")

    #             self.quarantine_file(file_path)  # Move matched file to quarantine
      
    #     except (yara.SyntaxError, yara.CompileError) as e:
    #         self.log(f"[ERROR] Failed to scan file '{file_path}': {e}", "tested")
        
        
        
        
        
    def scan_file(self, file_path):
        if self.stop_scan:
            return
        try:
            matches = self.rules.match(file_path, timeout=60)
            self.log(f"{file_path} \n", "tested")
            
            if matches:
                # print(matches)
                # Get the namespace (YARA file name without extension)
                yara_file = os.path.splitext(os.path.basename(matches[0].namespace))[0]  # Remove .yar extension

                # Get the folder name where the YARA rule is located
                rule_folder = os.path.dirname(matches[0].namespace)
                folder_name = os.path.basename(rule_folder)

                # print(f"Match found in rule: {matches[0].rule}")
                # print(f"YARA file located in folder: {folder_name}")
                
                # Log the match information with the folder name
                self.log(f"[MATCH] {file_path}\nRule: {matches[0].rule}\nMalware Type: {yara_file}\nRule Folder: {folder_name}\n\n", "matched")

                # Quarantine the file
                self.quarantine_file(file_path,yara_file) # Move matched file to quarantine
                self.notify_threat_detected(file_path, yara_file)

        except Exception as e:
            self.log(f"[ERROR] Failed to scan file '{file_path}': {e}", "tested")

    # def quarantine_file(self, file_path):
    #     """Move matched files to a quarantine folder and encode metadata in the filename."""
    #     if not os.path.exists(self.quarantine_folder):
    #         os.makedirs(self.quarantine_folder)

    #     file_name = os.path.basename(file_path)
    #     file_p = os.path.dirname(file_path)
    #     timestamp = time.strftime("%Y%m%d%H%M%S")  # Format: YYYYMMDDHHMMSS
    #     MAX_ENCODED_LENGTH = 100  # Limit the encoded path length
    #     # Encode original file path in base64 to avoid special character issues
    #     encoded_path = base64.urlsafe_b64encode(file_p.encode()).decode()
    #     encoded_path = encoded_path[:MAX_ENCODED_LENGTH]  # Trim long paths
 
    #     # New filename format: original_name__timestamp__encoded_path.quarantined
    #     quarantined_name = f"{file_name}__{timestamp}__{encoded_path}.quarantined"
    #     quarantined_path = os.path.join(self.quarantine_folder, quarantined_name)

    #     try:
    #         shutil.move(file_path, quarantined_path)
    #         self.log(f"[QUARANTINED] {file_path} → {quarantined_path} at {timestamp}", "matched")
    #     except Exception as e:
    #         self.log(f"[ERROR] Failed to quarantine {file_path}: {e}", "matched")           
    
    
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



################################&&&&&&&&&&&&&&&&&&&&&&&&&

    # def create_auto_scanning_page(self):
    #     """Create the Auto Scanning Page for real-time file monitoring."""
    #     auto_scanning_page = Frame(self.root, bg="#009AA5")
    #     self.pages["auto_scanning"] = auto_scanning_page

    #     # Back Button
    #     Button(auto_scanning_page, text="Back", command=lambda: self.show_page("home"), bg="gray", fg="white",
    #         font=("Inter", 12)).place(x=10, y=10, width=80, height=30)

    #     # Title Label
    #     Label(auto_scanning_page, text="Quarantined Files", font=("Inter", 16, "bold"), bg="#009AA5", fg="white").place(x=20, y=60)


 
    #     # Quarantine Listbox
    #     self.quarantine_listbox = Listbox(
    #         auto_scanning_page,
    #         font=("Inter", 11),
    #         xscrollcommand=lambda *args: x_scrollbar.set(*args),
    #         yscrollcommand=lambda *args: y_scrollbar.set(*args),
    #     )

    #     self.quarantine_listbox.place(x=20, y=100, width=550, height=300)

    #     # Vertical Scrollbar
    #     y_scrollbar = Scrollbar(auto_scanning_page, orient="vertical", command=self.quarantine_listbox.yview)
    #     y_scrollbar.place(x=570, y=100, height=300)

    #     # Horizontal Scrollbar
    #     x_scrollbar = Scrollbar(auto_scanning_page, orient="horizontal", command=self.quarantine_listbox.xview)
    #     x_scrollbar.place(x=20, y=400, width=550)

    #     # Final scrollbar setup
    #     self.quarantine_listbox.config(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)

    #     # Auto Scan Buttons
    #     self.auto_scan_button_text = StringVar(value="Start Auto Scanning")
    #     self.monitoring_active = False
        
    #     # Detail Panel (Text box)
    #     self.detail_text = Text(auto_scanning_page, font=("Inter", 11), wrap="word", state="disabled", bg="white", fg="black")
    #     self.detail_text.place(x=600, y=100, width=400, height=300)
        

    #     def start_auto_scanning():
    #         if not self.monitoring_active:
    #             self.monitor = RealTimeMonitor(self, self.watch_path)
    #             self.monitor.start()
    #             self.monitoring_active = True
    #             self.auto_scan_button_text.set("Stop Auto Scanning")
    #             self.log("[INFO] Auto scanning started.", "load")

    #     def stop_auto_scanning():
    #         if self.monitoring_active and hasattr(self, 'monitor'):
    #             self.monitor.stop()
    #             self.monitoring_active = False
    #             self.auto_scan_button_text.set("Start Auto Scanning")
    #             self.log("[INFO] Auto scanning stopped.", "load")

    #     def toggle_auto_scanning():
    #         if self.monitoring_active:
    #             stop_auto_scanning()
    #         else:
    #             start_auto_scanning()

    #     # Start/Stop Button
    #     Button(auto_scanning_page, textvariable=self.auto_scan_button_text,
    #         command=toggle_auto_scanning, bg="#004953", fg="white",
    #         font=("Inter", 12, "bold")).place(x=20, y=420, width=200, height=40)

    #     # Delete Selected Quarantined File(s)
    #     # def delete_selected_quarantined_files():
    #     #     selected_indices = self.quarantine_listbox.curselection()
    #     #     # print(selected_indices)
    #     #     if not selected_indices:
    #     #         return  # Do nothing if nothing is selected
    #     #     for index in selected_indices[::-1]:  # Reverse to avoid index shifting
    #     #         file_name = self.quarantine_listbox.get(index)
    #     #         # print(file_name)
    #     #         def extract_filename(line):
    #     #             try:
    #     #                 parts = line.split("|")
    #     #                 if len(parts) > 2:
    #     #                     return parts[1].strip()
    #     #             except Exception as e:
    #     #                 print(f"Error parsing line: {e}")
    #     #             return ""
    #     #         name1 = extract_filename(file_name)
    #     #         # print(name1)
    #     #         # print(quarantine_folder)
    #     #         file_path = os.path.join(self.quarantine_folder, name1)
    #     #         # print(file_path)
    #     #         if os.path.exists(file_path):
    #     #             try:
    #     #                 os.remove(file_path)
    #     #                 self.quarantine_listbox.delete(index)
    #     #                 self.log(f"[INFO] Deleted quarantined file: {file_name}", "load")
    #     #             except Exception as e:
    #     #                 self.log(f"[ERROR] Failed to delete {file_name}: {e}", "load")
        
    #     def delete_selected_quarantined_files():
    #         selected_indices = self.quarantine_listbox.curselection()
    #         if not selected_indices:
    #             return  # Do nothing if nothing is selected

    #         for index in selected_indices[::-1]:  # Reverse to avoid index shifting
    #             display_text = self.quarantine_listbox.get(index)

    #             # Extract actual filename from display text (e.g., "1. File: filename...")
    #             try:
    #                 line_start = display_text.split("File: ")[1].split("\n")[0].strip()
    #             except IndexError:
    #                 self.log(f"[ERROR] Could not parse filename from: {display_text}", "load")
    #                 continue

    #             # Search the quarantine folder for the matching file
    #             matched_file = None
    #             for file in os.listdir(self.quarantine_folder):
    #                 if file.startswith(line_start) and file.endswith(".quarantined"):
    #                     matched_file = file
    #                     break

    #             if matched_file:
    #                 quarantined_path = os.path.join(self.quarantine_folder, matched_file)
    #                 meta_path = quarantined_path + ".meta"

    #                 try:
    #                     if os.path.exists(quarantined_path):
    #                         os.remove(quarantined_path)
    #                     if os.path.exists(meta_path):
    #                         os.remove(meta_path)

    #                     self.quarantine_listbox.delete(index)
    #                     self.log(f"[INFO] Deleted quarantined file and metadata: {matched_file}", "load")

    #                 except Exception as e:
    #                     self.log(f"[ERROR] Failed to delete {matched_file} or metadata: {e}", "load")
    #             else:
    #                 self.log(f"[WARN] Could not locate quarantined file for: {line_start}", "load")

    #     Button(auto_scanning_page, text="Delete Selected", command=delete_selected_quarantined_files,
    #         bg="#B22222", fg="white", font=("Inter", 12)).place(x=240, y=420, width=160, height=40)

    #     # Refresh Quarantine List
        
    #     # def refresh_quarantine_list():
            
    #     #     # a=self.update_quarantine_listbox()
    #     #     # print(a)
    #     #     self.quarantine_listbox.delete(0, "end")
    #     #     if os.path.exists(self.quarantine_folder):
    #     #         files = os.listdir(self.quarantine_folder)
    #     #         for file in files:
    #     #             self.quarantine_listbox.insert("end", file)

    #     # Button(auto_scanning_page, text="Refresh", command=refresh_quarantine_list,
    #     #     bg="#006666", fg="white", font=("Inter", 12)).place(x=420, y=420, width=100, height=40)

    #     # # Initial load
    #     # refresh_quarantine_list()
        
        
    #     def refresh_quarantine_list():
    #         self.quarantine_listbox.delete(0, "end")
    #         index = 1

    #         for file_name in os.listdir(self.quarantine_folder):
    #             if not file_name.endswith(".quarantined"):
    #                 continue

    #             quarantined_path = os.path.join(self.quarantine_folder, file_name)
    #             meta_path = quarantined_path + ".meta"

    #             if not os.path.exists(meta_path):
    #                 continue  # Skip if no metadata

    #             try:
    #                 with open(meta_path, "r", encoding="utf-8") as f:
    #                     metadata = json.load(f)

    #                 # Extract metadata fields
    #                 original_path = metadata.get("original_path", "Unknown")
    #                 timestamp = metadata.get("timestamp", "")
    #                 matched_rules = metadata.get("matched_rules", [])

    #                 # Format timestamp
    #                 formatted_time = "Unknown"
    #                 if len(timestamp) == 14:
    #                     formatted_time = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]} {timestamp[8:10]}:{timestamp[10:12]}:{timestamp[12:]}"
                    
    #                 # Format rule list
    #                 rules_str = ", ".join(matched_rules) if matched_rules else "Unknown"

    #                 # Extract display-safe filename
    #                 fname = file_name.split("__")[0]

    #                 # Compose formatted string
    #                 display_text = (
    #                     f"{index}. File: {fname}\n"
    #                     f"   → Quarantined: {formatted_time}\n"
    #                     f"   → From: {original_path}\n"
    #                     f"   → Matched Rules: {rules_str}"
    #                 )

    #                 self.quarantine_listbox.insert("end", display_text)
    #                 index += 1

    #             except Exception as e:
    #                 self.log(f"[ERROR] Failed to read metadata for {file_name}: {e}", "load")

    #     Button(auto_scanning_page, text="Refresh", command=refresh_quarantine_list,
    #         bg="#006666", fg="white", font=("Inter", 12)).place(x=420, y=420, width=100, height=40)

    #     # Initial load
    #     refresh_quarantine_list()
    #     self.update_quarantine_listbox()

#####################%%%%%%%%%%%%%%%%%%%%%%%%%

    def create_auto_scanning_page(self):
        """Create the Auto Scanning Page for real-time file monitoring."""
        auto_scanning_page = Frame(self.root, bg="#009AA5")
        self.pages["auto_scanning"] = auto_scanning_page

        Button(auto_scanning_page, text="Back", command=lambda: self.show_page("home"),
            bg="gray", fg="white", font=("Inter", 12)).place(x=10, y=10, width=80, height=30)

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
        
        
        self.auto_scan_progress = ttk.Progressbar(
            auto_scanning_page,
            mode='indeterminate',
            length=200
        )
        self.auto_scan_progress.place(x=20, y=470)

    
        
        
        def start_auto_scanning():
            if not self.monitoring_active:
                self.monitor = RealTimeMonitor(self, self.watch_path)
                self.monitor.start()
                self.monitoring_active = True
                self.auto_scan_button_text.set("Stop Auto Scanning")
                self.auto_scan_progress.start(10)  # Start the animation with a 10ms interval
                self.home_scan_progress.start(10)  # Start home page animation
                self.log("[INFO] Auto scanning started.", "load")

        def stop_auto_scanning():
            if self.monitoring_active and hasattr(self, 'monitor'):
                self.monitor.stop()
                self.monitoring_active = False
                self.auto_scan_button_text.set("Start Auto Scanning")
                self.auto_scan_progress.stop()  # Stop the animation
                self.home_scan_progress.stop()  # Stop home page animation
                self.log("[INFO] Auto scanning stopped.", "load")

        def toggle_auto_scanning():
            if self.monitoring_active:
                stop_auto_scanning()
            else:
                start_auto_scanning()

        Button(auto_scanning_page, textvariable=self.auto_scan_button_text,
            command=toggle_auto_scanning, bg="#004953", fg="white",
            font=("Inter", 12, "bold")).place(x=20, y=420, width=200, height=40)

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
                        self.log(f"[INFO] Deleted quarantined file and metadata: {matched_file}", "load")
                    except Exception as e:
                        self.log(f"[ERROR] Failed to delete {matched_file} or metadata: {e}", "load")

        Button(auto_scanning_page, text="Delete Selected", command=delete_selected_quarantined_files,
            bg="#B22222", fg="white", font=("Inter", 12)).place(x=240, y=420, width=160, height=40)

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

                    rules_str = ", ".join(matched_rules) if matched_rules else "Unknown"
                    fname = file_name.split("__")[0]

                    display_text = (
                        f"{index}. File: {fname}\n"
                        f"   → Quarantined: {formatted_time}\n"
                        f"   → From: {original_path}\n"
                        f"   → Matched Rules: {rules_str}"
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
                    rules_str = "\n".join(matched_rules) if matched_rules else "None"

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
            bg="#006666", fg="white", font=("Inter", 12)).place(x=420, y=420, width=100, height=40)

        # Initial load
        self.update_quarantine_listbox()
        refresh_quarantine_list()
        






    # def create_backup_page(self):
    #     """Create the Backup Page for file backup and restoration."""
    #     backup_page = Frame(self.root, bg="#009AA5")
    #     self.pages["backup"] = backup_page

    #     Button(backup_page, text="Back", command=lambda: self.show_page("home"), bg="gray", fg="white",
    #            font=("Inter", 12)).place(x=10, y=10, width=80, height=30)

    #     Button(backup_page, text="Select File to Backup", command=self.select_backup_file).place(x=302, y=139, width=150, height=40)
    #     Button(backup_page, text="Restore from Backup", command=self.restore_backup).place(x=302, y=195, width=150, height=40)




    # def select_backup_file(self):
    #     """Allow user to select a file to back up and choose where to save it."""
    #     # Step 1: Select file to back up
    #     source_path = filedialog.askopenfilename(
    #         title="Select File to Backup",
    #         filetypes=(("All files", "*.*"),)
    #     )
    #     if not source_path:
    #         return  # User cancelled the operation

    #     # Step 2: Select destination directory for backup
    #     destination_root = filedialog.askdirectory(
    #         title="Select Destination Folder for Backup"
    #     )
    #     if not destination_root:
    #         return  # User cancelled the operation

    #     # Step 3: Determine backup folder path
    #     if os.path.basename(destination_root) == "VWARbackup":
    #         backup_folder_path = destination_root
    #     else:
    #         backup_folder_path = os.path.join(destination_root, "VWARbackup")
    #         if not os.path.exists(backup_folder_path):
    #             os.makedirs(backup_folder_path)

    #     # Step 4: Create date-based folder inside backup folder
    #     today = datetime.now().strftime("%Y-%m-%d")
    #     date_folder_path = os.path.join(backup_folder_path, today)
    #     os.makedirs(date_folder_path, exist_ok=True)

    #     # Step 5: Copy the selected file into the date-based folder
    #     try:
    #         filename = os.path.basename(source_path)
    #         backup_file_path = os.path.join(date_folder_path, filename + ".backup")
    #         shutil.copy2(source_path, backup_file_path)
    #         self.log(f"[BACKUP] {source_path} -> {backup_file_path}", "load")
    #         messagebox.showinfo("Backup", f"File backed up successfully:\n{backup_file_path}")
    #     except Exception as e:
    #         self.log(f"[ERROR] Failed to backup {source_path}: {e}", "load")
    #         messagebox.showerror("Backup Error", f"Failed to backup file:\n{e}")



    # def select_backup_file(self):
    #     """Allow user to select a file or directory to back up and choose where to save it."""
    #     # Step 1: Select file or directory to back up
    #     source_path = filedialog.askopenfilename(
    #         title="Select File to Backup",
    #         filetypes=(("All files", "*.*"),)
    #     )
    #     if not source_path:
    #         return  # User cancelled the operation

    #     # Step 2: Select destination directory for backup
    #     destination_root = filedialog.askdirectory(
    #         title="Select Destination Folder for Backup"
    #     )
    #     if not destination_root:
    #         return  # User cancelled the operation

    #     # Step 3: Determine backup folder name
    #     backup_folder_name = "VWARbackup"
    #     backup_folder_path = os.path.join(destination_root, backup_folder_name)

    #     # Step 4: Create backup folder if it doesn't exist
    #     if not os.path.exists(backup_folder_path):
    #         os.makedirs(backup_folder_path)

    #     # Step 5: Create date-based folder inside backup folder
    #     today = datetime.now().strftime("%Y-%m-%d")
    #     date_folder_path = os.path.join(backup_folder_path, today)
    #     os.makedirs(date_folder_path, exist_ok=True)

    #     # Step 6: Copy the selected file into the date-based folder
    #     try:
    #         filename = os.path.basename(source_path)
    #         backup_file_path = os.path.join(date_folder_path, filename + ".backup")
    #         shutil.copy2(source_path, backup_file_path)
    #         self.log(f"[BACKUP] {source_path} -> {backup_file_path}", "load")
    #         messagebox.showinfo("Backup", f"File backed up successfully:\n{backup_file_path}")
    #     except Exception as e:
    #         self.log(f"[ERROR] Failed to backup {source_path}: {e}", "load")
    #         messagebox.showerror("Backup Error", f"Failed to backup file:\n{e}")

    # def select_backup_file(self):
    #     """Allow user to select a file to back up in a date-based directory."""
    #     file_path = filedialog.askopenfilename(title="Select File to Backup", filetypes=(("All files", "*.*"),))
    #     if file_path:
    #         today = datetime.now().strftime("%Y-%m-%d")  # Get current date
    #         daily_backup_folder = os.path.join(self.backup_folder, today)  # Backup folder for today

    #         os.makedirs(daily_backup_folder, exist_ok=True)  # Ensure folder exists

    #         backup_path = os.path.join(daily_backup_folder, os.path.basename(file_path) + ".backup")
            
    #         try:
    #             shutil.copy(file_path, backup_path)  # Copy file to daily folder
    #             self.log(f"[BACKUP] {file_path} -> {backup_path}", "load")
    #         except Exception as e:
    #             self.log(f"[ERROR] Failed to backup {file_path}: {e}", "load")
       
       


         
                
    # def restore_backup(self):
    #     """Restore a backup file from the daily backup folder."""
    #     today = datetime.now().strftime("%Y-%m-%d")  # Current date
    #     backup_folders = [f for f in os.listdir(self.backup_folder) if os.path.isdir(os.path.join(self.backup_folder, f))]

    #     if not backup_folders:
    #         messagebox.showinfo("Restore Backup", "No backups found.")
    #         return

    #     # Let user choose a date folder
    #     selected_date = filedialog.askdirectory(initialdir=self.backup_folder, title="Select Backup Date Folder")
    #     if not selected_date or not os.path.exists(selected_date):
    #         return

    #     # Let user select a file from that date's backup folder
    #     file_path = filedialog.askopenfilename(initialdir=selected_date, title="Select Backup to Restore",
    #                                         filetypes=(("Backup files", "*.backup"),))
    #     if file_path:
    #         original_name = os.path.basename(file_path).replace(".backup", "")
    #         restore_path = filedialog.asksaveasfilename(initialfile=original_name, title="Save Restored File")
    #         if restore_path:
    #             try:
    #                 shutil.copy(file_path, restore_path)
    #                 self.log(f"[RESTORED] {file_path} -> {restore_path}", "load")
    #             except Exception as e:
    #                 self.log(f"[ERROR] Failed to restore {file_path}: {e}", "load")



















    def create_backup_page(self):
            """Create the Backup Page with Menu, Manual Backup, Restore, Auto Backup."""
            backup_page = Frame(self.root, bg="#009AA5")
            self.pages["backup"] = backup_page

            Button(backup_page, text="Back", command=lambda: self.show_page("home"),
                bg="gray", fg="white", font=("Inter", 12)).place(x=10, y=10, width=80, height=30)

            # Create internal frames
            self.menu_frame = Frame(backup_page, bg="#009AA5")
            self.menu_frame.place(x=0, y=50, relwidth=1, relheight=1)

            self.manual_backup_frame = Frame(backup_page, bg="#009AA5")
            self.manual_backup_frame.place(x=0, y=50, relwidth=1, relheight=1)
            self.manual_backup_frame.place_forget()  # Hide manual backup at start

            # === Menu Frame contents ===
            Button(self.menu_frame, text="Manual Backup", command=self.show_manual_backup,
                bg="#004953", fg="white", font=("Inter", 14, "bold")).place(relx=0.3, rely=0.2, width=200, height=60)

            Button(self.menu_frame, text="Restore Files", command=self.show_restore_backup,
                bg="#004953", fg="white", font=("Inter", 14, "bold")).place(relx=0.3, rely=0.4, width=200, height=60)

            Button(self.menu_frame, text="Auto Backup", command=self.auto_backup_placeholder,
                bg="#004953", fg="white", font=("Inter", 14, "bold")).place(relx=0.3, rely=0.6, width=200, height=60)

            # === Manual Backup Frame contents ===
            # ===  backup Button ===
            Button(self.manual_backup_frame, text="Back", command=self.show_menu_frame,
                bg="gray", fg="white", font=("Inter", 12)).place(x=10, y=10, width=80, height=30)

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
            
            Button(self.manual_backup_frame, text="Select Files", command=self.select_backup_files,
                bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=110, width=180, height=40)

            Button(self.manual_backup_frame, text="Select Destination", command=self.select_backup_destination,
                bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=170, width=180, height=40)

            self.start_backup_button = Button(self.manual_backup_frame, text="Start Backup", command=self.perform_backup,
                                            state="disabled", bg="#006666", fg="white", font=("Inter", 12, "bold"))
            self.start_backup_button.place(x=600, y=230, width=180, height=40)

            self.selected_files = []
            self.selected_backup_folder = ""
            # ===  backup Button ===
            #  === Manual Backup Frame contents ===
            
            
            
            self.restore_backup_frame = Frame(backup_page, bg="#009AA5")
            self.restore_backup_frame.place(x=0, y=50, relwidth=1, relheight=1)
            self.restore_backup_frame.place_forget()  # Initially hidden
            
            
            # === Restore Backup Frame contents ===
            Button(self.restore_backup_frame, text="Back", command=self.show_menu_frame,
                bg="gray", fg="white", font=("Inter", 12)).place(x=10, y=10, width=80, height=30)

            # Step 1: Select VWARbackup Folder
            Label(self.restore_backup_frame, text="Step 1: Select VWARbackup Folder", font=("Inter", 14, "bold"),
                bg="#009AA5", fg="white").place(x=20, y=30)

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

            Button(self.restore_backup_frame, text="Select Folder", command=self.select_vwarbackup_folder,
                bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=60, width=180, height=40)

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

            Button(self.restore_backup_frame, text="Select Backup File", command=self.select_restore_file,
                bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=160, width=180, height=40)

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

            Button(self.restore_backup_frame, text="Select Location", command=self.select_restore_location,
                bg="#004953", fg="white", font=("Inter", 12, "bold")).place(x=600, y=250, width=180, height=40)

            # Step 4: Start Restore
            self.start_restore_button = Button(self.restore_backup_frame, text="Start Restore", command=self.perform_restore,
                state="disabled", bg="#006666", fg="white", font=("Inter", 12, "bold"))
            self.start_restore_button.place(x=600, y=320, width=180, height=40)
            
                
            self.selected_vwar_folder = ""
            self.selected_restore_file = ""
            self.selected_restore_folder = ""
            
                        
            
    # === Frame switchers ===

    def show_manual_backup(self):
        """Show manual backup frame."""
        self.menu_frame.place_forget()
        self.manual_backup_frame.place(x=0, y=50, relwidth=1, relheight=1)

    def show_menu_frame(self):
        """Show the main menu frame."""
        self.manual_backup_frame.place_forget()
        self.menu_frame.place(x=0, y=50, relwidth=1, relheight=1)
        
        
    def show_restore_backup(self):
        self.menu_frame.place_forget()
        self.restore_backup_frame.place(x=0, y=50, relwidth=1, relheight=1)

    def auto_backup_placeholder(self):
        """Placeholder function for Auto Backup button."""
        messagebox.showinfo("Coming Soon", "Auto Backup is not available yet!")
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




class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, scanner):
        self.scanner = scanner  # Reference to the VWAR scanner instance

    def on_created(self, event):
        """Trigger when a new file is created in the monitored directory."""
        if not event.is_directory:  # Ignore directories
            file_path = event.src_path

            # Ask user if they want to scan the new file
            self.prompt_scan(file_path)

    def prompt_scan(self, file_path):
        """Show a pop-up asking if the user wants to scan the detected file."""
        def scan_decision():
            # messagebox.askyesno("New File Detected", f"Scan new file?\n{file_path}")
            self.scanner.scan_file(file_path)  # Use VWAR's scanning function
        
        # Run the prompt in the main GUI thread
        self.scanner.root.after(0, scan_decision)

class RealTimeMonitor:
    def __init__(self, scanner, watch_path):
        self.scanner = scanner  # VWAR scanner instance
        self.watch_path = watch_path  # Directory to monitor
        self.observer = Observer()

    def start(self):
        """Start monitoring for new files."""
        event_handler = FileMonitorHandler(self.scanner)
        self.observer.schedule(event_handler, self.watch_path, recursive=True)
        monitoring_thread = threading.Thread(target=self.observer.start, daemon=True)
        monitoring_thread.start()

    def stop(self):
        """Stop monitoring for new files."""
        self.observer.stop()
        self.observer.join()


if __name__ == "__main__":
    root = Tk()
    app = VWARScannerGUI(root)
    root.resizable(False, False)
    root.mainloop()
