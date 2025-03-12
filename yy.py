import threading
import yara
import os
import shutil
from tkinter import Tk, Canvas, Label, Text, Button, filedialog, messagebox
from tkinter.ttk import Progressbar
import requests


class VWARScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VWAR Scanner")
        self.rule_folder = os.path.join(os.getcwd(), "yara")
        self.backup_folder = os.path.join(os.getcwd(), "backup")
        self.quarantine_folder = os.path.join(os.getcwd(), "quarantine")
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

        # Buttons
        Button(root, text="Select Target File", command=self.select_file).place(x=302.0, y=139.0, width=125.0, height=40.0)
        Button(root, text="Select Target Folder", command=self.select_folder).place(x=302.0, y=195.0, width=125.0, height=40.0)
        Button(root, text="Select File to Backup", command=self.select_backup_file).place(x=616.0, y=139.0, width=125.0, height=40.0)
        Button(root, text="Restore from Backup", command=self.restore_backup).place(x=616.0, y=195.0, width=125.0, height=40.0)
        Button(root, text="Scan", command=self.start_scan_thread).place(x=485.0, y=150.0, width=73.0, height=25.0)
        Button(root, text="Stop", command=self.stop_scanning).place(x=485.0, y=195.0, width=73.0, height=25.0)
       

        self.progress_label = Label(root, text="PROGRESS : 0%", bg="#12e012", fg="#000000", font=("Inter", 12 * -1))
        self.progress_label.place(x=476.0, y=311.0)

        self.progress = Progressbar(root, orient="horizontal", length=350, mode="determinate")
        self.progress.place(x=354, y=350)

        # Matched and Tested Files Sections
        canvas.create_rectangle(0.0, 432.0, 485.0, 486.0, fill="#AE0505", outline="")
        canvas.create_text(164.0, 447.0, anchor="nw", text="MATCHED FILES", fill="#FFFFFF", font=("Inter", 20 * -1))
        self.matched_text = Text(root, bg="#D9D9D9", fg="#000000", wrap="word")
        self.matched_text.place(x=0.0, y=488.0, width=485.0, height=232.0)

        canvas.create_rectangle(557.0, 432.0, 1042.0, 486.0, fill="#001183", outline="")
        canvas.create_text(731.0, 447.0, anchor="nw", text="TESTED FILES", fill="#FFFFFF", font=("Inter", 20 * -1))
        self.tested_text = Text(root, bg="#D9D9D9", fg="#000000", wrap="word")
        self.tested_text.place(x=557.0, y=488.0, width=485.0, height=232.0)

        # Ensure necessary folders exist
        self.create_folders()
        self.fetch_and_generate_yara_rules()
        self.root.after(100, self.load_rules)

    def create_folders(self):
        """Ensure required folders exist."""
        os.makedirs(self.rule_folder, exist_ok=True)
        os.makedirs(self.quarantine_folder, exist_ok=True)
        os.makedirs(self.backup_folder, exist_ok=True)

    def fetch_and_generate_yara_rules(self):
        """Fetch YARA rules from a URL and write them into categorized .yar files."""
        try:
            url = "https://library.bitss.fr/windows.php"
            response = requests.get(url)
            json_data = response.json()

            rule_files = {}

            for rule in json_data:
                # rulename = rule.get("rulename", "Unknown_Rule")
                category = rule.get("categoryname", "uncategorized").replace(" ", "_").lower()
                conditions = rule.get("conditions", [])

                if category not in rule_files:
                    rule_files[category] = []

                for condition in conditions:
                    rule_string = condition.get("string", "")
                    if rule_string:
                        rule_files[category].append(rule_string.strip('""'))

            for category, rules in rule_files.items():
                output_file = os.path.join(self.rule_folder, f"{category}.yar")
                with open(output_file, "w") as file:
                    for rule in rules:
                        file.write(rule + "\n\n")

            self.log("[INFO] YARA rules categorized and saved.", "load")

        except Exception as e:
            self.log(f"[ERROR] Failed to fetch YARA rules: {e}", "load")

    def load_rules(self):
        try:
            rule_files = [
                os.path.join(self.rule_folder, file)
                for file in os.listdir(self.rule_folder)
                if file.endswith(".yar")
            ]
            if not rule_files:
                raise FileNotFoundError("No .yar files found in the 'yara' folder.")
            
            valid_rule_files = {}
            for file_path in rule_files:
                try:
                    yara.compile(filepath=file_path)
                    valid_rule_files[os.path.basename(file_path)] = file_path
                except yara.Error as e:
                    print(f"[ERROR] Failed to compile YARA file {file_path}: {e}")

            if valid_rule_files:
                self.rules = yara.compile(filepaths=valid_rule_files)
                self.log(f"[INFO] Successfully compiled {len(valid_rule_files)} YARA rule files.", "load")
            else:
                self.log("[ERROR] No valid YARA rules to compile.", "load")
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

    def scan_file(self, file_path):
        if self.stop_scan:
            return
        try:
            matches = self.rules.match(file_path, timeout=60)
            self.log(f"{file_path} \n", "tested")
            if matches:
                matched_rules_info = []
                for match in matches:
                    rule_name = match.rule  # Get the rule name
                    # yar_file = match.namespace  # Get the .yar file name
                    # matched_rules_info.append(f"Rule: {rule_name}\nYARA File: {yar_file}")
                    yara_file = os.path.splitext(os.path.basename(match.namespace))[0]  # Remove .yar extension
                    self.log(f"[MATCH] {file_path}\nRule: {rule_name}\nMalware Type: {yara_file}\n\n", "matched")
                
                # matched_details = "\n".join(matched_rules_info)
                # self.log(f"[MATCH] {file_path}\n{matched_details}\n\n", "matched")
        except yara.Error as e:
            self.log(f"[ERROR] Failed to scan file '{file_path}': {e}", "tested")
            


        # def scan_directory(self, directory):
        #     files = []
        #     for root, _, file_names in os.walk(directory):
        #         files.extend([os.path.join(root, file) for file in file_names])
        #     total_files = len(files)
        #     self.progress["maximum"] = total_files
        #     for i, file_path in enumerate(files, 1):
        #         if self.stop_scan:
        #             self.log("[INFO] Scan stopped by user.", "load")
        #             break
        #         self.scan_file(file_path)
        #         self.progress["value"] = i
        #         progress_percent = int((i / total_files) * 100)
        #         self.progress_label.config(text=f"Progress: {progress_percent}%")
        #         self.root.update_idletasks()            
    
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



    def scan_file(self, file_path):
        if self.stop_scan:
            return
        try:
            matches = self.rules.match(file_path, timeout=60)
            self.log(f"{file_path} \n", "tested")
            if matches:
                yara_file = os.path.splitext(os.path.basename(matches[0].namespace))[0]  # Remove .yar extension
                self.log(f"[MATCH] {file_path}\nRule: {matches[0].rule}\nMalware Type: {yara_file}\n\n", "matched")

                self.quarantine_file(file_path)  # Move matched file to quarantine
        except yara.Error as e:
            self.log(f"[ERROR] Failed to scan file '{file_path}': {e}", "tested")

    def quarantine_file(self, file_path):
        """Move matched files to a quarantine folder."""
        if not os.path.exists(self.quarantine_folder):
            os.makedirs(self.quarantine_folder)

        file_name = os.path.basename(file_path)
        quarantined_path = os.path.join(self.quarantine_folder, file_name + ".quarantined")

        try:
            shutil.move(file_path, quarantined_path)
            self.quarantined_files[file_name] = (quarantined_path, file_path)
            self.log(f"[QUARANTINED] {file_path} moved to {quarantined_path}", "matched")
        except Exception as e:
            self.log(f"[ERROR] Failed to quarantine {file_path}: {e}", "matched")

    # def restore_file(self):
    #     """Restore a quarantined file to its original location."""
    #     file_name = filedialog.askopenfilename(initialdir=self.quarantine_folder, title="Select file to restore")
    #     if file_name and file_name.endswith(".quarantined"):
    #         original_name = os.path.basename(file_name).replace(".quarantined", "")
    #         if original_name in self.quarantined_files:
    #             quarantined_path, original_path = self.quarantined_files[original_name]
    #             try:
    #                 shutil.move(quarantined_path, original_path)
    #                 self.log(f"[RESTORED] {original_name} restored to {original_path}", "load")
    #                 del self.quarantined_files[original_name]
    #             except Exception as e:
    #                 self.log(f"[ERROR] Failed to restore {original_name}: {e}", "load")
    #         else:
    #             self.log(f"[ERROR] No record of {original_name} in quarantine.", "load")
    #     else:
    #         self.log("[ERROR] Invalid file selected for restoration.", "load")
    
    

    def select_backup_file(self):
        """Allow user to select a file to backup."""
        file_path = filedialog.askopenfilename(title="Select File to Backup", filetypes=(("All files", "*.*"),))
        if file_path:
            backup_path = os.path.join(self.backup_folder, os.path.basename(file_path) + ".backup")
            try:
                shutil.copy(file_path, backup_path)
                self.log(f"[BACKUP] {file_path} -> {backup_path}", "load")
            except Exception as e:
                self.log(f"[ERROR] Failed to backup {file_path}: {e}", "load")

    def restore_backup(self):
        """Restore a backup file."""
        file_path = filedialog.askopenfilename(initialdir=self.backup_folder, title="Select Backup to Restore",
                                               filetypes=(("Backup files", "*.backup"),))
        if file_path:
            original_name = os.path.basename(file_path).replace(".backup", "")
            restore_path = filedialog.asksaveasfilename(initialfile=original_name, title="Save Restored File")
            if restore_path:
                try:
                    shutil.copy(file_path, restore_path)
                    self.log(f"[RESTORED] {file_path} -> {restore_path}", "load")
                except Exception as e:
                    self.log(f"[ERROR] Failed to restore {file_path}: {e}", "load")
    

    def stop_scanning(self):
        self.stop_scan = True

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


if __name__ == "__main__":
    root = Tk()
    app = VWARScannerGUI(root)
    # Button(root, text="Restore File", command=app.restore_file).place(x=485.0, y=315.0, width=120.0, height=25.0)
    root.resizable(False, False)
    root.mainloop()
