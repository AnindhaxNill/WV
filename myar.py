# import yara
# import os
# from tkinter import Tk, Label, Button, filedialog, Text, messagebox
# from tkinter.ttk import Progressbar


# class VWARScannerGUI:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("VWAR Scanner")
#         self.rule_folder = None
#         self.target_path = None
#         self.rules = None
#         self.stop_scan = False  # Stop flag

#         # Set background color to sky blue
#         self.root.configure(bg="skyblue")

#         # GUI components
#         Label(root, text="VWAR Malware Scanner", font=("Helvetica", 16, "bold"), bg="skyblue", fg="black").pack(pady=10)

#         self.rule_label = Label(root, text="No VWAR rules folder selected", bg="skyblue", fg="black")
#         self.rule_label.pack()

#         Button(root, text="Select VWAR Rules Folder", command=self.select_VWAR_rules_folder).pack(pady=5)

#         self.target_label = Label(root, text="No file or folder selected", bg="skyblue", fg="black")
#         self.target_label.pack()

#         # Separate buttons for file and folder selection
#         Button(root, text="Select Target File", command=self.select_file).pack(pady=5)
#         Button(root, text="Select Target Folder", command=self.select_folder).pack(pady=5)

#         Button(root, text="Scan", command=self.scan).pack(pady=10)
#         Button(root, text="Stop", command=self.stop_scanning).pack(pady=10)  # Stop button

#         # Progress bar and output
#         self.progress_label = Label(root, text="Progress: 0%", bg="skyblue", fg="black")
#         self.progress_label.pack()

#         self.progress = Progressbar(root, orient="horizontal", length=400, mode="determinate")
#         self.progress.pack(pady=10)

#         self.output_text = Text(root, wrap="word", height=15, width=60)
#         self.output_text.pack(padx=10, pady=10)

#     def select_VWAR_rules_folder(self):
#         """Select a folder containing multiple VWAR (YARA) rules."""
#         self.rule_folder = filedialog.askdirectory(title="Select VWAR Rules Folder")
#         if self.rule_folder:
#             self.rule_label.config(text=f"VWAR Rules Folder: {os.path.basename(self.rule_folder)}")
#             self.compile_VWAR_rules()

#     def select_file(self):
#         """Select a single file to scan."""
#         target = filedialog.askopenfilename(
#             title="Select File to Scan",
#             filetypes=(("All files", "*.*"),),
#         )
#         if target:
#             self.target_path = target
#             self.target_label.config(text=f"Target File: {os.path.basename(target)}")

#     def select_folder(self):
#         """Select a folder to scan."""
#         target = filedialog.askdirectory(title="Select Folder to Scan")
#         if target:
#             self.target_path = target
#             self.target_label.config(text=f"Target Folder: {target}")

#     # def compile_VWAR_rules(self):
#     #     """Compile all YARA rules in the selected folder."""
#     #     try:
#     #         rule_files = [
#     #             os.path.join(self.rule_folder, file)
#     #             for file in os.listdir(self.rule_folder)
#     #             if file.endswith(".yar")
#     #         ]
#     #         if not rule_files:
#     #             raise FileNotFoundError("No .yar files found in the selected folder.")
#     #         for i in rule_files:
#     #             print( i )
#     #             self.rules = yara.compile(filepath=i)
#     #             # self.rules = yara.compile(filepaths={os.path.basename(f): f for f in rule_files})
#     #             self.log(f"[INFO] Successfully compiled {len(rule_files)} VWAR rules.")
#     #     except Exception as e:
#     #         self.log(f"[ERROR] Failed to compile VWAR rules: {e}")
#     def compile_VWAR_rules(self):
#         """Compile all valid YARA rules in the selected folder, skipping invalid ones."""
#         try:
#             rule_files = [
#                 os.path.join(self.rule_folder, file)
#                 for file in os.listdir(self.rule_folder)
#                 if file.endswith(".yar")
#             ]
#             if not rule_files:
#                 raise FileNotFoundError("No .yar files found in the selected folder.")

#             valid_rule_files = {}
#             skipped_files = []

#             for file_path in rule_files:
#                 try:
#                     # Compile individual rule to verify validity
#                     yara.compile(filepath=file_path)
#                     valid_rule_files[os.path.basename(file_path)] = file_path
#                 except yara.Error as e:
#                     skipped_files.append((os.path.basename(file_path), str(e)))

#             if valid_rule_files:
#                 # Compile only the valid files
#                 self.rules = yara.compile(filepaths=valid_rule_files)
#                 self.log(f"[INFO] Successfully compiled {len(valid_rule_files)} valid VWAR rules.")
#             else:
#                 self.log("[ERROR] No valid VWAR rules to compile.")

#             if skipped_files:
#                 self.log("[WARNING] The following files were skipped due to errors:")
#                 for file, error in skipped_files:
#                     self.log(f" - {file}: {error}")

#         except Exception as e:
#             self.log(f"[ERROR] Failed to compile VWAR rules: {e}")

#     def scan(self):
#         """Scan the selected file or folder."""
#         if not self.rules:
#             messagebox.showerror("Error", "Please select and compile a valid folder of VWAR rules.")
#             return

#         if not self.target_path:
#             messagebox.showerror("Error", "Please select a file or folder to scan.")
#             return

#         self.stop_scan = False  # Reset stop flag
#         self.output_text.delete("1.0", "end")  # Clear the output text area

#         if os.path.isfile(self.target_path):
#             self.scan_file(self.target_path)
#         elif os.path.isdir(self.target_path):
#             self.scan_directory(self.target_path)
#         else:
#             self.log(f"[ERROR] Invalid target path: {self.target_path}")

#         self.progress.stop()  # Stop progress bar after completion
#         self.progress_label.config(text="Scan Complete!")

#     def scan_file(self, file_path):
#         """Scan a single file with the compiled VWAR (YARA) rules."""
#         if self.stop_scan:
#             return
#         try:
#             matches = self.rules.match(file_path)
#             if matches:
#                 self.log(f"[MATCH] Matches found in file: {file_path}")
#                 for match in matches:
#                     self.log(f" - Rule: {match.rule}")
#                     if match.strings:
#                         for offset, string_id, string_data in match.strings:
#                             self.log(f"   * Offset: {offset}, String ID: {string_id}, Data: {string_data}")
#             else:
#                 self.log(f"[INFO] No matches found in file: {file_path}")
#         except yara.Error as e:
#             self.log(f"[ERROR] Failed to scan file '{file_path}': {e}")

#     def scan_directory(self, directory):
#         """Recursively scan all files in a directory."""
#         files = []
#         for root, _, file_names in os.walk(directory):
#             files.extend([os.path.join(root, file) for file in file_names])

#         total_files = len(files)
#         self.progress["maximum"] = total_files
#         self.log(f"[INFO] Scanning directory: {directory}")

#         for i, file_path in enumerate(files, 1):
#             if self.stop_scan:
#                 self.log("[INFO] Scan stopped by user.")
#                 break
#             self.scan_file(file_path)
#             self.progress["value"] = i
#             progress_percent = int((i / total_files) * 100)
#             self.progress_label.config(text=f"Progress: {progress_percent}%")
#             self.root.update_idletasks()

#     def stop_scanning(self):
#         """Stop the scanning process."""
#         self.stop_scan = True

#     def log(self, message):
#         """Log messages to the output text area."""
#         self.output_text.insert("end", message + "\n")
#         self.output_text.see("end")


# if __name__ == "__main__":
#     root = Tk()
#     app = VWARScannerGUI(root)
#     root.mainloop()
#######################################@#@@@@@@@@@@@@@@@@@@@@

import yara
import os
from tkinter import Tk, Canvas, Label, Text, Button, filedialog, messagebox
from tkinter.ttk import Progressbar
from pathlib import Path
import requests


class VWARScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VWAR Scanner")
        self.rule_folder = os.path.join(os.getcwd(), "yara")
        self.target_path = None
        self.rules = None
        self.stop_scan = False

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

        # Buttons and Labels
        Button(
            root,
            text="Select Target File",
            command=self.select_file,
            activebackground="green",
            activeforeground="white",
            bd=3,
            bg="lightgray",
            cursor="hand2",
            fg="black",
            font=("Arial", 10),
        ).place(x=463.0, y=139.0, width=118.0, height=40.0)

        Button(
            root,
            text="Select Target Folder",
            command=self.select_folder,
            activebackground="green",
            activeforeground="white",
            bd=3,
            bg="lightgray",
            cursor="hand2",
            fg="black",
            font=("Arial", 10),
        ).place(x=463.0, y=189.0, width=118.0, height=40.0)

        Button(
            root,
            text="Scan",
            command=self.scan,
            relief="flat"
        ).place(x=485.0, y=239.0, width=73.0, height=25.0)

        Button(
            root,
            text="Stop",
            command=self.stop_scanning,
            relief="flat"
        ).place(x=485.0, y=275.0, width=73.0, height=25.0)

        self.progress_label = Label(
            root,
            anchor="nw",
            text="PROGRESS : 0%",
            bg="#2EADAD",
            fg="#000000",
            font=("Inter", 12 * -1)
        )
        self.progress_label.place(x=476.0, y=311.0)

        self.progress = Progressbar(
            root,
            orient="horizontal",
            length=350,
            mode="determinate",
        )
        self.progress.place(x=354, y=336)

        # Matched and Tested Files Sections
        canvas.create_rectangle(
            0.0, 432.0, 485.0, 486.0, fill="#AE0505", outline="")
        canvas.create_text(
            164.0, 447.0, anchor="nw", text="MATCHED FILES", fill="#FFFFFF", font=("Inter", 20 * -1))
        self.matched_text = Text(root, bg="#D9D9D9", fg="#000000", wrap="word")
        self.matched_text.place(x=0.0, y=488.0, width=485.0, height=232.0)

        canvas.create_rectangle(
            557.0, 432.0, 1042.0, 486.0, fill="#001183", outline="")
        canvas.create_text(
            731.0, 447.0, anchor="nw", text="TESTED FILES", fill="#FFFFFF", font=("Inter", 20 * -1))
        self.tested_text = Text(root, bg="#D9D9D9", fg="#000000", wrap="word")
        self.tested_text.place(x=557.0, y=488.0, width=485.0, height=232.0)

        # Auto-load YARA rules on startup
        self.create_yara_folder()
        self.fetch_and_generate_yara_rules()
        self.root.after(100, self.load_rules)

    def create_yara_folder(self):
        """Ensure the 'yara' folder exists."""
        if not os.path.exists(self.rule_folder):
            os.makedirs(self.rule_folder)

    def fetch_and_generate_yara_rules(self):
        """Fetch YARA rules from a URL and write them to a .yar file."""
        try:
            url = "https://library.bitss.fr/windows.php"
            response = requests.get(url)
            json_data = response.json()
            output_file = os.path.join(self.rule_folder, "generated_rules.yar")
            with open(output_file, "w") as file:
                for rule in json_data:
                    rulename = rule.get("rulename", "Unknown_Rule")
                    conditions = rule.get("conditions", [])
                    for condition in conditions:
                        rule_string = condition.get("string", "")
                        if rule_string:
                            file.write(rule_string.strip('""') + "\n\n")
                        else:
                            print(f"Warning: Rule '{rulename}' has no valid string. Skipping...")
            self.log(f"[INFO] Fetched and saved YARA rules to {output_file}.", "load")
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
                self.log(f"[INFO] Successfully compiled {len(valid_rule_files)} VWAR rules.", "load")
            else:
                self.log("[ERROR] No valid VWAR rules to compile.", "load")
        except Exception as e:
            self.log(f"[ERROR] Failed to load VWAR rules: {e}", "load")

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
            matches = self.rules.match(file_path)
            self.log(f"{file_path} \n", "tested")
            if matches:
                self.log(f"[MATCH] {file_path}\n RULES:{matches} \n\n", "matched")
        except yara.Error as e:
            self.log(f"[ERROR] Failed to scan file '{file_path}': {e}", "tested")

    def scan_directory(self, directory):
        files = []
        for root, _, file_names in os.walk(directory):
            files.extend([os.path.join(root, file) for file in file_names])
        total_files = len(files)
        self.progress["maximum"] = total_files
        for i, file_path in enumerate(files, 1):
            if self.stop_scan:
                self.log("[INFO] Scan stopped by user.", "tested")
                break
            self.scan_file(file_path)
            self.progress["value"] = i
            progress_percent = int((i / total_files) * 100)
            self.progress_label.config(text=f"Progress: {progress_percent}%")
            self.root.update_idletasks()

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
    root.resizable(False, False)
    root.mainloop()
