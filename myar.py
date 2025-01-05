import yara
import os
from tkinter import Tk, Label, Button, filedialog, Text, messagebox
from tkinter.ttk import Progressbar


class VWARScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VWAR Scanner")
        self.rule_folder = None
        self.target_path = None
        self.rules = None
        self.stop_scan = False  # Stop flag

        # Set background color to sky blue
        self.root.configure(bg="skyblue")

        # GUI components
        Label(root, text="VWAR Malware Scanner", font=("Helvetica", 16, "bold"), bg="skyblue", fg="black").pack(pady=10)

        self.rule_label = Label(root, text="No VWAR rules folder selected", bg="skyblue", fg="black")
        self.rule_label.pack()

        Button(root, text="Select VWAR Rules Folder", command=self.select_VWAR_rules_folder).pack(pady=5)

        self.target_label = Label(root, text="No file or folder selected", bg="skyblue", fg="black")
        self.target_label.pack()

        # Separate buttons for file and folder selection
        Button(root, text="Select Target File", command=self.select_file).pack(pady=5)
        Button(root, text="Select Target Folder", command=self.select_folder).pack(pady=5)

        Button(root, text="Scan", command=self.scan).pack(pady=10)
        Button(root, text="Stop", command=self.stop_scanning).pack(pady=10)  # Stop button

        # Progress bar and output
        self.progress_label = Label(root, text="Progress: 0%", bg="skyblue", fg="black")
        self.progress_label.pack()

        self.progress = Progressbar(root, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(pady=10)

        self.output_text = Text(root, wrap="word", height=15, width=60)
        self.output_text.pack(padx=10, pady=10)

    def select_VWAR_rules_folder(self):
        """Select a folder containing multiple VWAR (YARA) rules."""
        self.rule_folder = filedialog.askdirectory(title="Select VWAR Rules Folder")
        if self.rule_folder:
            self.rule_label.config(text=f"VWAR Rules Folder: {os.path.basename(self.rule_folder)}")
            self.compile_VWAR_rules()

    def select_file(self):
        """Select a single file to scan."""
        target = filedialog.askopenfilename(
            title="Select File to Scan",
            filetypes=(("All files", "*.*"),),
        )
        if target:
            self.target_path = target
            self.target_label.config(text=f"Target File: {os.path.basename(target)}")

    def select_folder(self):
        """Select a folder to scan."""
        target = filedialog.askdirectory(title="Select Folder to Scan")
        if target:
            self.target_path = target
            self.target_label.config(text=f"Target Folder: {target}")

    # def compile_VWAR_rules(self):
    #     """Compile all YARA rules in the selected folder."""
    #     try:
    #         rule_files = [
    #             os.path.join(self.rule_folder, file)
    #             for file in os.listdir(self.rule_folder)
    #             if file.endswith(".yar")
    #         ]
    #         if not rule_files:
    #             raise FileNotFoundError("No .yar files found in the selected folder.")
    #         for i in rule_files:
    #             print( i )
    #             self.rules = yara.compile(filepath=i)
    #             # self.rules = yara.compile(filepaths={os.path.basename(f): f for f in rule_files})
    #             self.log(f"[INFO] Successfully compiled {len(rule_files)} VWAR rules.")
    #     except Exception as e:
    #         self.log(f"[ERROR] Failed to compile VWAR rules: {e}")
    def compile_VWAR_rules(self):
        """Compile all valid YARA rules in the selected folder, skipping invalid ones."""
        try:
            rule_files = [
                os.path.join(self.rule_folder, file)
                for file in os.listdir(self.rule_folder)
                if file.endswith(".yar")
            ]
            if not rule_files:
                raise FileNotFoundError("No .yar files found in the selected folder.")

            valid_rule_files = {}
            skipped_files = []

            for file_path in rule_files:
                try:
                    # Compile individual rule to verify validity
                    yara.compile(filepath=file_path)
                    valid_rule_files[os.path.basename(file_path)] = file_path
                except yara.Error as e:
                    skipped_files.append((os.path.basename(file_path), str(e)))

            if valid_rule_files:
                # Compile only the valid files
                self.rules = yara.compile(filepaths=valid_rule_files)
                self.log(f"[INFO] Successfully compiled {len(valid_rule_files)} valid VWAR rules.")
            else:
                self.log("[ERROR] No valid VWAR rules to compile.")

            if skipped_files:
                self.log("[WARNING] The following files were skipped due to errors:")
                for file, error in skipped_files:
                    self.log(f" - {file}: {error}")

        except Exception as e:
            self.log(f"[ERROR] Failed to compile VWAR rules: {e}")

    def scan(self):
        """Scan the selected file or folder."""
        if not self.rules:
            messagebox.showerror("Error", "Please select and compile a valid folder of VWAR rules.")
            return

        if not self.target_path:
            messagebox.showerror("Error", "Please select a file or folder to scan.")
            return

        self.stop_scan = False  # Reset stop flag
        self.output_text.delete("1.0", "end")  # Clear the output text area

        if os.path.isfile(self.target_path):
            self.scan_file(self.target_path)
        elif os.path.isdir(self.target_path):
            self.scan_directory(self.target_path)
        else:
            self.log(f"[ERROR] Invalid target path: {self.target_path}")

        self.progress.stop()  # Stop progress bar after completion
        self.progress_label.config(text="Scan Complete!")

    def scan_file(self, file_path):
        """Scan a single file with the compiled VWAR (YARA) rules."""
        if self.stop_scan:
            return
        try:
            matches = self.rules.match(file_path)
            if matches:
                self.log(f"[MATCH] Matches found in file: {file_path}")
                for match in matches:
                    self.log(f" - Rule: {match.rule}")
                    if match.strings:
                        for offset, string_id, string_data in match.strings:
                            self.log(f"   * Offset: {offset}, String ID: {string_id}, Data: {string_data}")
            else:
                self.log(f"[INFO] No matches found in file: {file_path}")
        except yara.Error as e:
            self.log(f"[ERROR] Failed to scan file '{file_path}': {e}")

    def scan_directory(self, directory):
        """Recursively scan all files in a directory."""
        files = []
        for root, _, file_names in os.walk(directory):
            files.extend([os.path.join(root, file) for file in file_names])

        total_files = len(files)
        self.progress["maximum"] = total_files
        self.log(f"[INFO] Scanning directory: {directory}")

        for i, file_path in enumerate(files, 1):
            if self.stop_scan:
                self.log("[INFO] Scan stopped by user.")
                break
            self.scan_file(file_path)
            self.progress["value"] = i
            progress_percent = int((i / total_files) * 100)
            self.progress_label.config(text=f"Progress: {progress_percent}%")
            self.root.update_idletasks()

    def stop_scanning(self):
        """Stop the scanning process."""
        self.stop_scan = True

    def log(self, message):
        """Log messages to the output text area."""
        self.output_text.insert("end", message + "\n")
        self.output_text.see("end")


if __name__ == "__main__":
    root = Tk()
    app = VWARScannerGUI(root)
    root.mainloop()
