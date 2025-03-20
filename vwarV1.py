import threading
import yara
import os
import shutil
from tkinter import Tk, Frame, Canvas, Label, Text, Button, filedialog, messagebox
from tkinter.ttk import Progressbar
import requests
from tkinter import Toplevel, Listbox
import time
import base64
import hashlib



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

        # Show home page initially
        self.show_page("home")
        
        
        
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

    def create_folders(self):
        """Ensure required folders exist."""
        os.makedirs(self.rule_folder, exist_ok=True)
        os.makedirs(self.quarantine_folder, exist_ok=True)
        os.makedirs(self.backup_folder, exist_ok=True)

    def show_page(self, page_name):
        """Display the requested page."""
        for page in self.pages.values():
            page.place_forget()
        self.pages[page_name].place(x=0, y=0, width=1043, height=722)

    def create_home_page(self):
        """Create the Home Page with navigation buttons."""
        home_page = Frame(self.root, bg="#009AA5")
        self.pages["home"] = home_page

        Label(home_page, text="VWAR Scanner", font=("Inter", 24), bg="#009AA5", fg="white").place(x=420, y=50)

        Button(home_page, text="Scanning", command=lambda: self.show_page("scanning"), bg="blue", fg="white",
               font=("Inter", 16)).place(x=400, y=200, width=200, height=50)

        Button(home_page, text="Backup", command=lambda: self.show_page("backup"), bg="orange", fg="white",
               font=("Inter", 16)).place(x=400, y=300, width=200, height=50)

    def create_scanning_page(self):
        
        

        self.fetch_and_generate_yara_rules()
        self.root.after(100, self.load_rules)
        
        
        """Create the Scanning Page with scan controls."""
        scanning_page = Frame(self.root, bg="#009AA5")
        self.pages["scanning"] = scanning_page
        


        Button(scanning_page, text="Back", command=lambda: self.show_page("home"), bg="gray", fg="white",
               font=("Inter", 12)).place(x=10, y=10, width=80, height=30)

        # Button(scanning_page, text="Select Target File", command=self.select_file).place(x=302, y=139, width=125, height=40)
        # Button(scanning_page, text="Select Target Folder", command=self.select_folder).place(x=302, y=195, width=125, height=40)
        Button(scanning_page, text="Select Target File", command=self.select_file).place(x=302.0, y=139.0, width=125.0, height=40.0)
        Button(scanning_page, text="Select Target Folder", command=self.select_folder).place(x=302.0, y=195.0, width=125.0, height=40.0)
        Button(scanning_page, text="Scan", command=self.start_scan_thread, bg="green", fg="white").place(x=485, y=150, width=73, height=25)
        Button(scanning_page, text="Stop", command=self.stop_scanning, bg="red", fg="white").place(x=485, y=195, width=73, height=25)
        
        
        Button(scanning_page, text="Show Quarantined Files", command=self.show_quarantine_window, bg="purple", fg="white",
       font=("Inter", 12)).place(x=700, y=195, width=200, height=40)


        # self.progress_label = Label(scanning_page, text="PROGRESS : 0%", bg="#12e012", fg="black", font=("Inter", 12))
        # self.progress_label.place(x=476, y=311)
        
        self.progress_label = Label(scanning_page, text="PROGRESS : 0%", bg="#12e012", fg="#000000", font=("Inter", 12 * -1))
        self.progress_label.place(x=476.0, y=311.0)

        # self.progress = Progressbar(scanning_page, orient="horizontal", length=350, mode="determinate")
        # self.progress.place(x=354, y=350)
        
        self.progress = Progressbar(scanning_page, orient="horizontal", length=350, mode="determinate")
        self.progress.place(x=354, y=350)
        
        
        # self.matched_text = Text(scanning_page, bg="#D9D9D9", fg="black", wrap="word")
        # self.matched_text.place(x=0, y=488, width=485, height=232)

        # self.tested_text = Text(scanning_page, bg="#D9D9D9", fg="black", wrap="word")
        # self.tested_text.place(x=557, y=488, width=485, height=232)
        
        
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



    # def show_quarantine_window(self):
    #     """Display a window with quarantined files fetched from the quarantine folder."""
    #     quarantine_window = Toplevel(self.root)
    #     quarantine_window.title("Quarantined Files")
    #     quarantine_window.geometry("500x400")
    #     quarantine_window.configure(bg="#009AA5")

    #     # Label(quarantine_window, text="Quarantined Files", font=("Inter", 16), bg="#009AA5", fg="white").pack(pady=10)

    #     self.quarantine_listbox = Listbox(quarantine_window, bg="white", fg="black", font=("Inter", 12), selectmode="single")
    #     self.quarantine_listbox.pack(padx=20, pady=10, fill="both", expand=True)

    #     # Load quarantined files dynamically from the quarantine folder
    #     self.quarantined_files = {}
    #     for index, file_name in enumerate(os.listdir(self.quarantine_folder), start=1):
    #             quarantined_path = os.path.join(self.quarantine_folder, file_name)
    #             # print(quarantined_path)
    #             if os.path.isfile(quarantined_path):
    #                 original_path = quarantined_path.replace(".quarantined", "")  # Assume original name before renaming
                    
    #                 parts = original_path.rsplit("__", 2)
    #                 if len(parts) < 3:
    #                     return None  # Invalid format
    #                 encoded_path = parts[-1].replace(".quarantined", "")
    #                 print(encoded_path)
    #                # Decode the base64 string
    #                 padding_needed = len(encoded_path) % 4
    #                 if padding_needed:
    #                     encoded_string += '=' * (4 - padding_needed)

    #                 # Decode the base64 string
    #                 decoded_string = base64.urlsafe_b64decode(encoded_string).decode()

    #                 # Print the decoded result
    #                 print(decoded_string)
    #                 # print(encoded_path)
    #             self.quarantined_files[file_name] = (quarantined_path, original_path)
    #             self.quarantine_listbox.insert("end", f"{index}. {file_name}")  # Proper numbering

    #     # Button to restore files
    #     # Button(quarantine_window, text="Restore Selected File", command=self.restore_selected_file, bg="green", fg="white").pack(pady=5)

    #     # Button to delete files
    #     Button(quarantine_window, text="Delete Selected File", command=self.delete_selected_file, bg="red", fg="white").pack(pady=5)

    def show_quarantine_window(self):
        """Display a window with quarantined files, extracting timestamp and original location."""
        quarantine_window = Toplevel(self.root)
        quarantine_window.title("Quarantined Files")
        quarantine_window.geometry("700x400")
        quarantine_window.configure(bg="#009AA5")

        self.quarantine_listbox = Listbox(quarantine_window, bg="white", fg="black", font=("Inter", 12), selectmode="single")
        self.quarantine_listbox.pack(padx=20, pady=10, fill="both", expand=True)

        # Load quarantined files dynamically
        self.quarantined_files = {}
        
        for index, file_name in enumerate(os.listdir(self.quarantine_folder), start=1):
            quarantined_path = os.path.join(self.quarantine_folder, file_name)
            
            if os.path.isfile(quarantined_path) and file_name.endswith(".quarantined"):
                parts = file_name.rsplit("__", 2)
                if len(parts) < 3:
                    continue  # Invalid format, skip
                
                fname, timestamp, encoded_path = parts

                # Decode original file path
                original_path =decode_base64(encoded_path)

                # Format timestamp
                formatted_time = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]} {timestamp[8:10]}:{timestamp[10:12]}:{timestamp[12:]}"

                # Display in GUI
                print(original_path)
                display_text = f"{index}. {fname}...  | Quarantined: {formatted_time} | From: {original_path}"
                self.quarantine_listbox.insert("end", display_text)

                # Store information for restoring
                self.quarantined_files[file_name] = (quarantined_path, original_path)

        # Buttons
        Button(quarantine_window, text="Delete Selected File", command=self.delete_selected_file, bg="red", fg="white").pack(pady=5)



    def restore_selected_file(self):
        """Restore a selected quarantined file to its original location."""
        selected_index = self.quarantine_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("No Selection", "Please select a file to restore.")
            return

        selected_file = self.quarantine_listbox.get(selected_index)
        quarantined_path, original_path = self.quarantined_files[selected_file]

        try:
            shutil.move(quarantined_path, original_path)
            del self.quarantined_files[selected_file]  # Remove from the dictionary
            self.quarantine_listbox.delete(selected_index)  # Remove from listbox
            self.log(f"[RESTORED] {selected_file} restored to {original_path}", "load")
            messagebox.showinfo("Success", f"{selected_file} has been restored successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restore {selected_file}: {e}")

    def delete_selected_file(self):
        """Delete a selected quarantined file permanently."""
        selected_index = self.quarantine_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("No Selection", "Please select a file to delete.")
            return

        selected_file = self.quarantine_listbox.get(selected_index)
        quarantined_path, _ = self.quarantined_files[selected_file]

        confirm = messagebox.askyesno("Confirm Deletion", f"Are you sure you want to permanently delete {selected_file}?")
        if confirm:
            try:
                os.remove(quarantined_path)  # Permanently delete the file
                del self.quarantined_files[selected_file]  # Remove from the dictionary
                self.quarantine_listbox.delete(selected_index)  # Remove from listbox
                self.log(f"[DELETED] {selected_file} permanently deleted.", "load")
                messagebox.showinfo("Deleted", f"{selected_file} has been permanently deleted.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete {selected_file}: {e}")

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
                # except yara.Error as e:
                #     print(f"[ERROR] Failed to compile YARA file {file_path}: {e}")
                except (yara.SyntaxError, yara.CompileError) as e:
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
        # except yara.Error as e:
        #     self.log(f"[ERROR] Failed to scan file '{file_path}': {e}", "tested")
        except (yara.SyntaxError, yara.CompileError) as e:
            self.log(f"[ERROR] Failed to scan file '{file_path}': {e}", "tested")
        
    # def quarantine_file(self, file_path):
    #     """Move matched files to a quarantine folder."""
    #     if not os.path.exists(self.quarantine_folder):
    #         os.makedirs(self.quarantine_folder)

    #     file_name = os.path.basename(file_path)
    #     quarantined_path = os.path.join(self.quarantine_folder, file_name + ".quarantined")

    #     try:
    #         shutil.move(file_path, quarantined_path)
    #         self.quarantined_files[file_name] = (quarantined_path, file_path)
    #         self.log(f"[QUARANTINED] {file_path} moved to {quarantined_path}", "matched")
    #     except Exception as e:
    #         self.log(f"[ERROR] Failed to quarantine {file_path}: {e}", "matched")
            

    def quarantine_file(self, file_path):
        """Move matched files to a quarantine folder and encode metadata in the filename."""
        if not os.path.exists(self.quarantine_folder):
            os.makedirs(self.quarantine_folder)

        file_name = os.path.basename(file_path)
        file_p = os.path.dirname(file_path)
        timestamp = time.strftime("%Y%m%d%H%M%S")  # Format: YYYYMMDDHHMMSS
        MAX_ENCODED_LENGTH = 100  # Limit the encoded path length
        # Encode original file path in base64 to avoid special character issues
        encoded_path = base64.urlsafe_b64encode(file_p.encode()).decode()
        encoded_path = encoded_path[:MAX_ENCODED_LENGTH]  # Trim long paths
        
        # encoded_path = hashlib.sha256(file_path.encode()).hexdigest()
        # print(file_p)
        # print(f"{file_name},{timestamp},{encoded_path}")
        # New filename format: original_name__timestamp__encoded_path.quarantined
        quarantined_name = f"{file_name}__{timestamp}__{encoded_path}.quarantined"
        quarantined_path = os.path.join(self.quarantine_folder, quarantined_name)

        try:
            shutil.move(file_path, quarantined_path)
            self.log(f"[QUARANTINED] {file_path} → {quarantined_path} at {timestamp}", "matched")
        except Exception as e:
            self.log(f"[ERROR] Failed to quarantine {file_path}: {e}", "matched")           
    
    
    
    
    # def quarantine_file(self, file_path):
    #     """Move matched files to a quarantine folder and encode metadata in the filename."""
    #     if not os.path.exists(self.quarantine_folder):
    #         os.makedirs(self.quarantine_folder)

    #     if not os.path.exists(file_path):
    #         self.log(f"[ERROR] Source file does not exist: {file_path}", "matched")
    #         return

    #     file_name = os.path.basename(file_path)
    #     timestamp = time.strftime("%Y%m%d%H%M%S")

    #     # Use SHA-256 to encode the original file path (fixed 64-character length)
    #     encoded_path = hashlib.sha256(file_path.encode()).hexdigest()

    #     # Format: <original_file>__<timestamp>__<hashed_path>.quarantined
    #     quarantined_name = f"{file_name}__{timestamp}__{encoded_path[:16]}.quarantined"
    #     quarantined_path = os.path.join(self.quarantine_folder, quarantined_name)

    #     try:
    #         shutil.move(file_path, quarantined_path)  # Try moving
    #     except Exception:
    #         try:
    #             os.rename(file_path, quarantined_path)  # Fallback rename
    #         except Exception as e:
    #             self.log(f"[ERROR] Failed to quarantine {file_path}: {e}", "matched")
    #             return

    #     self.log(f"[QUARANTINED] {file_path} → {quarantined_path} at {timestamp}", "matched")
            
            

    def stop_scanning(self):
        """Stop the scanning process."""
        self.stop_scan = True




    def create_backup_page(self):
        """Create the Backup Page for file backup and restoration."""
        backup_page = Frame(self.root, bg="#009AA5")
        self.pages["backup"] = backup_page

        Button(backup_page, text="Back", command=lambda: self.show_page("home"), bg="gray", fg="white",
               font=("Inter", 12)).place(x=10, y=10, width=80, height=30)

        Button(backup_page, text="Select File to Backup", command=self.select_backup_file).place(x=302, y=139, width=150, height=40)
        Button(backup_page, text="Restore from Backup", command=self.restore_backup).place(x=302, y=195, width=150, height=40)





    def select_backup_file(self):
        """Backup selected file."""
        file_path = filedialog.askopenfilename(title="Select File to Backup", filetypes=[("All files", "*.*")])
        if file_path:
            backup_path = os.path.join(self.backup_folder, os.path.basename(file_path) + ".backup")
            shutil.copy(file_path, backup_path)

    def restore_backup(self):
        """Restore a backup file."""
        file_path = filedialog.askopenfilename(initialdir=self.backup_folder, title="Select Backup to Restore",
                                               filetypes=[("Backup files", "*.backup")])
        if file_path:
            original_name = os.path.basename(file_path).replace(".backup", "")
            restore_path = filedialog.asksaveasfilename(initialfile=original_name, title="Save Restored File")
            if restore_path:
                shutil.copy(file_path, restore_path)





if __name__ == "__main__":
    root = Tk()
    app = VWARScannerGUI(root)
    root.resizable(False, False)
    root.mainloop()
