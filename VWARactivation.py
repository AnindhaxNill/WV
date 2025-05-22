import os
import sys
import ctypes

# # def is_admin():
# #     try:
# #         return ctypes.windll.shell32.IsUserAnAdmin()
# #     except:
# #         return False

# # # Relaunch with admin rights if not already running as admin
# # if not is_admin():
# #     print("Requesting admin access...")
# #     ctypes.windll.shell32.ShellExecuteW(
# #         None, "runas", sys.executable, " ".join([f'"{arg}"' for arg in sys.argv]), None, 1
# #     )
# #     sys.exit()





import subprocess
import requests, subprocess, json, os
from tkinter import Tk, Label, Entry, Button, messagebox

API_GET = "https://bitts.fr/vwar_windows/getAPI.php"
API_POST = "https://bitts.fr/vwar_windows/postAPI.php"



def get_processor_info():
    try:
        result = subprocess.run(['wmic', 'cpu', 'get', 'Name,ProcessorId'], capture_output=True, text=True)
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if len(lines) >= 2:
            header = lines[0].split()
            values = lines[1].split()
            # In case there's a space in the processor name
            if len(values) > 2:
                processor_id = values[-1]
                processor_name = ' '.join(values[:-1])
            else:
                processor_name, processor_id = values
            print(f"{processor_name} | {processor_id}")
            return f"{processor_name} | {processor_id}"
        else:
            print("Processor info not found")
            return None, None
    except Exception as e:
        print(f"Error getting processor info: {e}")
        return None, None
    
    
    
    
    
def get_motherboard_info():
    try:
        result = subprocess.run(['wmic', 'baseboard', 'get', 'Product,Manufacturer,SerialNumber'], capture_output=True, text=True)
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if len(lines) >= 2:
            headers = lines[0].split()
            values = lines[1].split()
            # Handle case where fields may be separated by multiple spaces
            while len(values) < 3:
                values.append("UNKNOWN")
            manufacturer, product, serial = values[:3]
            # print(f"Motherboard: {manufacturer} {product} | Serial: {serial}")
            return f"{manufacturer} {product} | {serial}"
        else:
            print("Motherboard info not found")
            return None, None
    except Exception as e:
        print(f"Error getting motherboard info: {e}")
        return None, None    
# #21153445231

# def activate(key):
    
    
#     try:
#         response = requests.get(API_GET)
#         data = response.json().get("data", [])
#     except Exception as e:
#         messagebox.showerror("Error", f"Failed to fetch data: {e}")
#         return

#     for record in data:
#         if record["password"] == key:
#             if record["motherboard_id"] or record["processor_id"]:
#                 messagebox.showerror("Error", "This key is already used on another system.")
#                 return

#             processor_id = get_processor_info()
#             motherboard_id = get_motherboard_info()

#             payload = {
#                 "id": int(record["id"]),
#                 "processor_id": processor_id,
#                 "motherboard_id": motherboard_id
#             }

#             try:
#                 post_response = requests.post(API_POST, json=payload)
#                 if post_response.status_code == 200:
#                     activation_data = {
#                         "id": record["id"],
#                         "username": record["username"],
#                         "password": record["password"],
#                         "processor_id": processor_id,
#                         "motherboard_id": motherboard_id
#                     }
#                     with open("activation.json", "w") as f:
#                         json.dump(activation_data, f)

#                     messagebox.showinfo("Success", "Activation successful.")
#                     root.destroy()
#                     os.startfile("y.exe")  # Launch main app
#                 else:
#                     messagebox.showerror("Error", "Failed to activate. API rejected the request.")
#             except Exception as e:
#                 messagebox.showerror("Error", f"Failed to activate: {e}")
#             return

#     messagebox.showerror("Error", "Invalid or expired key.")

# # GUI
# root = Tk()
# root.title("Activate VWAR")
# root.geometry("400x200")

# Label(root, text="Enter License Key:", font=("Arial", 12)).pack(pady=20)
# key_entry = Entry(root, width=30, font=("Arial", 12))
# key_entry.pack()

# Button(root, text="Activate", command=lambda: activate(key_entry.get()), bg="green", fg="white", font=("Arial", 12)).pack(pady=20)

# root.mainloop()




def activate(key):
    try:
        response = requests.get(API_GET)
        data = response.json().get("data", [])
    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch data: {e}")
        return

    for record in data:
        if record["password"] == key:
            current_processor = get_processor_info()
            current_motherboard = get_motherboard_info()

            server_processor = record.get("processor_id", "").strip()
            server_motherboard = record.get("motherboard_id", "").strip()

            # Case 1: Key is already used
            if server_processor and server_motherboard:
                if current_processor == server_processor and current_motherboard == server_motherboard:
                    # ✅ Re-activate on the same PC
                    activation_data = {
                        "id": record["id"],
                        "username": record["username"],
                        "password": record["password"],
                        "processor_id": current_processor,
                        "motherboard_id": current_motherboard
                    }
                    with open("activation.json", "w") as f:
                        json.dump(activation_data, f)
                    messagebox.showinfo("Info", "This system is already activated.")
                    root.destroy()
                    os.startfile("VWAR.exe")
                    return
                else:
                    # ❌ Used on another system
                    messagebox.showerror("Error", "This key is already used on another system.")
                    return

            # Case 2: Key not used yet — activate on this system
            payload = {
                "id": int(record["id"]),
                "processor_id": current_processor,
                "motherboard_id": current_motherboard
            }

            try:
                post_response = requests.post(API_POST, json=payload)
                if post_response.status_code == 200:
                    activation_data = {
                        "id": record["id"],
                        "username": record["username"],
                        "password": record["password"],
                        "processor_id": current_processor,
                        "motherboard_id": current_motherboard
                    }
                    with open("activation.json", "w") as f:
                        json.dump(activation_data, f)

                    messagebox.showinfo("Success", "Activation successful.")
                    root.destroy()
                    os.startfile("VWAR.exe")
                else:
                    messagebox.showerror("Error", "Failed to activate. API rejected the request.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to activate: {e}")
            return

    messagebox.showerror("Error", "Invalid or expired key.")


# GUI
root = Tk()
root.title("Activate VWAR")
root.geometry("400x200")

Label(root, text="Enter License Key:", font=("Arial", 12)).pack(pady=20)
key_entry = Entry(root, width=30, font=("Arial", 12))
key_entry.pack()

Button(root, text="Activate", command=lambda: activate(key_entry.get()), bg="green", fg="white", font=("Arial", 12)).pack(pady=20)

root.mainloop()