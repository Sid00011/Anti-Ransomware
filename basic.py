from pathlib import Path
from tkinter import ttk, messagebox, filedialog
import datetime
import queue
import tkinter as tk
import pygame
import psutil
from prettytable import PrettyTable
import time
import pickle
import pefile
import sys
import array
import joblib
import math
import os
import hashlib
import shutil
import ctypes
import subprocess
import re



#  WATCHDOG CODE FOR DETECTION
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from watchdog.events import (
    EVENT_TYPE_CREATED,
    EVENT_TYPE_DELETED,
    EVENT_TYPE_MODIFIED,
    EVENT_TYPE_MOVED
)

#global variables
directory = 'C:\\'
file_paths = []  # To store file paths for scanning
q = queue.Queue()
observer = None  # To hold the Watchdog observer instance
hash_algos = ["md5", "sha1", "sha256"]
# hash_file_path = "C://ANTI-RANSOMWARE//hashes.txt"
hash_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hashes.txt")
safe_programs = ["explorer.exe", "System Idle Process", "System"]
cpu_threshold = 15
memory_threshold = 15
modtree = None  # Declare the variable

# Scan files and update Treeview
selected_directory = None
def choose_directory():
    global selected_directory
    selected_directory = filedialog.askdirectory()  # Open directory selection dialog

    if selected_directory:
        directory_label.config(text=f"Directory Selected: {selected_directory}")
    else:
        directory_label.config(text="No directory selected")

def on_tab_change(event):
    """Hide the directory label on non-scanning tabs."""
    selected_tab = notebook.index(notebook.select())
    if selected_tab != 0:  # 0 is for the "File Scanning" tab
        directory_label.pack_forget()  # Hide label
    else:
        directory_label.pack(pady=10)  # Show label


def scan_files(treeview):
    """Scan files in the selected directory and update the Treeview."""
    global selected_directory
    if not selected_directory:
        messagebox.showwarning("No Directory Selected", "Please select a directory to scan.")
        return

    ransomware_dict = set(ransomware_dictionary)  # Optimize lookup for extensions

    for root, dirs, files in os.walk(selected_directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                # Check if the file matches any ransomware extension
                if any(file.lower().endswith(ext) for ext in ransomware_dict):
                    treeview.insert("", 0, values=(file, "Flagged", "Ransomware-likely filename"), tags=("flagged",))
                    continue

                # Attempt to scan for PE file details
                data = extract_infos(file_path)
                if data:
                    features_list = list(map(lambda x: data.get(x, 0), features))
                    result = "Malicious" if clf.predict([features_list])[0] == 0 else "Legitimate"
                    reason = "PE file flagged as highly likely ransomware" if result == "Malicious" else "Legitimate"
                    treeview.insert("", 0, values=(file, "Scanned", reason), tags=("malicious" if result == "Malicious" else "legitimate",))
                else:
                    treeview.insert("", 0, values=(file, "Skipped", "Not a PE file"))
            except Exception as e:
                treeview.insert("", 0, values=(file, "Error", str(e)))

    attach_context_menu(treeview)

# def attach_context_menu(treeview):
#     """Attach a context menu for quarantine and delete actions."""
#     menu = tk.Menu(treeview, tearoff=0)

#     def quarantine_action():
#         selected_item = treeview.selection()
#         if selected_item:
#             file_name = treeview.item(selected_item, "values")[0]
#             file_path = os.path.join(directory, file_name)
#             confirm = messagebox.askyesno("Confirm Quarantine", f"Do you want to quarantine the file {file_name}?")
#             if confirm:
#                 quarantine_dir = os.path.join(directory, "Quarantine")
#                 os.makedirs(quarantine_dir, exist_ok=True)
#                 shutil.move(file_path, os.path.join(quarantine_dir, file_name))
#                 messagebox.showinfo("Quarantine", f"File {file_name} has been quarantined.")
#                 treeview.item(selected_item, values=(file_name, "Quarantined", "Action taken"))

#     def delete_action():
#         selected_item = treeview.selection()
#         if selected_item:
#             file_name = treeview.item(selected_item, "values")[0]
#             file_path = os.path.join(directory, file_name)
#             confirm = messagebox.askyesno("Confirm Delete", f"Do you want to delete the file {file_name}?")
#             if confirm:
#                 os.remove(file_path)
#                 messagebox.showinfo("Delete", f"File {file_name} has been deleted.")
#                 treeview.delete(selected_item)

#     # Add options to the context menu
#     menu.add_command(label="Quarantine", command=quarantine_action)
#     menu.add_command(label="Delete", command=delete_action)

#     # Bind the right-click event to the Treeview
#     def show_context_menu(event):
#         if treeview.identify_row(event.y):  # Check if a row is clicked
#             treeview.selection_set(treeview.identify_row(event.y))  # Select the clicked row
#             menu.post(event.x_root, event.y_root)

#     treeview.bind("<Button-3>", show_context_menu)




def attach_context_menu(treeview):
    """Attach a context menu for quarantine and delete actions."""
    menu = tk.Menu(treeview, tearoff=0)

    def quarantine_action():
        selected_item = treeview.selection()
        if selected_item:
            file_name = treeview.item(selected_item, "values")[0]
            # Use selected_directory instead of directory
            file_path = os.path.join(selected_directory, file_name)
            confirm = messagebox.askyesno("Confirm Quarantine", f"Do you want to quarantine the file {file_name}?")
            if confirm:
                quarantine_dir = os.path.join(selected_directory, "Quarantine")
                os.makedirs(quarantine_dir, exist_ok=True)
                shutil.move(file_path, os.path.join(quarantine_dir, file_name))
                messagebox.showinfo("Quarantine", f"File {file_name} has been quarantined.")
                treeview.item(selected_item, values=(file_name, "Quarantined", "Action taken"))

    def delete_action():
        selected_item = treeview.selection()
        if selected_item:
            file_name = treeview.item(selected_item, "values")[0]
            # Use selected_directory instead of directory
            file_path = os.path.join(selected_directory, file_name)
            confirm = messagebox.askyesno("Confirm Delete", f"Do you want to delete the file {file_name}?")
            if confirm:
                os.remove(file_path)
                messagebox.showinfo("Delete", f"File {file_name} has been deleted.")
                treeview.delete(selected_item)

    # Add options to the context menu
    menu.add_command(label="Quarantine", command=quarantine_action)
    menu.add_command(label="Delete", command=delete_action)

    # Bind the right-click event to the Treeview
    def show_context_menu(event):
        if treeview.identify_row(event.y):  # Check if a row is clicked
            treeview.selection_set(treeview.identify_row(event.y))  # Select the clicked row
            menu.post(event.x_root, event.y_root)

    treeview.bind("<Button-3>", show_context_menu)





# Function to detect and delete malware based on hashes
def detect_and_delete_malware(treeview):
    """Allow user to choose a directory and detect malware within that directory."""
    # Let the user choose a directory
    selected_directory = filedialog.askdirectory(title="Select Directory for Malware Detection")
    if not selected_directory:
        messagebox.showwarning("No Directory Selected", "Please select a directory to proceed.")
        return

    # Clear the Treeview before adding new results
    for item in treeview.get_children():
        treeview.delete(item)

    # Detect malware in the selected directory
    for root, dirs, files in os.walk(selected_directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "rb") as f:
                    file_content = f.read()  # Read the entire file content
                    file_hashes = [hashlib.new(algo, file_content).hexdigest() for algo in hash_algos]

                if any(file_hash in malware_hashes for file_hash in file_hashes):
                    os.remove(file_path)
                    treeview.insert("", 0, values=(file, "Deleted", "Malware Detected"))
                else:
                    treeview.insert("", 0, values=(file, "Safe", "No Malware"))
            except Exception as e:
                treeview.insert("", 0, values=(file, "Error", str(e)))

    messagebox.showinfo("Detection Complete", "Malware detection process has completed.")




def stop_monitoring():
    """Stop real-time directory monitoring."""
    global observer
    if observer and observer.is_alive():
        observer.stop()
        observer.join()  # Ensure the observer thread has fully stopped
        observer = None
    monitor_status_label.config(text="Monitoring Status: Inactive", foreground="red")
# Function to start monitoring
# def start_monitoring_ui(treeview):
#     global observer, monitor_status_label
#     observer = Observer()
#     observer.schedule(MyEventHandler(q,root), directory, recursive=True)
#     observer.start()
#     monitor_status_label.config(text="Monitoring Status: Active", foreground="green")
#     root.after(2000, process_events_ui, observer, q, treeview)


def start_monitoring_ui(treeview):
    global observer, monitor_status_label, selected_directory
    if not selected_directory:
        messagebox.showerror("Error", "No directory selected!")
        return  # Stop further execution if no directory is selected

    if not os.path.isdir(selected_directory):
        messagebox.showerror("Error", "Invalid directory!")
        return  # Stop execution if the selected directory is invalid

    observer = Observer()
    observer.schedule(MyEventHandler(q, root), selected_directory, recursive=True)
    observer.start()
    monitor_status_label.config(text="Monitoring Status: Active", foreground="green")
    root.after(2000, process_events_ui, observer, q, treeview)




# Process Events for UI
def process_events_ui(observer, q, treeview):
    """Process events with updated treeview."""
    if not observer.is_alive():
        return

    try:
        while not q.empty():
            file_name, action, timestamp, process = q.get_nowait()
            treeview.insert("", 0, values=(file_name, action, timestamp, process))
    except queue.Empty:
        pass

    root.after(2000, process_events_ui, observer, q, treeview)




# Create a list of file extensions to watch
ransomware_dictionary = [".encrypt", ".cry", ".crypto", ".darkness", ".enc" , ".exx", ".kb15", ".kraken", ".locked", ".nochance", ".___xratteamLucked", ".__AiraCropEncrypted!",
  "._AiraCropEncrypted", "._read_thi$_file" , ".02", ".0x0", ".725", ".1btc", ".1999", ".1cbu1", ".1txt", ".2ed2", ".31392E30362E32303136_[ID-KEY]_LSBJ1", ".73i87A",
  ".726", ".777", ".7h9r", ".7z.encrypted", ".7zipper", ".8c7f", ".8lock8", ".911", ".a19", ".a5zfn", ".aaa" , ".abc" , ".adk", ".adr", ".adair", ".AES", ".aes128ctr",
  ".AES256" , ".aes_ni", ".aes_ni_gov", ".aes_ni_0day" , ".AESIR", ".AFD", ".aga", ".alcatraz", ".Aleta", ".amba", ".amnesia", ".angelamerkel", ".AngleWare", ".antihacker2017",
  ".animus", ".ap19", ".atlas", ".aurora", ".axx", ".B6E1", ".BarRax", ".barracuda", ".bart", ".bart.zip", ".better_call_saul", ".bip", ".birbb", ".bitstak", ".bitkangoroo",
  ".boom", ".black007", ".bleep", ".bleepYourFiles" , ".bloc", ".blocatto", ".block", ".braincrypt", ".breaking_bad", ".bript", ".brrr", ".btc", ".btcbtcbtc", ".btc-help-you",
  ".cancer", ".canihelpyou", ".cbf", ".ccc", ".CCCRRRPPP", ".cerber", ".cerber2", ".cerber3", ".checkdiskenced", ".chifrator@qq_com", ".CHIP" , ".cifgksaffsfyghd", ".clf",
  ".clop", ".cnc", ".cobain", ".code", ".coded", ".comrade", ".coverton", ".crashed", ".crime", ".crinf", ".criptiko" , ".crypton", ".criptokod" , ".cripttt" , ".crjoker",
  ".crptrgr", ".CRRRT" , ".cry", ".cry_", ".cryp1" , ".crypt", ".crypt38", ".crypted", ".cryptes", ".crypted_file", ".crypto", ".cryptolocker", ".CRYPTOSHIEL", ".CRYPTOSHIELD",
  ".CryptoTorLocker2015!", ".cryptowall", ".cryptowin", ".crypz", ".CrySiS", ".css", ".ctb2", ".ctbl", ".CTBL", ".czvxce", ".d4nk", ".da_vinci_code", ".dale", ".damage",
  ".darkness" , ".darkcry", ".dCrypt", ".decrypt2017", ".ded", ".deria", ".desu", ".dharma", ".disappeared", ".diablo6", ".divine", ".dll", ".doubleoffset", ".domino",
  ".doomed", ".dxxd", ".dyatel@qq_com", ".ecc", ".edgel", ".enc", ".encedRSA", ".EnCiPhErEd", ".encmywork", ".encoderpass", ".ENCR", ".encrypted", ".EnCrYpTeD", ".encryptedAES",
  ".encryptedRSA", ".encryptedyourfiles", ".enigma", ".epic", ".evillock", ".exotic", ".exte", ".exx", ".ezz", ".fantom", ".fear", ".FenixIloveyou!!", ".file0locked",
  ".filegofprencrp", ".fileiscryptedhard", ".filock", ".firecrypt", ".flyper", ".frtrss", ".fs0ciety", ".fuck", ".Fuck_You", ".fucked", ".FuckYourData" , ".fun",
  ".flamingo", ".gamma", ".gefickt", ".gembok", ".globe", ".glutton", ".goforhelp", ".good", ".gruzin@qq_com" , ".gryphon", ".grinch", ".GSupport" , ".GWS", ".HA3",
  ".hairullah@inbox.lv", ".hakunamatata", ".hannah", ".haters", ".happyday" ," .happydayzz", ".happydayzzz", ".hb15", ".helpdecrypt@ukr .net", ".helpmeencedfiles",
  ".herbst", ".hendrix", ".hermes", ".help", ".hnumkhotep", ".hitler", ".howcanihelpusir", ".html", ".homer", ".hush", ".hydracrypt" , ".iaufkakfhsaraf", ".ifuckedyou",
  ".iloveworld", ".infected", ".info", ".invaded", ".isis" , ".ipYgh", ".iwanthelpuuu", ".jaff", ".java", ".JUST", ".justbtcwillhelpyou", ".JLQUF", ".jnec", ".karma",
  ".kb15", ".kencf", ".keepcalm", ".kernel_complete", ".kernel_pid", ".kernel_time", ".keybtc@inbox_com", ".KEYH0LES", ".KEYZ" , "keemail.me", ".killedXXX", ".kirked",
  ".kimcilware", ".KKK" , ".kk", ".korrektor", ".kostya", ".kr3", ".krab", ".kraken", ".kratos", ".kyra", ".L0CKED", ".L0cked", ".lambda_l0cked", ".LeChiffre", ".legion",
  ".lesli", ".letmetrydecfiles", ".letmetrydecfiles", ".like", ".lock", ".lock93", ".locked", ".Locked-by-Mafia", ".locked-mafiaware", ".locklock", ".locky", ".LOL!", ".loprt",
  ".lovewindows", ".lukitus", ".madebyadam", ".magic", ".maktub", ".malki", ".maya", ".merry", ".micro", ".MRCR1", ".muuq", ".MTXLOCK", ".nalog@qq_com", ".nemo-hacks.at.sigaint.org",
  ".nobad", ".no_more_ransom", ".nochance" , ".nolvalid", ".noproblemwedecfiles", ".notfoundrans", ".NotStonks", ".nuclear55", "nuclear", ".obleep", ".odcodc", ".odin", ".oled",
  ".OMG!", ".only-we_can-help_you", ".onion.to._", ".oops", ".openforyou@india.com", ".oplata@qq.com" , ".oshit", ".osiris", ".otherinformation", ".oxr", ".p5tkjw", ".pablukcrypt",
  ".padcrypt", ".paybtcs", ".paym", ".paymrss", ".payms", ".paymst", ".payransom", ".payrms", ".payrmts", ".pays", ".paytounlock", ".pdcr", ".PEGS1", ".perl", ".pizda@qq_com",
  ".PoAr2w", ".porno", ".potato", ".powerfulldecrypt", ".powned"," .pr0tect", ".purge", ".pzdc", ".R.i.P", ".r16m" , ".R16M01D05", ".r3store", ".R4A" , ".R5A", ".r5a", ".RAD" ,
  ".RADAMANT", ".raid10",".ransomware", ".RARE1", ".rastakhiz", ".razy", ".RDM", ".rdmk", ".realfs0ciety@sigaint.org.fs0ciety", ".recry1", ".rekt", ".relock@qq_com", ".reyptson",
  ".remind", ".rip", ".RMCM1", ".rmd", ".rnsmwr", ".rokku", ".rrk", ".RSNSlocked" , ".RSplited", ".sage", ".salsa222", ".sanction", ".scl", ".SecureCrypted", ".serpent", ".sexy",
  ".shino", ".shit", ".sifreli", ".Silent", ".sport", ".stn", ".supercrypt", ".surprise", ".szf", ".t5019", ".tedcrypt", ".TheTrumpLockerf", ".thda", ".TheTrumpLockerfp",
  ".theworldisyours", ".thor", ".toxcrypt", ".troyancoder@qq_com", ".trun", ".trmt", ".ttt", ".tzu", ".uk-dealer@sigaint.org", ".unavailable", ".vault", ".vbransom", ".vekanhelpu",
  ".velikasrbija", ".venusf", ".Venusp", ".versiegelt", ".VforVendetta", ".vindows", ".viki", ".visioncrypt", ".vvv", ".vxLock", ".wallet", ".wcry", ".weareyourfriends", ".weencedufiles",
  ".wflx", ".wlu", ".Where_my_files.txt", ".Whereisyourfiles", ".windows10", ".wnx", ".WNCRY", ".wncryt", ".wnry", ".wowreadfordecryp", ".wowwhereismyfiles", ".wuciwug", ".www", ".xiaoba",
  ".xcri", ".xdata", ".xort", ".xrnt", ".xrtn", ".xtbl", ".xyz", ".ya.ru", ".yourransom", ".Z81928819", ".zc3791", ".zcrypt", ".zendr4", ".zepto", ".zorro", ".zXz", ".zyklon", ".zzz" ,
  ".zzzzz"]

def start_monitoring():
    if not selected_directory:
        messagebox.showerror("Error", "No directory selected!")
        return
    if not os.path.isdir(selected_directory):
        messagebox.showerror("Error", "Invalid directory!")
        return
    # Replace this with your monitoring logic
    messagebox.showinfo("Monitoring", f"Started monitoring: {selected_directory}")
    print(f"Monitoring {selected_directory}")

def open_scan_window():
    scan_window = tk.Toplevel(root)
    scan_window.title("File Scanning")
    scan_window.geometry("600x400")
    scan_window.configure(bg="#f0f0f0")

    ttk.Label(scan_window, text="File Scanning", font=("Helvetica", 14, "bold")).pack(pady=10)
    scan_tree = ttk.Treeview(scan_window, columns=("File", "Status", "Result"), show="headings", height=15)
    scan_tree.heading("File", text="File")
    scan_tree.heading("Status", text="Status")
    scan_tree.heading("Result", text="Result")
    scan_tree.pack(fill=tk.BOTH, expand=True)
    ttk.Button(scan_window, text="Start Scan", command=lambda: scan_files(scan_tree)).pack(pady=10)

def open_monitor_window():
    monitor_window = tk.Toplevel(root)
    monitor_window.title("Real-time Monitoring")
    monitor_window.geometry("800x600")

    notebook = ttk.Notebook(monitor_window)
    notebook.pack(fill=tk.BOTH, expand=True)

    # Tab 1: File Events
    file_tab = ttk.Frame(notebook)
    notebook.add(file_tab, text="File Events")

    global monitor_status_label
    monitor_status_label = ttk.Label(file_tab, text="Monitoring Status: Inactive", font=("Helvetica", 12))
    monitor_status_label.pack(pady=5)

    monitor_tree = ttk.Treeview(file_tab, columns=("File", "Action", "Time","Process"), show="headings", height=15)
    monitor_tree.heading("File", text="File")
    monitor_tree.heading("Action", text="Action")
    monitor_tree.heading("Time", text="Time")
    monitor_tree.heading("Process", text="Process")
    monitor_tree.pack(fill=tk.BOTH, expand=True)

    button_frame = ttk.Frame(file_tab)
    button_frame.pack(fill=tk.X)
    ttk.Button(button_frame, text="Start Monitoring", command=lambda: start_monitoring_ui(monitor_tree)).pack(side=tk.LEFT, padx=5, pady=5)
    ttk.Button(button_frame, text="Stop Monitoring", command=stop_monitoring).pack(side=tk.LEFT, padx=5, pady=5)

    # Tab 2: Suspicious Processes
    process_tab = ttk.Frame(notebook)
    notebook.add(process_tab, text="Suspicious Processes")

    process_tree = ttk.Treeview(process_tab, columns=("PID", "Name", "CPU Usage", "Memory Usage", "Reason"),
                                show="headings", height=15)
    process_tree.heading("PID", text="PID")
    process_tree.heading("Name", text="Name")
    process_tree.heading("CPU Usage", text="CPU Usage")
    process_tree.heading("Memory Usage", text="Memory Usage")
    process_tree.heading("Reason", text="Reason")
    process_tree.pack(fill=tk.BOTH, expand=True)

    ttk.Label(process_tab, text="Suspicious Processes will appear here", font=("Helvetica", 12)).pack(pady=5)
    ttk.Button(process_tab, text="Check Suspicious Processes",
               command=lambda: display_suspicious_processes(process_tree, directory, safe_programs)).pack(pady=10)

def display_suspicious_processes(process_tree, monitored_directory, safe_programs):
    """
    Fetch and display suspicious processes in the Treeview.

    Args:
        process_tree (ttk.Treeview): The Treeview to update.
        monitored_directory (str): Directory to monitor for suspicious processes.
        safe_programs (list): List of safe programs to exclude.
    """
    # Clear the existing entries
    for item in process_tree.get_children():
        process_tree.delete(item)

    # Check for suspicious processes
    try:
        suspicious_processes = check_suspicious_processes(
            directory=monitored_directory,
            safe_programs=safe_programs,
            cpu_threshold=15,
            memory_threshold=15
        )
        # Populate the Treeview
        for process in suspicious_processes:
            process_tree.insert("", "end", values=(
                process['pid'],
                process['name'],
                f"{process['cpu_percent']}%",
                f"{process['memory_percent']}%",
                process['reason']
            ))
    except Exception as e:
        print(f"Error displaying suspicious processes: {e}")

def open_detect_malware_window():
    detect_window = tk.Toplevel(root)
    detect_window.title("Detect and Delete Malware")
    detect_window.geometry("600x400")
    detect_window.configure(bg="#f0f0f0")

    ttk.Label(detect_window, text="Malware Detection", font=("Helvetica", 14, "bold")).pack(pady=10)
    detect_tree = ttk.Treeview(detect_window, columns=("File", "Status", "Result"), show="headings", height=15)
    detect_tree.heading("File", text="File")
    detect_tree.heading("Status", text="Status")
    detect_tree.heading("Result", text="Result")
    detect_tree.pack(fill=tk.BOTH, expand=True)
    ttk.Button(detect_window, text="Detect Malware", command=lambda: detect_and_delete_malware(detect_tree)).pack(pady=10)

# def start_monitoring_ui(treeview):
#     """Start monitoring with UI updates."""
#     global observer, monitor_status_label
#     observer = Observer()
#     # observer.schedule(MyEventHandler(q,root), directory, recursive=True)
#     observer.schedule(MyEventHandler(q, root), selected_directory, recursive=True)
#     observer.start()
#     monitor_status_label.config(text="Monitoring Status: Active", foreground="green")
#     root.after(2000, process_events_ui, observer, q, treeview)


def start_monitoring_ui(treeview):
    """Start monitoring with UI updates."""
    global observer, monitor_status_label, selected_directory

    # Check if the directory is selected
    if not selected_directory:
        messagebox.showerror("Error", "No directory selected!")
        return

    # Check if the directory exists
    if not os.path.isdir(selected_directory):
        messagebox.showerror("Error", f"The directory '{selected_directory}' does not exist!")
        return

    # Initialize and start the observer
    observer = Observer()
    observer.schedule(MyEventHandler(q, root), selected_directory, recursive=True)
    observer.start()

    monitor_status_label.config(text="Monitoring Status: Active", foreground="green")
    root.after(2000, process_events_ui, observer, q, treeview)



def process_events_ui(observer, q, treeview):
    """Process events with updated treeview."""
    if not observer.is_alive():
        return

    try:
        while not q.empty():
            file_name, action, timestamp, process = q.get_nowait()  # Now unpack 4 values
            treeview.insert("", 0, values=(file_name, action, timestamp, process))
    except queue.Empty:
        pass

    root.after(2000, process_events_ui, observer, q, treeview)


class MyEventHandler(FileSystemEventHandler):
    # def __init__(self, q):
    #     """Initialize with a reference to the event queue."""
    #     self._q = q
    #     super().__init__()
    def __init__(self, q, root):
        """Initialize with a reference to the event queue and Tkinter root window."""
        self._q = q
        self.root = root
        self.treeview = None
        super().__init__()

    # def get_responsible_process(file_path):
    #     """
    #     Find the process responsible for accessing a file.
    #     """
    #     process_name = "Unknown"
    #     try:
    #         for proc in psutil.process_iter(attrs=['pid', 'name']):
    #             try:
    #                 # Check open files for the process
    #                 open_files = proc.open_files() if hasattr(proc, 'open_files') else []
    #                 if any(file_path == file.path for file in open_files):
    #                     return proc.info['name']
    #             except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
    #                 continue

    #         # Check if the file is being accessed by a system process
    #         if os.name == 'nt':  # Windows-specific implementation
    #             file_handle = ctypes.windll.kernel32.CreateFileW(
    #                 file_path,
    #                 0,  # No access
    #                 7,  # Share mode
    #                 None,
    #                 3,  # Open existing
    #                 0,
    #                 None
    #             )
    #             if file_handle != -1:  # File handle obtained
    #                 process_name = "System"
    #                 ctypes.windll.kernel32.CloseHandle(file_handle)
    #     except Exception as e:
    #         print(f"Error finding responsible process: {e}")

    #     return process_name
    def get_responsible_process(self, file_path):
        """
        Find the process responsible for accessing a file using Sysinternals Handle.
        """
        process_name = "Unknown"
        try:
            # Run handle.exe with the target file path
            result = subprocess.run(
                ['handle.exe', file_path],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:  # Command executed successfully
                output_lines = result.stdout.strip().split('\n')
                
                # Search for processes accessing the file
                for line in output_lines:
                    match = re.search(r'pid: (\d+) *\w+: (.+)', line)
                    if match:
                        process_id = match.group(1)
                        process_name = match.group(2)
                        break  # Stop after finding the first process
            else:
                print(f"Handle error: {result.stderr.strip()}")
        except Exception as e:
            print(f"Error finding responsible process: {e}")

        return process_name

    def on_any_event(self, event):
        """
        Handle any file system event.
        """
        # Map event types to user-friendly actions
        action = {
            EVENT_TYPE_CREATED: "Created",
            EVENT_TYPE_DELETED: "Deleted",
            EVENT_TYPE_MODIFIED: "Modified",
            EVENT_TYPE_MOVED: "Moved",
        }.get(event.event_type, "Unknown")

        process_name = "Unknown"
        # process_name = self.get_responsible_process(event.src_path)
        try:
            # Get the process responsible for the event
            for proc in psutil.process_iter(attrs=['pid', 'name']):
                open_files = proc.open_files() if hasattr(proc, 'open_files') else []
                if any(event.src_path in file.path for file in open_files):
                    process_name = proc.info['name']
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        # Append destination path for moved events
        if event.event_type == EVENT_TYPE_MOVED and hasattr(event, 'dest_path'):
            action += f" to {event.dest_path}"

        # Detect suspicious processes
        suspicious_processes = self.check_suspicious_processes()
        self.display_suspicious_processes(suspicious_processes)

        # Queue the event for processing in the main thread 
        self._q.put((
            Path(event.src_path).name,  # File name
            action,  # Action performed
            datetime.datetime.now().strftime("%H:%M:%S"),  # Timestamp
            process_name  # Responsible process
        ))

    def trigger_alarm(self):
        """Play an alarm sound to notify the user."""
        try:
            pygame.mixer.init()
            alarm_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "python version_detection_alarm.mp3")
            pygame.mixer.music.load(alarm_file_path)
            # pygame.mixer.music.load('C://ANTI-RANSOMWARE//python version_detection_alarm.mp3')
            pygame.mixer.music.play()
        except Exception as e:
            print(f"Error playing alarm: {e}")

    def check_suspicious_processes(self):
        """
        Check for suspicious processes and provide reasons for suspicion.
        """
        suspicious = []
        try:
            for process in psutil.process_iter(
                    attrs=['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'num_threads']):
                try:
                    info = process.info
                    reasons = []

                    # Skip safe programs by name
                    if info['name'] in safe_programs:
                        continue

                    # Check CPU and memory usage
                    if info['cpu_percent'] > cpu_threshold:
                        reasons.append("High CPU usage")
                    if info['memory_percent'] > memory_threshold:
                        reasons.append("High memory usage")

                    # Check for unusual states
                    if info['status'] not in ['running', 'sleeping']:
                        reasons.append(f"Unusual status: {info['status']}")
                    if info['num_threads'] > 50:
                        reasons.append("Excessive thread count")

                    # Append reasons if suspicious
                    if reasons:
                        info['reason'] = ", ".join(reasons)
                        suspicious.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except psutil.Error:
            pass

        return suspicious

    def create_treeview(self):
        """Create a Treeview widget for displaying suspicious processes."""
        if self.treeview is None:
            self.treeview = ttk.Treeview(self.root, columns=('PID', 'Name', 'CPU Usage', 'Memory Usage', 'Reason'), show='headings')
            self.treeview.heading('PID', text='PID')
            self.treeview.heading('Name', text='Name')
            self.treeview.heading('CPU Usage', text='CPU Usage')
            self.treeview.heading('Memory Usage', text='Memory Usage')
            self.treeview.heading('Reason', text='Reason')
            self.treeview.pack(expand=True, fill='both')

    def display_suspicious_processes(self, suspicious_processes):
        """
        Display suspicious processes in a Treeview UI.
        """
        if not suspicious_processes:
            return

        # Ensure the Treeview is created
        self.create_treeview()

        # Clear any previous entries in the treeview
        for row in self.treeview.get_children():
            self.treeview.delete(row)

        # Insert the new suspicious processes into the Treeview
        for process in suspicious_processes:
            self.treeview.insert("", "end", values=(
                process['pid'],
                process['name'],
                f"{process['cpu_percent']}%",
                f"{process['memory_percent']}%",
                process.get('reason', 'Unknown')
            ))

# Trusted directories for program files
trusted_directories = [
    "C:\\Windows",          # Windows system directory
    "C:\\Program Files",    # Default 64-bit program files
    "C:\\Program Files (x86)",  # Default 32-bit program files

]
 
def check_suspicious_processes(directory, safe_programs, cpu_threshold=10, memory_threshold=10, io_threshold=1024**2):
    """
    Check for suspicious processes and provide reasons for suspicion.

    Args:
        directory (str): Directory being monitored.
        safe_programs (list): List of trusted program names to exclude.
        cpu_threshold (float): CPU usage percentage threshold for suspicion.
        memory_threshold (float): Memory usage percentage threshold for suspicion.
        io_threshold (int): Disk I/O threshold in bytes (default: 1 MB).

    Returns:
        list: Information about suspicious processes and reasons for flagging.
    """
    
    suspicious = []
    try:
        for process in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'num_threads', 'exe', 'io_counters']):
            try:
                info = process.info
                reasons = []

                # Skip safe programs by name
                if info['name'] in safe_programs:
                    continue

                # Skip processes in trusted directories
                exe_path = info.get('exe', '')
                if exe_path and any(exe_path.startswith(trusted_dir) for trusted_dir in trusted_directories):
                    continue

                # Check CPU and memory usage
                if info['cpu_percent'] > cpu_threshold:
                    reasons.append("High CPU usage")
                if info['memory_percent'] > memory_threshold:
                    reasons.append("High memory usage")

                # Check access to monitored directory
                open_files = process.open_files() if hasattr(process, 'open_files') else []
                if open_files and any(directory in file.path for file in open_files):
                    reasons.append("Interacting with monitored directory")

                # Check for unusual states or behaviors
                if info['status'] not in ['running', 'sleeping']:
                    reasons.append(f"Unusual status: {info['status']}")
                if info['num_threads'] > 50:
                    reasons.append("Excessive thread count")

                # Check disk I/O usage
                io_counters = info.get('io_counters')
                if io_counters:
                    total_io = io_counters.read_bytes + io_counters.write_bytes
                    if total_io > io_threshold:
                        reasons.append("High disk activity")

                # Append to suspicious list if any reason exists
                if reasons:
                    info['reason'] = ", ".join(reasons)
                    suspicious.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue  # Handle inaccessible processes gracefully
    except psutil.Error:
        pass  # Handle global psutil errors gracefully

    return suspicious


def process_events(observer, q, modtree):
    """Process file system events from the queue and update the UI."""
    if not observer.is_alive():
        return

    processed_events = []

    try:
        # Drain the queue
        while not q.empty():
            processed_events.append(q.get_nowait())
    except queue.Empty:
        pass

    for event in processed_events:
        file_name, action, timestamp = event
        modtree.insert("", 0, values=(file_name, action, timestamp))

    # Schedule the next call
    root.after(2000, process_events, observer, q, modtree)


#### ML CODE FOR DETECTION
def get_entropy(data):
    """Get entropy of file"""
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0] * 256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

    return entropy


def get_resources(pe):
    """Extract resources: [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(
                                    resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception:
            return resources
    return resources


def get_version_info(pe):
    """Return version information"""
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
        res['os'] = pe.VS_FIXEDFILEINFO.FileOS
        res['type'] = pe.VS_FIXEDFILEINFO.FileType
        res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
        res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
        res['signature'] = pe.VS_FIXEDFILEINFO.Signature
        res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res


def extract_infos(fpath):
    """Extract information about a file"""
    res = {}
    default_keys = [
        'Machine', 'SizeOfOptionalHeader', 'Characteristics',
        'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode',
        'SizeOfInitializedData', 'SizeOfUninitializedData', 'AddressOfEntryPoint',
        'BaseOfCode', 'BaseOfData', 'ImageBase', 'SectionAlignment',
        'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
        'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion',
        'MinorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum',
        'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve',
        'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit',
        'LoaderFlags', 'NumberOfRvaAndSizes', 'SectionsNb',
        'SectionsMeanEntropy', 'SectionsMinEntropy', 'SectionsMaxEntropy',
        'SectionsMeanRawsize', 'SectionsMinRawsize', 'SectionsMaxRawsize',
        'SectionsMeanVirtualsize', 'SectionsMinVirtualsize',
        'SectionMaxVirtualsize', 'ImportsNbDLL', 'ImportsNb',
        'ImportsNbOrdinal', 'ExportNb', 'ResourcesNb',
        'ResourcesMeanEntropy', 'ResourcesMinEntropy',
        'ResourcesMaxEntropy', 'ResourcesMeanSize',
        'ResourcesMinSize', 'ResourcesMaxSize',
        'LoadConfigurationSize', 'VersionInformationSize'
    ]

    # Initialize all keys with default values
    for key in default_keys:
        res[key] = 0  # Default value for missing attributes

    try:
        pe = pefile.PE(fpath)

        # Basic PE Header Information
        res['Machine'] = pe.FILE_HEADER.Machine
        res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        res['Characteristics'] = pe.FILE_HEADER.Characteristics
        res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        res['BaseOfData'] = getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0)
        res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
        res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
        res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
        res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

        # Sections
        res['SectionsNb'] = len(pe.sections)
        entropy = list(map(lambda x: x.get_entropy(), pe.sections))
        if entropy:
            res['SectionsMeanEntropy'] = sum(entropy) / len(entropy)
            res['SectionsMinEntropy'] = min(entropy)
            res['SectionsMaxEntropy'] = max(entropy)
        raw_sizes = list(map(lambda x: x.SizeOfRawData, pe.sections))
        if raw_sizes:
            res['SectionsMeanRawsize'] = sum(raw_sizes) / len(raw_sizes)
            res['SectionsMinRawsize'] = min(raw_sizes)
            res['SectionsMaxRawsize'] = max(raw_sizes)
        virtual_sizes = list(map(lambda x: x.Misc_VirtualSize, pe.sections))
        if virtual_sizes:
            res['SectionsMeanVirtualsize'] = sum(virtual_sizes) / len(virtual_sizes)
            res['SectionsMinVirtualsize'] = min(virtual_sizes)
            res['SectionMaxVirtualsize'] = max(virtual_sizes)

        # Imports
        try:
            res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
            res['ImportsNb'] = len(imports)
            res['ImportsNbOrdinal'] = len([imp for imp in imports if imp.name is None])
        except AttributeError:
            pass  # Imports not found

        # Exports
        try:
            res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except AttributeError:
            pass  # Exports not found

        # Resources
        resources = get_resources(pe)
        res['ResourcesNb'] = len(resources)
        if resources:
            entropy = [r[0] for r in resources]
            sizes = [r[1] for r in resources]
            res['ResourcesMeanEntropy'] = sum(entropy) / len(entropy)
            res['ResourcesMinEntropy'] = min(entropy)
            res['ResourcesMaxEntropy'] = max(entropy)
            res['ResourcesMeanSize'] = sum(sizes) / len(sizes)
            res['ResourcesMinSize'] = min(sizes)
            res['ResourcesMaxSize'] = max(sizes)

        # Load Configuration Size
        try:
            res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
        except AttributeError:
            pass  # Load configuration not found

        # Version Information Size
        try:
            version_infos = get_version_info(pe)
            res['VersionInformationSize'] = len(version_infos.keys())
        except AttributeError:
            pass  # Version information not found

    except pefile.PEFormatError:
        print(f"Skipping invalid PE file: {fpath}")
    except PermissionError:
        print(f"Skipping inaccessible file: {fpath}")
    except Exception as e:
        print(f"An error occurred while processing {fpath}: {e}")

    return res




# def flag_as_malware(pth):
#     # Warn the user that malware has been found
#     print("WARNING: Malware detected at {}".format(pth))

#     # Add the file to the system's list of known malware
#     malware_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "malware_database.txt")
#     with open(malware_db_path, 'a') as f:
#         f.write(f"{pth}\n")

#     # Prompt the user for confirmation before deleting the file
#     user_input = input("Do you want to delete this file? [y/n]")
#     if user_input.lower() == 'y':
#         # Delete the file
#         os.remove(file_path)
#         print("File deleted.")
#     else:
#         print("File not deleted.")

#variable global



# Load classifier and features
classifier_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "classifier", "svm_classifier.pkl")
features_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "classifier", "svm_features.pkl")

clf = joblib.load(classifier_path)
features = pickle.loads(open(features_path, 'rb').read())


malware_found = False

# Read malware hashes from the file
with open(hash_file_path, "r") as f:
    malware_hashes = [line.strip() for line in f]


# Iterate over all root directories in the drive
# for root, directories, files in os.walk(directory):
#   # Iterate over all files in the current root directory
#   for file in files:
#     # Get the full file path by joining the root and file name
#     file_path = os.path.join(root, file)
#     # Add the file path to the list
#     file_paths.append(file_path)

# Join the file paths into a single string separated by newlines
def replace_non_ascii_in_path(path):
    # Replace non-ASCII characters with their correct encoding
    return path.encode('utf-8').decode('ascii', errors='ignore')

# Join the file paths, replacing non-ASCII characters with ASCII ones
file_string = '\n'.join([replace_non_ascii_in_path(file) for file in file_paths])

# Save the file string to a text file
file_list_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "file_list.txt")
with open(file_list_path, 'w') as f:
    f.write(file_string)

# Load file string from text file
with open(file_list_path, 'r') as f:
    file_string = f.read()

# Split file string into a list of file paths
file_paths = file_string.split('\n')

# def initial_scan():
#     """Perform the initial scan when explicitly triggered."""
#     for pth in file_paths:
#         try:
#             data = extract_infos(pth)
#             if all(feature in data for feature in features):
#                 pe_features = list(map(lambda x: data.get(x, 0), features))
#                 res = clf.predict([pe_features])[0]
#                 print(f'The file {os.path.basename(pth)} is {["malicious", "legitimate"][res]}')
#                 if res == 0:  # `malicious` classification
#                     flag_as_malware(pth)
#             else:
#                 print(f"Skipping file due to missing features: {pth}")
#         except Exception as e:
#             print(f"An error occurred while analyzing file {pth}: {e}")




# UI
root = tk.Tk()
root.title("Basic Shield: Anti-Ransomware Solution")
root.geometry("1024x768")
root.configure(bg="#1e1e2f")

# Header Label
header_frame = ttk.Frame(root, padding="10")
header_frame.pack(fill=tk.X)
header_label = ttk.Label(
    header_frame,
    text="Basic Shield: Anti-Ransomware Solution",
    font=("Helvetica", 20, "bold"),
    anchor="center"
)
header_label.pack(pady=15)

# Notebook (Tabbed Interface)
notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
notebook.bind("<<NotebookTabChanged>>", on_tab_change)  # Bind tab change event

# Tab 1: Scanning
scan_tab = ttk.Frame(notebook)
notebook.add(scan_tab, text="File Scanning")

# Add widgets to scan_tab
scan_label = ttk.Label(scan_tab, text="Scan for Potential Ransomware", font=("Helvetica", 14))
scan_label.pack(pady=10)

# Create a frame for the buttons and place them at the top
button_frame = ttk.Frame(scan_tab)
button_frame.pack(pady=5, anchor="n")  # Keep the buttons at the top and centered

# Add the buttons to the frame
choose_dir_button = ttk.Button(button_frame, text="Choose Directory", command=choose_directory)
choose_dir_button.pack(side=tk.LEFT, padx=10)

scan_button = ttk.Button(button_frame, text="Start Scan", command=lambda: scan_files(scan_tree))
scan_button.pack(side=tk.LEFT, padx=10)

# Add the Treeview to display scan results
scan_tree = ttk.Treeview(
    scan_tab,
    columns=("File", "Status", "Result"),
    show="headings",
    height=15
)
scan_tree.heading("File", text="File")
scan_tree.heading("Status", text="Status")
scan_tree.heading("Result", text="Result")
scan_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Directory Path Label (only visible in the scanning tab)
directory_label = tk.Label(root, text="No directory selected", font=("Helvetica", 12))
directory_label.pack(pady=10)

# Tab 2: Real-Time Monitoring
# Tab 2: Real-Time Monitoring
monitor_tab = ttk.Frame(notebook)
notebook.add(monitor_tab, text="Real-Time Monitoring")

# Monitoring Status Label
monitor_status_label = ttk.Label(
    monitor_tab,
    text="Monitoring Status: Inactive",
    font=("Helvetica", 14),
    foreground="red"
)
monitor_status_label.pack(pady=10)

# Treeview for monitoring
monitor_tree = ttk.Treeview(
    monitor_tab,
    columns=("File", "Action", "Time", "Process"),
    show="headings",
    height=15
)
monitor_tree.heading("File", text="File")
monitor_tree.heading("Action", text="Action")
monitor_tree.heading("Time", text="Time")
monitor_tree.heading("Process", text="Process")
monitor_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Button Frame for Controls
monitor_button_frame = ttk.Frame(monitor_tab)
monitor_button_frame.pack(fill=tk.X, pady=10)

# Directory Selection Label
directory_label = ttk.Label(monitor_button_frame, text="No directory selected", anchor="w")
directory_label.pack(fill=tk.X, padx=10, side=tk.TOP)

# Choose Directory Button
choose_directory_button = ttk.Button(
    monitor_button_frame,
    text="Choose Directory",
    command=choose_directory
)
choose_directory_button.pack(side=tk.LEFT, padx=10)

# Start Monitoring Button
start_monitor_button = ttk.Button(
    monitor_button_frame,
    text="Start Monitoring",
    command=lambda: start_monitoring_ui(monitor_tree)
)
start_monitor_button.pack(side=tk.LEFT, padx=10)

# Stop Monitoring Button
stop_monitor_button = ttk.Button(monitor_button_frame, text="Stop Monitoring", command=stop_monitoring)
stop_monitor_button.pack(side=tk.LEFT, padx=10)


# Tab 3: Malware Detection
malware_tab = ttk.Frame(notebook)
notebook.add(malware_tab, text="Malware Detection")

malware_label = ttk.Label(malware_tab, text="Detect and Handle Malware", font=("Helvetica", 14))
malware_label.pack(pady=10)

malware_tree = ttk.Treeview(
    malware_tab,
    columns=("File", "Status", "Result"),
    show="headings",
    height=15
)
malware_tree.heading("File", text="File")
malware_tree.heading("Status", text="Status")
malware_tree.heading("Result", text="Result")
malware_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

detect_button = ttk.Button(malware_tab, text="Detect Malware", command=lambda: detect_and_delete_malware(malware_tree))
detect_button.pack(pady=15)

# Tab 4: Suspicious Processes
suspicious_tab = ttk.Frame(notebook)
notebook.add(suspicious_tab, text="Suspicious Processes")

suspicious_label = ttk.Label(suspicious_tab, text="Monitor Suspicious Processes", font=("Helvetica", 14))
suspicious_label.pack(pady=10)

suspicious_tree = ttk.Treeview(
    suspicious_tab,
    columns=("PID", "Name", "CPU Usage", "Memory Usage", "Reason"),
    show="headings",
    height=15
)
suspicious_tree.heading("PID", text="PID")
suspicious_tree.heading("Name", text="Name")
suspicious_tree.heading("CPU Usage", text="CPU Usage")
suspicious_tree.heading("Memory Usage", text="Memory Usage")
suspicious_tree.heading("Reason", text="Reason")
suspicious_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Button to Populate Suspicious Processes
ttk.Button(
    suspicious_tab,
    text="Fetch Suspicious Processes",
    command=lambda: display_suspicious_processes(suspicious_tree, directory, safe_programs)
).pack(pady=10)

# Footer Buttons
footer_frame = ttk.Frame(root, padding="10")
footer_frame.pack(fill=tk.X, side=tk.BOTTOM)

exit_button = ttk.Button(footer_frame, text="Exit", command=root.destroy)
exit_button.pack(side=tk.RIGHT, padx=10)

# Adjust the Notebook to avoid overlap
notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 50))  # Add bottom padding to leave space for footer.

# Style Configuration
style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", font=("Helvetica", 10), rowheight=25, background="#2e2e38", foreground="white", fieldbackground="#2e2e38")
style.configure("Treeview.Heading", font=("Helvetica", 12, "bold"), background="#3a3a4e", foreground="white")
style.configure("TButton", font=("Helvetica", 12, "bold"), padding=10, background="#3a3a4e", foreground="white")
style.map("TButton", background=[("active", "#50505a")])

# Run Application
root.mainloop()