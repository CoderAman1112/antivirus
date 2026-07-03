import customtkinter as ctk
import os
from yara_integration import YaraIntegration
from tkinter import filedialog
import threading
from virustotal_integration import ScanUrl
from hashlib_algo import Hashlib
from algorithm import Algorithm
import json

yi = YaraIntegration()
hash_algo = Hashlib()
scan_url = ScanUrl()
algo = Algorithm()

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Antivirus")
app.geometry("1290x720")
app.resizable(False, False)

cancel_scan = False

def cancelScan():
    global cancel_scan
    cancel_scan = True

def fullScan():
    global cancel_scan
    cancel_scan = False

    info_label1.place_forget()
    info_label2.place_forget()
    info_label3.place_forget()
    info_label4.place_forget()
    info_label5.place_forget()

    threat = 0
    threat_detected.configure(text=f"Threats detected: {threat}")
    for widget in term.winfo_children():
        widget.grid_forget()

    l1 = ctk.CTkLabel(term, text="Starting scan...", anchor="w", text_color="white")
    l1.pack(fill="x", padx=10, pady=0)

    cancel_btn.grid(row=0, column=0, padx=10, pady=5, sticky="e")
    
    for root, dirs, files in os.walk("C:\\"):
        if cancel_scan:
            l3 = ctk.CTkLabel(term, text="Scan stopped.", anchor="w")
            l3.pack(fill="x", padx=10, pady=0)
            term._parent_canvas.yview_moveto(1.0)
            cancel_btn.grid_forget()
            return
        
        for file in files:
            if cancel_scan:
                l3 = ctk.CTkLabel(term, text="Scan stopped.", anchor="w")
                l3.pack(fill="x", padx=10, pady=0)
                term._parent_canvas.yview_moveto(1.0)
                cancel_btn.grid_forget()
                return
        
            path = os.path.join(root, file)
            l2 = ctk.CTkLabel(term, text=path, anchor="w")
            l2.pack(fill="x", padx=10, pady=0)
            term._parent_canvas.yview_moveto(1.0)
            check_yara = yi.yaraApply(path)
            get_hash = hash_algo.get_file_hash(path)
            check_hash = hash_algo.check_file_hash(get_hash)
            
            if check_yara or check_hash:
                l4 = ctk.CTkLabel(term, text=f"Threat detected at: {path}", text_color="red", anchor="w")
                l4.pack(fill="x", padx=10, pady=0)
                threat += 1
                threat_detected.configure(text=f"Threats detected: {threat}")

    cancel_btn.grid_forget()
    if threat<=0:
        l1.configure(text="No virus detected in your system", text_color="white")
    
    # l1.configure(text="Scan Complete")

def selectFolder():
    selected_folder = filedialog.askdirectory(title="select a folder")
    if selected_folder:
        return selected_folder
    else:
        return None

def quickScan():

    info_label1.place_forget()
    info_label2.place_forget()
    info_label3.place_forget()
    info_label4.place_forget()
    info_label5.place_forget()

    def choose_folder():
        global cancel_scan
        cancel_scan = False

        threat = 0
        threat_detected.configure(text=f"Threats detected: {threat}")

        for widget in term.winfo_children():
            widget.grid_forget()

        folder = selectFolder()
        if folder:
            l1 = ctk.CTkLabel(term, text="Starting scan...", anchor="w", text_color="white")
            l1.pack(fill="x", padx=10, pady=0)

            cancel_btn.grid(row=0, column=0, padx=10, pady=5, sticky="e")

            for root, dirs, files in os.walk(folder):
                term.update()
                if cancel_scan:
                    l3 = ctk.CTkLabel(term, text="Scan stopped.", anchor="w")
                    l3.pack(fill="x", padx=10, pady=0)
                    term._parent_canvas.yview_moveto(1.0)
                    cancel_btn.grid_forget()
                    return
                
                for file in files:
                    term.update()
                    if cancel_scan:
                        l3 = ctk.CTkLabel(term, text="Scan stopped.", anchor="w")
                        l3.pack(fill="x", padx=10, pady=0)
                        term._parent_canvas.yview_moveto(1.0)
                        cancel_btn.grid_forget()
                        return
                    
                    path = os.path.join(root, file)
                    l2 = ctk.CTkLabel(term, text=path, anchor="w")
                    l2.pack(fill="x", padx=10, pady=0)
                    term._parent_canvas.yview_moveto(1.0)
                    check_yara = yi.yaraApply(path)
                    get_hash = hash_algo.get_file_hash(path)
                    check_hash = hash_algo.check_file_hash(get_hash)

                    if check_yara or check_hash:
                        l4 = ctk.CTkLabel(term, text=f"Threat detected at: {path}", text_color="red", anchor="w")
                        l4.pack(fill="x", padx=10, pady=0)
                        threat += 1
                        threat_detected.configure(text=f"Threats detected: {threat}")

            cancel_btn.grid_forget()
            if threat<=0:
                l1.configure(text="No virus detected in your system", text_color="white")

    choose_folder()

def scanUrl():
    url = url_entry.get().strip()
    url_scan_btn.configure(state="disabled")

    if url:
        l2 = ctk.CTkLabel(term, text="Starting scan...", anchor="w")
        l2.pack(fill="x", padx=10, pady=0)

        info_label1.place(x=150, y=5)
        info_label2.place(x=250, y=5)
        info_label3.place(x=350, y=5)
        info_label4.place(x=450, y=5)
        info_label5.place(x=550, y=5)
        
        analysis_id = scan_url.submit_url(url)

        if analysis_id is None:
            l2 = ctk.CTkLabel(term, text="Failed to submit URL. Please try again", anchor="w")
            l2.pack(fill="x", padx=10, pady=0)
            term._parent_canvas.yview_moveto(1.0)
            url_scan_btn.configure(state="normal")
            return

        result = scan_url.get_analysis(analysis_id)

        if result is None:
            l2 = ctk.CTkLabel(term, text="Failed to retrieve URL. Please try again", anchor="w")
            l2.pack(fill="x", padx=10, pady=0)
            term._parent_canvas.yview_moveto(1.0)
            url_scan_btn.configure(state="normal")
            return

        try:
            stats = result["data"]["attributes"]["stats"]

            info_label1.configure(text=f"Malicious: {stats.get('malicious', 0)}")
            info_label2.configure(text=f"Suspicious: {stats.get('suspicious', 0)}")
            info_label3.configure(text=f"Harmless: {stats.get('harmless', 0)}")
            info_label4.configure(text=f"Undetected: {stats.get('undetected', 0)}")
            info_label5.configure(text=f"Timeout: {stats.get('timeout', 0)}")

            l2 = ctk.CTkLabel(term, text="Scan complete. You can see the results just above the terminal", anchor="w")
            l2.pack(fill="x", padx=10, pady=0)
            term._parent_canvas.yview_moveto(1.0)
            url_scan_btn.configure(state="normal")
            
        except Exception as e:
            l2 = ctk.CTkLabel(term, text=f"An error occured: {e}\n Please try again or use a different URL", anchor="w")
            l2.pack(fill="x", padx=10, pady=0)
            term._parent_canvas.yview_moveto(1.0)
        
    url_scan_btn.configure(state="normal")

def alerts(alert):
    l4 = ctk.CTkLabel(term, text=alert, text_color="red", anchor="w")
    l4.pack(fill="x", padx=10, pady=0)
    term._parent_canvas.yview_moveto(1.0)

def scanVirus():
    global cancel_scan
    cancel_scan = False
    scan_virus_btn.configure(state="disabled")

    info_label1.place_forget()
    info_label2.place_forget()
    info_label3.place_forget()
    info_label4.place_forget()
    info_label5.place_forget()

    virus_chances = 0
    found_threat = 0
    threat_detected.configure(text=f"Threats detected: {found_threat}")

    alerts("Starting scan...")
    cancel_btn.grid(row=0, column=0, padx=10, pady=5, sticky="e")

    pws_check = algo.is_powershell_running()
    if pws_check:
        virus_chances += 1
        alerts("Powershell is running.")
    cmd_check = algo.is_cmd_running()
    if cmd_check:
        virus_chances += 1
        alerts("Command Prompt is running.")
    defender_check = algo.create_virus()
    if defender_check:
        virus_chances += 1
        alerts("Windows Defender is turned off, maybe")
        
    if virus_chances>=2:
        alerts("Malicious activity detected!")

    folder = selectFolder()

    if not folder:
        folder = selectFolder()

    for root, dirs, files in os.walk(folder):
        if cancel_scan:
            l3 = ctk.CTkLabel(term, text="Scan stopped.", anchor="w")
            l3.pack(fill="x", padx=10, pady=0)
            term._parent_canvas.yview_moveto(1.0)
            cancel_btn.grid_forget()
            scan_virus_btn.configure(state="normal")
            return
        
        for file in files:
            if cancel_scan:
                l3 = ctk.CTkLabel(term, text="Scan stopped.", anchor="w")
                l3.pack(fill="x", padx=10, pady=0)
                term._parent_canvas.yview_moveto(1.0)
                cancel_btn.grid_forget()
                scan_virus_btn.configure(state="normal")
                return
            
            path = os.path.join(root, file)
            check_suspicious = algo.imports_suspicious(path)
            get_hash = hash_algo.get_file_hash(path)
            check_hash = hash_algo.check_file_hash(get_hash)
            check_yara = yi.yaraApply(path)

            if (check_suspicious and check_yara) or (check_hash and check_yara):
                l4 = ctk.CTkLabel(term, text=f"Found suspicious file imported from {path}", text_color="red", anchor="w")
                l4.pack(fill="x", padx=10, pady=0)
                term._parent_canvas.yview_moveto(1.0)
                found_threat += 1
                threat_detected.configure(text=f"Threats detected: {found_threat}")

                with open("threat.json", "r") as threat:
                    data = json.load(threat)
                    file_name = os.path.basename(path)
                    data[file_name] = path
                    
                with open("threat.json", "w") as threat:
                    json.dump(data, threat, indent=4)

        if virus_chances>=2:
            l4 = ctk.CTkLabel(term, text="Suspicious Activity Detected!", text_color="red", anchor="w")
            l4.pack(fill="x", padx=10, pady=0)
            term._parent_canvas.yview_moveto(1.0)

            l4 = ctk.CTkLabel(term, text="Finding virus containing file...", text_color="white", anchor="w")
            l4.pack(fill="x", padx=10, pady=0)
            term._parent_canvas.yview_moveto(1.0)

            algo.find_virus()
        
    cancel_btn.grid_forget()
    scan_virus_btn.configure(state="normal")

def viewThreats():
    win = ctk.CTk()
    win.title("Detected Threats In Your Comuter")
    win.geometry("600x400")
    win.resizable(False, False)

    def removeFile(file_path):
        if os.path.exists(file_path):
            os.remove(file_path)
            btn1.grid_forget()
            frame1.grid_forget()
            label1.grid_forget()

            with open("threat.json", "r") as file:
                data = json.load(file)
                del data[os.path.basename(file_path)]
            
            with open("threat.json", "w") as file:
                json.dump(data, file, indent=4)
        else:
            return

    scrl = ctk.CTkScrollableFrame(win, height=400, width=600)
    scrl.pack()

    with open("threat.json", "r") as file:
        data =  json.load(file)
    
    for path in data:
        frame1 = ctk.CTkFrame(scrl, height=50, width=580,
                              fg_color="#3D3D3D", corner_radius=10,
                              border_width=1, border_color="#5F5F5F",
                              )

        label1 = ctk.CTkLabel(frame1, font=("bahnschrift", 12), text=data[path], anchor="w")

        btn1 = ctk.CTkButton(frame1, text="Remove",
                        height=25,
                        width=80,
                        fg_color="#21517E",
                        border_width=1,
                        border_color="#0793E4",
                        font=("bahnschrift", 14),
                        hover_color="#0E4481",
                        corner_radius=10,
                        command=lambda: removeFile(data[path])
                        )
        
        frame1.grid(padx=10, pady=2)
        label1.grid(sticky="w", padx=10, pady=2)
        btn1.grid(sticky="e", padx=10, pady=2)

    win.mainloop()

threat_detected = ctk.CTkLabel(app, font=("bahnschrift", 14), text="Threats detected: 0", anchor="w")
threat_detected.grid(row=0, column=0, padx=10, pady=5, sticky="w")

info_label1 = ctk.CTkLabel(app, font=("bahnschrift", 14), text="Malicious: 0", anchor="w")
info_label2 = ctk.CTkLabel(app, font=("bahnschrift", 14), text="Suspicious: 0", anchor="w")
info_label3 = ctk.CTkLabel(app, font=("bahnschrift", 14), text="Harmless: 0", anchor="w")
info_label4 = ctk.CTkLabel(app, font=("bahnschrift", 14), text="Undetected: 0", anchor="w")
info_label5 = ctk.CTkLabel(app, font=("bahnschrift", 14), text="Timeout: 0", anchor="w")


term = ctk.CTkScrollableFrame(app, height=350, width=1250, border_width=1, border_color="#2B2B2B")
term.grid(row=1, column=0, padx=10, pady=10)

cont1 = ctk.CTkFrame(app, fg_color="transparent", corner_radius=10, width=1270,
                     border_width=1, border_color="#2B2B2B")
cont1.grid(padx=10, pady=10)

scan_btn = ctk.CTkButton(cont1,
                         text="Full Scan",
                         height=40,
                        width=150,
                        fg_color="#0156B8",
                        border_width=1,
                        border_color="#1772C7",
                        font=("bahnschrift", 24),
                        hover_color="#063866",
                        corner_radius=10,
                        command=lambda: threading.Thread(target=fullScan, daemon=True).start()
                        )
scan_btn2 = ctk.CTkButton(cont1,
                         text="Quick Scan",
                         height=40,
                        width=150,
                        fg_color="#0156B8",
                        border_width=1,
                        border_color="#1772C7",
                        font=("bahnschrift", 24),
                        hover_color="#063866",
                        corner_radius=10,
                        command=quickScan
                        )

cancel_btn = ctk.CTkButton(app, text="Cancel Scan",
                         height=25,
                        width=80,
                        fg_color="#21517E",
                        border_width=1,
                        border_color="#0793E4",
                        font=("bahnschrift", 16),
                        hover_color="#0E4481",
                        corner_radius=10,
                        command=cancelScan)

scan_btn.grid(row=2, column=1, padx=50, pady=10)
scan_btn2.grid(row=2, column=2, padx=50, pady=10)

url_entry = ctk.CTkEntry(app, placeholder_text="Paste URL you want to scan...",
                         height=40, width=1270, border_width=1, border_color="#313131", text_color="#949494",
                         fg_color="#252525",
                         corner_radius=10,
                         font=("bahnschrift", 14))

url_scan_btn = ctk.CTkButton(app, text="Scan URL",
                        height=40,
                        width=150,
                        fg_color="#0156B8",
                        border_width=1,
                        border_color="#1772C7",
                        font=("bahnschrift", 24),
                        hover_color="#063866",
                        corner_radius=10,
                        command=lambda: threading.Thread(target=scanUrl, daemon=True).start()
                        )

url_entry.grid(row=3, column=0, padx=10, pady=5)
url_scan_btn.grid(row=4, column=0, padx=10, pady=5, sticky="e")

scan_virus_btn = ctk.CTkButton(cont1, text="Scan Virus",
                        height=40,
                        width=150,
                        fg_color="#0156B8",
                        border_width=1,
                        border_color="#1772C7",
                        font=("bahnschrift", 24),
                        hover_color="#063866",
                        corner_radius=10,
                        command=lambda: threading.Thread(target=scanVirus, daemon=True).start()
                        )
view_threats_btn = ctk.CTkButton(cont1, text="View Threats",
                        height=40,
                        width=150,
                        fg_color="#0156B8",
                        border_width=1,
                        border_color="#1772C7",
                        font=("bahnschrift", 24),
                        hover_color="#063866",
                        corner_radius=10,
                        command=lambda: threading.Thread(target=viewThreats, daemon=True).start()
                        )

scan_virus_btn.grid(row=2, column=3, padx=50, pady=10)
view_threats_btn.grid(row=2, column=4, padx=50, pady=10)

app.mainloop()