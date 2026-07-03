import psutil
import os
import json
import time
import pefile
import win32com.client
from hashlib_algo import Hashlib
from yara_integration import YaraIntegration

hash_algo = Hashlib()
yi = YaraIntegration()
virus_chances = 0

class Algorithm:
    def is_powershell_running(self):
        global virus_chances

        for process in psutil.process_iter(['name']):
            name = process.info.get('name')
            if name and name.lower() in ("powershell.exe", "pwsh.exe"):
                virus_chances += 1
                return True
            else:
                return False

    def is_cmd_running(self):
        global virus_chances

        for process in psutil.process_iter(['name']):
            name = process.info.get('name')
            if name and name.lower() == "cmd.exe":
                virus_chances += 1
                return True
            else:
                return False

    def imports_suspicious(self, file_path):
        libs = ["VirtualAlloc", "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "HeapAlloc", "MapViewOfFile", "CreateRemoteThread"]

        try:
            pe = pefile.PE(file_path)

            if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                return False

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode().lower()

                for imp in entry.imports:
                    if imp.name:
                        func = imp.name.decode()

                        for lib in libs:
                            if func == lib:
                                return True

        except Exception as e:
            print("Error:", e)
            return False

    def create_virus(self):
        folder = r"C:\Antivirus\virus"
        os.makedirs(folder, exist_ok=True)

        path = os.path.join(folder, "eicar.txt")
        try:
            if os.path.exists(path):
                print("Defender is turned off, maybe")
                global virus_chances
                virus_chances += 1
                return True
            else:
                print("PC is safe")

                with open(path, "w") as test_file:
                    test_file.write(r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
                    print("file created!")

                return False
            
        except Exception as e:
            print(f"error: {e}")

    def find_virus(self):
        recents = os.path.join(os.environ["APPDATA"],r"Microsoft\Windows\Recent")
        shell = win32com.client.Dispatch("WScript.Shell")
        for file in os.listdir(recents):
            if file.endswith(".lnk"):
                shortcut = shell.CreateShortcut(os.path.join(recents, file))
                check_suspicious = self.imports_suspicious(shortcut.Targetpath)
                get_hash = hash_algo.get_file_hash(shortcut.Targetpath)
                check_hash = hash_algo.check_file_hash(get_hash)
                check_yara = yi.yaraApply(shortcut.Targetpath)

                if (check_suspicious and check_yara) or (check_hash and check_yara):
                        print(f"Found suspicious file imported from {shortcut.Targetpath}")
                        with open("threat.json", "r") as threat:
                            data = json.load(threat)
                            file_name = os.path.basename(shortcut.Targetpath)
                            data[file_name] = shortcut.Targetpath
                        
                        with open("threat.json", "w") as threat:
                            json.dump(data, threat, indent=4)

algo = Algorithm()

#funct_set can be used in future for continuousely detecting pc

def funct_set():
    while True:
        algo.is_powershell_running()
        algo.is_cmd_running()
        algo.create_virus()
        
        for root, dirs, files in os.walk("C:\\"):
            for file in files:
                path = os.path.join(root, file)
                check_suspicious = algo.imports_suspicious(path)
                get_hash = hash_algo.get_file_hash(path)
                check_hash = hash_algo.check_file_hash(get_hash)
                check_yara = yi.yaraApply(path)

                if (check_suspicious and check_yara) or (check_hash and check_yara):
                    if not os.path.exists("threat.json"):
                        with open("threat.json", "w") as threat_file:
                            json.dump({}, threat_file, indent=4)

                    with open("threat.json", "r") as threat:
                        data = json.load(threat)

                    file_name = os.path.basename(path)
                    data[file_name] = path
                    
                    with open("threat.json", "w") as threat_file:
                        json.dump(data, threat_file, indent=4)

                    print(f"Found suspicious file imported from {path}")

        if virus_chances>=2:
            print("Virus detected!!")
            algo.find_virus()

        time.sleep(600)


# funct_set()