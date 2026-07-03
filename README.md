# 🛡️ Python Antivirus

A lightweight antivirus application built in **Python** with a modern **CustomTkinter** GUI. This project combines multiple malware detection techniques to provide basic protection and demonstrate how antivirus software works.

## Features

* 🔍 Full System Scan
* ⚡ Quick Scan
* 🧬 YARA Rule-based Detection
* 🔑 SHA-256 File Hash Scanning
* 🌐 VirusTotal API Integration
* 📦 PE (Portable Executable) Import Analysis
* 🖥️ Suspicious Process Detection
* 📊 Scan Progress and Threat Counter
* ❌ Scan Cancellation Support

## Technologies Used

* Python
* CustomTkinter
* YARA-Python
* psutil
* pefile
* hashlib
* requests
* VirusTotal API

## Notes

* This project is intended for **educational and learning purposes**. It demonstrates the fundamentals of antivirus development and is **not a replacement for commercial antivirus software**.
* Detection relies on a combination of YARA rules, SHA-256 hashes, VirusTotal lookups, and basic heuristic analysis.
* Some detections may produce **false positives**, as the heuristic engine is intentionally simple.

## VirusTotal API Key

The repository currently includes a **VirusTotal API key** inside the source code for convenience during testing.

If you fork or use this project, it is **strongly recommended** that you replace it with your own free VirusTotal API key. You can obtain one by creating an account on the VirusTotal website.

## Future Improvements

* Real-time protection
* Quarantine and restore functionality
* Digital signature verification
* File entropy analysis
* ZIP archive scanning
* Multi-threaded scanning
* Improved heuristic detection
* Reduced false positives

⭐ Feel free to fork, improve, and contribute to the project!
