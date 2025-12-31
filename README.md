# 🛡️ MiniDefender X

MiniDefender X is a lightweight, Python-based antivirus engine that combines **local heuristic analysis**, **keyword detection**, and **cloud-based threat intelligence** to protect your files.



## ✨ Features

* **Multi-Layered Scanning:** * **Signatures:** Matches file hashes against a local `signatures.txt` database.
    * **Heuristics:** Analyzes file entropy and suspicious naming conventions.
    * **Keywords:** Scans script contents for dangerous commands (e.g., PowerShell injection).
* **Cloud Intelligence:** Integrated with **Kaspersky OpenTIP API** for real-time global threat verdicts.
* **Smart Classification:** Categorizes files into five risk levels:
    * 🔴 **Critical:** Known malware or high-confidence heuristic hits.
    * 🟠 **High Risk:** Suspicious behavior or Kaspersky "Yellow" zone.
    * 🟡 **Medium Risk:** Potentially unwanted patterns.
    * 🔵 **Low Risk:** Minor anomalies.
    * 🟢 **Clean:** Trusted files.
* **Automatic Quarantine:** Safely moves threats to an isolated folder to prevent execution.
* **Dark Mode UI:** A modern, clean interface built with Tkinter.

## 🚀 Installation

### 1. Prerequisites
Ensure you have [Python 3.x](https://www.python.org/downloads/) installed.

### 2. Install Dependencies
MiniDefender X requires the `requests` library for cloud scanning. Open your terminal and run:

```bash
python -m pip install requests# MiniDefender
