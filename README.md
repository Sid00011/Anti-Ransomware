# Anti-Ransomware

Windows desktop application for real-time ransomware detection and response.
Combines an SVM machine learning classifier, filesystem monitoring, hash-based
malware detection, and process analysis in a single Tkinter GUI.

---

## What it does

- **ML-based PE file scanning** - SVM classifier trained on PE header features
  (entropy, imports, sections, resources) flags executables as malicious or legitimate
- **Real-time filesystem monitoring** - watchdog observer detects file creation,
  modification, deletion, and moves as they happen
- **Hash-based malware detection** - MD5, SHA1, SHA256 hashes checked against
  a known malware database
- **Ransomware extension detection** - 500+ known ransomware file extensions
  (.locky, .wcry, .cerber, .clop, .dharma...) flagged on scan
- **Suspicious process detection** - monitors CPU usage, memory, disk I/O,
  thread count, and open file handles to surface anomalous processes
- **Quarantine and delete** - right-click any flagged file to quarantine or remove it
- **Alarm system** - audio alert fires when a threat is detected

---

## Interface

Four tabs:

| Tab | Function |
|---|---|
| File Scanning | Scan a directory with SVM classifier + extension dictionary |
| Real-Time Monitoring | Live filesystem event stream with process attribution |
| Malware Detection | Hash-based detection and deletion |
| Suspicious Processes | Process monitor with CPU/memory/IO anomaly detection |

---

## ML classifier

The SVM model (`classifier/svm_classifier.pkl`) classifies PE files using
55 features extracted from the PE header:

- File header: Machine, Characteristics, SizeOfOptionalHeader
- Optional header: ImageBase, SizeOfCode, EntryPoint, Subsystem, DllCharacteristics
- Sections: count, mean/min/max entropy, mean/min/max raw size, mean/min/max virtual size
- Imports: DLL count, total imports, ordinal imports
- Exports: export count
- Resources: count, mean/min/max entropy, mean/min/max size
- Metadata: LoadConfigurationSize, VersionInformationSize

---

## Stack

| Component | Technology |
|---|---|
| GUI | Python Tkinter + ttk |
| ML classifier | scikit-learn SVM (joblib/pickle) |
| PE analysis | pefile |
| Filesystem monitoring | watchdog |
| Process monitoring | psutil |
| Audio alert | pygame |
| Build | PyInstaller (produces basic.exe) |

---

## Installation

```bash
pip install watchdog psutil pefile pygame joblib scikit-learn prettytable
python basic.py
Or run the pre-built executable:

dist/basic.exe
Project structure
Anti-Ransomware/
├── basic.py                    # Main application
├── classifier/
│   ├── svm_classifier.pkl      # Trained SVM model
│   └── svm_features.pkl        # Feature list used during training
├── database/
│   └── file_list.txt           # Scanned file index
├── hashes.txt                  # Known malware hash database (MD5/SHA1/SHA256)
├── alarm.mp3                   # Alert sound
└── dist/basic.exe              # Pre-built Windows executable
