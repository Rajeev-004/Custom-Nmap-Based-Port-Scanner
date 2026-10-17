# Custom Nmap Based Port Scanner With GUI and Reporting

This tool is a custom Nmap-based port scanner enhanced with a graphical user interface (GUI) built using Python Tkinter. It scans a given IP address for open ports and detects known vulnerabilities using a local JSON-based database.

## 🧰 Tools & Tech Used
- Python
- Nmap & python-nmap
- Tkinter
- JSON
- PDF/CSV report generation

## 💡 Features
- GUI interface for user-friendly scanning
- Open port & service detection using Nmap
- Matches known CVEs using a JSON vulnerability DB
- Save reports as `.txt`, `.csv`
- Visual output through GUI
- Error handling and validation

## 📸 Screenshots
(Include screenshots here using markdown: `![desc](screenshots/output1.png)`)

## 📁 Files
- `scanner_gui.py`: Main source code
- `vulnerabilities.json`: Custom CVE list
- `mini_project.pdf`: Full project report
- `requirements.txt`: Dependencies

## 🛠️ Installation
```bash
pip install -r requirements.txt
python scanner_gui.py