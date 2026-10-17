import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import nmap
import datetime
import json

# Load vulnerabilities from JSON file
def load_vulnerabilities(file_path="vulnerabilities.json"):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load vulnerability database:\n{e}")
        return []

# Match port/product/version to known vulnerabilities
def match_vulnerability(port, product, version):
    for vuln in vulnerabilities_list:
        if (port == vuln["port"] and
            vuln["product"].lower() in product.lower() and
            (vuln["version"] == "" or vuln["version"] in version)):
            return vuln["description"]
    return None

# Perform Nmap scan
def scan():
    global scan_output
    target = target_entry.get()
    ports = ports_entry.get()

    if not target:
        messagebox.showwarning("Input Error", "Please enter a target IP or domain.")
        return

    try:
        scanner = nmap.PortScanner()
        scan_result_text.delete(1.0, tk.END)
        scan_output = f"Scan Report for {target} - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        scan_result_text.insert(tk.END, f"Scanning {target} on ports {ports or 'default'}...\n\n")
        if ports:
            scanner.scan(target, ports)
        else:
            scanner.scan(target)

        vulnerabilities_found = False

        for host in scanner.all_hosts():
            host_info = f"Host: {host} ({scanner[host].hostname()})\nState: {scanner[host].state()}\n"
            scan_result_text.insert(tk.END, host_info)
            scan_output += host_info + "\n"

            for proto in scanner[host].all_protocols():
                proto_info = f"Protocol: {proto}\n"
                scan_result_text.insert(tk.END, proto_info)
                scan_output += proto_info + "\n"

                ports_data = scanner[host][proto].keys()
                for port in sorted(ports_data):
                    state = scanner[host][proto][port]['state']
                    if state != 'open':
                        continue

                    name = scanner[host][proto][port].get('name', '')
                    product = scanner[host][proto][port].get('product', '')
                    version = scanner[host][proto][port].get('version', '')

                    port_info = f"Port: {port}\tState: {state}\tService: {name}\t{product} {version}\n"
                    scan_result_text.insert(tk.END, port_info)
                    scan_output += port_info

                    vuln = match_vulnerability(port, product, version)
                    if vuln:
                        vulnerabilities_found = True
                        vuln_msg = f"⚠️ Vulnerability Detected: {vuln}\n"
                        scan_result_text.insert(tk.END, vuln_msg)
                        scan_output += vuln_msg

        if not vulnerabilities_found:
            no_vuln_msg = "✅ No vulnerabilities detected.\n"
            scan_result_text.insert(tk.END, no_vuln_msg)
            scan_output += no_vuln_msg

        scan_result_text.insert(tk.END, "\nScan Complete.")
        scan_output += "\nScan Complete."

    except Exception as e:
        messagebox.showerror("Scan Error", str(e))

# Save scan report to file
def save_report():
    if not scan_output:
        messagebox.showinfo("No Data", "No scan result to save.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt")],
                                             title="Save Scan Report")
    if file_path:
        with open(file_path, "w") as f:
            f.write(scan_output)
        messagebox.showinfo("Saved", f"Scan report saved to: {file_path}")

# GUI Setup
window = tk.Tk()
window.title("Custom Nmap Port Scanner with GUI")
window.geometry("800x600")

tk.Label(window, text="Target IP/Domain:").pack()
target_entry = tk.Entry(window, width=50)
target_entry.pack()

tk.Label(window, text="Ports (e.g., 22,80,443 or leave blank for default):").pack()
ports_entry = tk.Entry(window, width=50)
ports_entry.pack()

button_frame = tk.Frame(window)
button_frame.pack(pady=10)

tk.Button(button_frame, text="Start Scan", command=scan, bg="#007ACC", fg="white", width=20).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Save Report", command=save_report, bg="#28a745", fg="white", width=20).pack(side=tk.LEFT, padx=5)

scan_result_text = scrolledtext.ScrolledText(window, width=100, height=25, font=("Courier", 10))
scan_result_text.pack(pady=10)

vulnerabilities_list = load_vulnerabilities()
scan_output = ""

window.mainloop()
