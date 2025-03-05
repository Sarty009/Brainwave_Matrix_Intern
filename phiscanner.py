import argparse
import requests
import re
import sys
import json
import csv
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from colorama import Fore, Style
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# API Keys (Loaded from environment variables)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

def is_phishing_url(url):
    phishing_keywords = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'free', 'paypal']
    return any(keyword in url.lower() for keyword in phishing_keywords)

def check_url_blacklist(url):
    try:
        response = requests.get(f'https://openphish.com/feed.txt', timeout=5)
        if url in response.text:
            return True
    except requests.RequestException:
        pass
    return False

def check_virustotal(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers)
    if response.status_code == 200:
        data = response.json()
        if data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            return True
    return False

def check_google_safe_browsing(url):
    payload = {
        "client": {"clientId": "phiscan", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}", json=payload)
    if response.status_code == 200 and response.json():
        return True
    return False

def scan_url(url):
    print(f"\n[+] Scanning: {url}")
    result = {"url": url, "status": "Safe"}
    
    if check_url_blacklist(url):
        print(Fore.RED + "[!] URL found in phishing blacklist!" + Style.RESET_ALL)
        result["status"] = "Blacklisted"
    elif check_virustotal(url):
        print(Fore.RED + "[!] URL flagged by VirusTotal!" + Style.RESET_ALL)
        result["status"] = "Malicious (VirusTotal)"
    elif check_google_safe_browsing(url):
        print(Fore.RED + "[!] URL flagged by Google Safe Browsing!" + Style.RESET_ALL)
        result["status"] = "Malicious (Google)"
    elif is_phishing_url(url):
        print(Fore.YELLOW + "[!] Suspicious URL detected!" + Style.RESET_ALL)
        result["status"] = "Suspicious"
    else:
        print(Fore.GREEN + "[✓] URL looks safe (No guarantees)" + Style.RESET_ALL)
    
    return result

def scan_from_file(file_path, output_file):
    try:
        with open(file_path, 'r') as file:
            urls = file.readlines()
            results = [scan_url(url.strip()) for url in urls]
        with open(output_file, 'w') as json_file:
            json.dump(results, json_file, indent=4)
    except FileNotFoundError:
        print(Fore.RED + "[ERROR] File not found!" + Style.RESET_ALL)

def save_results_csv(results, filename):
    keys = results[0].keys()
    with open(filename, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(results)

def gui_scan():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(title="Select a file with URLs")
    if file_path:
        output_file = "scan_results.json"
        scan_from_file(file_path, output_file)
        messagebox.showinfo("Scan Complete", f"Results saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Phishing Link Scanner CLI")
    parser.add_argument("url", nargs="?", help="URL to scan")
    parser.add_argument("-f", "--file", help="File containing multiple URLs to scan")
    parser.add_argument("-o", "--output", help="Output file for results (JSON/CSV)")
    args = parser.parse_args()
    
    results = []
    if args.file:
        output_file = args.output if args.output else "scan_results.json"
        scan_from_file(args.file, output_file)
    elif args.url:
        results.append(scan_url(args.url))
        if args.output:
            save_results_csv(results, args.output)
    else:
        print("Usage: python phishing_scanner.py <URL> or -f <file>")
        sys.exit(1)

if __name__ == "__main__":
    main()
