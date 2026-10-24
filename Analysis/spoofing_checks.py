"""
spoofing_checks.py
Analyzes parsed email headers to detect spoofing/phishing indicators.
Input : reports/messages.json
Output: reports/forensic_report.txt
"""

import json
import os
import re

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MESSAGES_JSON = os.path.join(BASE_DIR, "reports", "messages.json")
REPORT_FILE = os.path.join(BASE_DIR, "reports", "forensic_report.txt")

def domain(addr):
    if "@" in addr:
        return addr.split("@")[-1].lower()
    return ""

def analyze_message(msg):
    flags = []
    score = 0

    from_addr = msg.get("from_addr", "")
    return_path = msg.get("return_path", "")
    reply_to = msg.get("reply_to", "")
    auth_results = msg.get("authentication_results", "").lower()
    attachments = msg.get("attachment_paths", [])

    from_domain = domain(from_addr)
    return_domain = domain(return_path)

    # Rule 1: From vs Return-Path mismatch
    if return_domain and from_domain and return_domain != from_domain:
        flags.append("From domain differs from Return-Path domain")
        score += 3

    # Rule 2: Reply-To mismatch
    if reply_to and reply_to != from_addr:
        flags.append("Reply-To address differs from From address")
        score += 2

    # Rule 3: SPF/DKIM failure or absence
    if "spf=fail" in auth_results or "dkim=fail" in auth_results:
        flags.append("SPF/DKIM authentication failure")
        score += 3
    elif auth_results == "":
        flags.append("Missing Authentication-Results header")
        score += 1

    # Rule 4: Suspicious attachment extensions
    for path in attachments:
        if path.lower().endswith((".exe", ".js", ".docm", ".xlsm")):
            flags.append("Macro-capable or executable attachment detected")
            score += 3
            break

    return flags, score

def main():
    if not os.path.exists(MESSAGES_JSON):
        print("[ERROR] messages.json not found.")
        return

    with open(MESSAGES_JSON, "r", encoding="utf-8") as f:
        messages = json.load(f)

    with open(REPORT_FILE, "w", encoding="utf-8") as report:
        report.write("EMAIL FORENSIC ANALYSIS REPORT\n")
        report.write("=" * 40 + "\n\n")

        for msg in messages:
            flags, score = analyze_message(msg)

            report.write(f"Message ID: {msg.get('message_id')}\n")
            report.write(f"From      : {msg.get('from_addr')}\n")
            report.write(f"To        : {', '.join(msg.get('to_addrs', []))}\n")
            report.write(f"Subject   : {msg.get('subject')}\n")
            report.write(f"Date      : {msg.get('date_iso')}\n")
            report.write(f"Score     : {score}\n")

            if flags:
                report.write("Flags:\n")
                for f in flags:
                    report.write(f"  - {f}\n")
            else:
                report.write("Flags     : None\n")

            report.write("-" * 40 + "\n")

    print("[+] Forensic report generated successfully.")

if __name__ == "__main__":
    main()
