"""
enhanced_analysis.py
- Runs layered analysis:
  1) Loads messages.json
  2) Reuses existing flags from spoofing_checks (if present) or recomputes
  3) Incorporates attachment_details (from attachment_checks)
  4) Computes suspicion_score and maps to severity
  5) Writes:
     - reports/final_forensic_report.txt (human readable)
     - reports/forensic_summary.json (structured)
     - updates reports/messages.json with 'suspicion_score','severity','flags'
"""

import os
import json
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MESSAGES_JSON = os.path.join(BASE_DIR, "reports", "messages.json")
FINAL_REPORT = os.path.join(BASE_DIR, "reports", "final_forensic_report.txt")
SUMMARY_JSON = os.path.join(BASE_DIR, "reports", "forensic_summary.json")

# severity thresholds (inclusive lower bounds)
SEVERITY_THRESHOLDS = {
    "Low": 0,
    "Medium": 3,
    "High": 6
}

def compute_severity(score):
    if score >= SEVERITY_THRESHOLDS["High"]:
        return "High"
    if score >= SEVERITY_THRESHOLDS["Medium"]:
        return "Medium"
    return "Low"

def recompute_spoof_flags(msg):
    flags = []
    score = 0
    from_addr = msg.get("from_addr", "") or ""
    return_path = msg.get("return_path", "") or ""
    reply_to = msg.get("reply_to", "") or ""
    auth_results = (msg.get("authentication_results") or "").lower()

    def domain(a): return a.split("@")[-1].lower() if "@" in a else ""

    if return_path and from_addr and domain(return_path) != domain(from_addr):
        flags.append("From vs Return-Path mismatch")
        score += 3
    if reply_to and reply_to.lower() != from_addr.lower():
        flags.append("Reply-To mismatch")
        score += 2
    if "spf=fail" in auth_results or "dkim=fail" in auth_results:
        flags.append("SPF/DKIM fail")
        score += 3
    elif auth_results == "":
        flags.append("Missing Authentication-Results")
        score += 1

    # attachments
    for a in msg.get("attachment_details", []):
        if a.get("suspicious"):
            flags.append("Suspicious attachment")
            score += 3
            break

    # message-id heuristic
    mid = (msg.get("message_id") or "")
    if "@" in mid:
        mid_domain = mid.split("@")[-1].strip(">").lower()
        if from_addr and mid_domain and (not from_addr.lower().endswith(mid_domain)):
            flags.append("Message-ID domain mismatch")
            score += 1

    return flags, score

def main():
    if not os.path.exists(MESSAGES_JSON):
        print("[ERROR] messages.json not found.")
        return

    with open(MESSAGES_JSON, "r", encoding="utf-8") as f:
        messages = json.load(f)

    total_messages = len(messages)
    analysis_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    agg = {"total_messages": total_messages, "analysis_timestamp": analysis_timestamp, "by_severity": {"Low": 0, "Medium": 0, "High": 0}, "flag_counts": {}}

    for msg in messages:
        flags, score = recompute_spoof_flags(msg)
        severity = compute_severity(score)
        msg["suspicion_score"] = score
        msg["severity"] = severity
        msg["flags"] = flags

        agg["by_severity"][severity] += 1
        for fl in flags:
            agg["flag_counts"][fl] = agg["flag_counts"].get(fl, 0) + 1

    # write updated messages.json
    with open(MESSAGES_JSON, "w", encoding="utf-8") as f:
        json.dump(messages, f, indent=2, ensure_ascii=False)

    # write human readable final report
    analysis_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(FINAL_REPORT, "w", encoding="utf-8") as r:
        r.write("FINAL EMAIL FORENSIC REPORT\n")
        r.write("="*60 + "\n")
        r.write(f"Analysis performed: {analysis_timestamp}\n")
        r.write("="*60 + "\n\n")
        r.write(f"Total messages analyzed: {total_messages}\n\n")
        r.write("Summary by severity:\n")
        for sev, cnt in agg["by_severity"].items():
            r.write(f"  - {sev}: {cnt}\n")
        r.write("\nTop flags observed:\n")
        for fl, cnt in sorted(agg["flag_counts"].items(), key=lambda x: x[1], reverse=True):
            r.write(f"  - {fl}: {cnt}\n")
        r.write("\nDETAILED MESSAGES\n")
        r.write("-"*60 + "\n")
        for msg in messages:
            r.write(f"Message ID : {msg.get('message_id')}\n")
            r.write(f"From       : {msg.get('from_addr')}\n")
            r.write(f"To         : {', '.join(msg.get('to_addrs', []))}\n")
            r.write(f"Subject    : {msg.get('subject')}\n")
            r.write(f"Date       : {msg.get('date_iso')}\n")
            r.write(f"Severity   : {msg.get('severity')} (score {msg.get('suspicion_score')})\n")
            if msg.get("flags"):
                r.write("Flags      :\n")
                for f in msg.get("flags"):
                    r.write(f"  - {f}\n")
            else:
                r.write("Flags      : None\n")
            att = msg.get("attachment_details", [])
            if att:
                r.write("Attachments :\n")
                for a in att:
                    r.write(f"  - {a.get('path')} (suspicious={a.get('suspicious')}, size={a.get('size_bytes', 'N/A')})\n")
            r.write("-"*60 + "\n")

        # recommended actions (generic)
        r.write("\nRECOMMENDATIONS\n")
        r.write(" - Quarantine any accounts involved in High severity messages pending investigation.\n")
        r.write(" - Block suspicious sender domains at perimeter and review SPF/DKIM settings.\n")
        r.write(" - Do NOT open attachments flagged as suspicious; analyze them in sandbox.\n")
        r.write(" - Reset credentials of recipients if credential harvesting suspected.\n")

    # write structured summary
    with open(SUMMARY_JSON, "w", encoding="utf-8") as s:
        json.dump(agg, s, indent=2, ensure_ascii=False)

    print(f"[+] Enhanced analysis complete. Final report: {FINAL_REPORT}")
    print(f"[+] Summary JSON: {SUMMARY_JSON}")

if __name__ == "__main__":
    main()
