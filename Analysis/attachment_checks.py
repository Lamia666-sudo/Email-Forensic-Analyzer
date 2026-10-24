"""
attachment_checks.py
- Loads reports/messages.json
- Inspects files in data/attachments for size and suspicious extensions
- Hashes attachments with SHA-256 for evidence integrity
- Adds per-message attachment metadata and writes back to reports/messages.json
- Outputs reports/attachment_report.json
"""
import os
import json
import hashlib

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ATTACH_DIR = os.path.join(BASE_DIR, "data", "attachments")
MESSAGES_JSON = os.path.join(BASE_DIR, "reports", "messages.json")
ATTACH_REPORT = os.path.join(BASE_DIR, "reports", "attachment_report.json")

SUSPICIOUS_EXTENSIONS = {".exe", ".js", ".vbs", ".scr", ".bat", ".ps1", ".docm", ".xlsm", ".hta"}

def compute_sha256(filepath):
    """Compute SHA-256 hash of a file for evidence integrity."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"ERROR: {str(e)}"

def analyze_attachments(messages):
    attachment_details = []
    for msg in messages:
        msg_idx = msg.get("message_index")
        details = []
        for path in msg.get("attachment_paths", []):
            try:
                if not os.path.exists(path):
                    details.append({"path": path, "exists": False})
                    continue
                size = os.path.getsize(path)
                ext = os.path.splitext(path)[1].lower()
                suspicious = ext in SUSPICIOUS_EXTENSIONS or size > (5 * 1024 * 1024)  # >5 MB flagged
                sha256 = compute_sha256(path)
                details.append({
                    "path": path,
                    "exists": True,
                    "size_bytes": size,
                    "extension": ext,
                    "suspicious": suspicious,
                    "sha256": sha256
                })
            except Exception as e:
                details.append({"path": path, "error": str(e)})
        msg["attachment_details"] = details
        attachment_details.append({"message_index": msg_idx, "attachments": details})
    return messages, attachment_details

def main():
    if not os.path.exists(MESSAGES_JSON):
        print("[ERROR] messages.json not found. Run parser first.")
        return
    with open(MESSAGES_JSON, "r", encoding="utf-8") as f:
        messages = json.load(f)

    messages, attachment_details = analyze_attachments(messages)

    # update messages.json with attachment details
    with open(MESSAGES_JSON, "w", encoding="utf-8") as f:
        json.dump(messages, f, indent=2, ensure_ascii=False)

    with open(ATTACH_REPORT, "w", encoding="utf-8") as f:
        json.dump(attachment_details, f, indent=2, ensure_ascii=False)

    print("[+] Attachment analysis complete.")
    print(f"[+] Attachment report written: {ATTACH_REPORT}")

if __name__ == "__main__":
    main()
