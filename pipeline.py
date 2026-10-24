"""
pipeline.py
Unified Email Forensics Pipeline (Flexible MBOX Input)

Accepts optional command-line argument: path to MBOX file
If none provided, defaults to data/raw_emails.mbox
"""

import os
import subprocess
import sys
from pathlib import Path

# --- Determine project root (works whether run directly or via subprocess) ---
if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).parent.resolve()

os.chdir(BASE_DIR)  # Ensure we always run from project root
print(f"[+] Working directory: {BASE_DIR}")

# Paths
PARSER_SCRIPT = BASE_DIR / "parser" / "mbox_reader.py"
ATTACHMENT_SCRIPT = BASE_DIR / "analysis" / "attachment_checks.py"
GRAPH_SCRIPT = BASE_DIR / "analysis" / "interaction_graph.py"
ENHANCED_SCRIPT = BASE_DIR / "analysis" / "enhanced_analysis.py"

def run_step(description: str, command: list):
    """Run a subprocess command and stream output live"""
    print(f"\n[+] {description}")
    try:
        result = subprocess.run(
            command,
            check=True,
            text=True,
            stdout=None,   # Let output go directly to terminal/GUI
            stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Step failed: {description}")
        print(f"[ERROR] Return code: {e.returncode}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"[ERROR] Script not found: {' '.join(command)}")
        print("[ERROR] Make sure you're running from the project root and venv is active.")
        sys.exit(1)


def main(mbox_path: str = None):
    print("=" * 70)
    print("EMAIL FORENSICS AUTOMATED PIPELINE")
    print("=" * 70)

    # Resolve MBOX path
    if mbox_path is None or not mbox_path.strip():
        default_mbox = BASE_DIR / "data" / "raw_emails.mbox"
        if not default_mbox.exists():
            print(f"[ERROR] Default MBOX not found: {default_mbox}")
            print("[INFO] Provide a custom MBOX path as argument or via GUI.")
            sys.exit(1)
        mbox_path = str(default_mbox)
        print(f"[+] Using default MBOX: {mbox_path}")
    else:
        mbox_path = os.path.abspath(mbox_path)
        if not os.path.exists(mbox_path):
            print(f"[ERROR] MBOX file not found: {mbox_path}")
            sys.exit(1)
        print(f"[+] Using selected MBOX: {mbox_path}")

    # Ensure reports and attachments directories exist
    (BASE_DIR / "reports").mkdir(exist_ok=True)
    (BASE_DIR / "data" / "attachments").mkdir(parents=True, exist_ok=True)
    
    # Clear previous messages.json to prevent case mixing
    messages_json = BASE_DIR / "reports" / "messages.json"
    if messages_json.exists():
        messages_json.unlink()
        print("[INFO] Cleared previous messages.json to prevent case mixing")

    # Step 1: Parse MBOX (pass the mbox path)
    run_step(
        "Parsing MBOX file",
        [sys.executable, str(PARSER_SCRIPT), mbox_path]
    )

    # Step 2: Analyze attachments
    run_step(
        "Analyzing attachments",
        [sys.executable, str(ATTACHMENT_SCRIPT)]
    )

    # Step 3: Build interaction graph
    run_step(
        "Building sender-recipient interaction graph",
        [sys.executable, str(GRAPH_SCRIPT)]
    )

    # Step 4: Enhanced analysis & final report
    run_step(
        "Running enhanced forensic analysis",
        [sys.executable, str(ENHANCED_SCRIPT)]
    )

    print("\n[OK] Pipeline execution completed successfully!")
    print(f"[OK] Reports saved in: {BASE_DIR / 'reports'}")
    print(f"[OK] Final report: {BASE_DIR / 'reports' / 'final_forensic_report.txt'}")


if __name__ == "__main__":
    # Accept optional MBOX path from command line or GUI
    mbox_arg = sys.argv[1] if len(sys.argv) > 1 else None
    main(mbox_arg)