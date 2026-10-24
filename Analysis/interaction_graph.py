"""
interaction_graph.py
- Reads reports/messages.json
- Produces:
  - reports/interaction_edges.csv  (from,to,count)
  - reports/interaction_summary.json (top senders/receivers, total messages)
"""
import os
import json
import csv
from collections import Counter, defaultdict

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MESSAGES_JSON = os.path.join(BASE_DIR, "reports", "messages.json")
EDGES_CSV = os.path.join(BASE_DIR, "reports", "interaction_edges.csv")
SUMMARY_JSON = os.path.join(BASE_DIR, "reports", "interaction_summary.json")

def build_edges(messages):
    edges = Counter()
    sender_counts = Counter()
    receiver_counts = Counter()
    for msg in messages:
        sender = (msg.get("from_addr") or "").lower()
        tos = [t.lower() for t in msg.get("to_addrs", [])]
        if not sender:
            continue
        sender_counts[sender] += 1
        for r in tos:
            receiver_counts[r] += 1
            edges[(sender, r)] += 1
    return edges, sender_counts, receiver_counts

def main():
    if not os.path.exists(MESSAGES_JSON):
        print("[ERROR] messages.json not found.")
        return
    with open(MESSAGES_JSON, "r", encoding="utf-8") as f:
        messages = json.load(f)

    edges, sender_counts, receiver_counts = build_edges(messages)

    # write edges csv
    with open(EDGES_CSV, "w", newline='', encoding="utf-8") as csvf:
        writer = csv.writer(csvf)
        writer.writerow(["from", "to", "count"])
        for (s, r), c in edges.items():
            writer.writerow([s, r, c])

    summary = {
        "total_messages": len(messages),
        "unique_senders": len(sender_counts),
        "unique_receivers": len(receiver_counts),
        "top_senders": sender_counts.most_common(10),
        "top_receivers": receiver_counts.most_common(10),
        "total_edges": len(edges)
    }

    with open(SUMMARY_JSON, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"[+] Interaction edges written: {EDGES_CSV}")
    print(f"[+] Interaction summary: {SUMMARY_JSON}")

if __name__ == "__main__":
    main()
