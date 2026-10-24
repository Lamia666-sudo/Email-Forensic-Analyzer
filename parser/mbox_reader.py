import mailbox
import json
import csv
import sys
import os
from pathlib import Path
from email.utils import parsedate_to_datetime, getaddresses

BASE_DIR = Path(__file__).resolve().parent.parent


def safe_str(s):
	return s if s is not None else ""


def extract_addresses(header_value):
	if not header_value:
		return []
	return [addr for name, addr in getaddresses([header_value]) if addr]


def parse_mbox(mbox_path: Path):
	messages = []
	timeline_rows = []
	try:
		mbox = mailbox.mbox(str(mbox_path))
	except Exception as e:
		print(f"[ERROR] Unable to open mbox: {e}")
		sys.exit(1)

	attach_dir = BASE_DIR / "data" / "attachments"
	attach_dir.mkdir(parents=True, exist_ok=True)

	for i, message in enumerate(mbox):
		try:
			subject = safe_str(message.get('subject'))
			from_hdr = safe_str(message.get('from'))
			to_hdr = safe_str(message.get('to'))
			date_hdr = safe_str(message.get('date'))
			msgid = safe_str(message.get('message-id') or message.get('message_id') or f'<no-id-{i}>')
			return_path = safe_str(message.get('return-path') or message.get('Return-Path'))
			reply_to = safe_str(message.get('reply-to') or message.get('Reply-To'))
			auth_results = safe_str(message.get('authentication-results') or message.get('Authentication-Results'))

			# parse date to ISO if possible
			date_iso = ""
			try:
				if date_hdr:
					dt = parsedate_to_datetime(date_hdr)
					date_iso = dt.isoformat()
			except Exception:
				date_iso = date_hdr

			# extract body (plain text preferred)
			body = ""
			if message.is_multipart():
				for part in message.walk():
					ctype = part.get_content_type()
					if ctype == 'text/plain' and not part.get_filename():
						try:
							body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', 'replace')
							break
						except Exception:
							continue
			else:
				try:
					body = message.get_payload(decode=True).decode(message.get_content_charset() or 'utf-8', 'replace')
				except Exception:
					body = str(message.get_payload())

			# attachments: save to data/attachments, record absolute paths
			attachment_paths = []
			if message.is_multipart():
				for part in message.walk():
					filename = part.get_filename()
					if filename:
						safe_name = filename.replace(os.path.sep, "_")
						out_name = f"msg{i}_{safe_name}"
						out_path = attach_dir / out_name
						try:
							with open(out_path, 'wb') as af:
								payload = part.get_payload(decode=True)
								if payload:
									af.write(payload)
							attachment_paths.append(str(out_path.resolve()))
						except Exception as e:
							print(f"[WARN] Failed to write attachment for msg {i}: {e}")

			msg = {
				"message_index": i,
				"message_id": msgid,
				"subject": subject,
				"from_hdr": from_hdr,
				"from_addr": (extract_addresses(from_hdr)[0] if extract_addresses(from_hdr) else ""),
				"to_hdr": to_hdr,
				"to_addrs": extract_addresses(to_hdr),
				"date_hdr": date_hdr,
				"date_iso": date_iso,
				"return_path": return_path,
				"reply_to": reply_to,
				"authentication_results": auth_results,
				"body_preview": body[:1000],
				"attachment_paths": attachment_paths
			}

			messages.append(msg)
			timeline_rows.append({"id": msgid, "date": date_iso or date_hdr, "from": msg["from_addr"], "to": ", ".join(msg["to_addrs"]), "subject": subject})
		except Exception as e:
			print(f"[WARN] Skipping message {i}: {e}")
			continue

	return messages, timeline_rows


def write_outputs(messages, timeline_rows):
	reports_dir = BASE_DIR / 'reports'
	data_dir = BASE_DIR / 'data'
	reports_dir.mkdir(parents=True, exist_ok=True)
	data_dir.mkdir(parents=True, exist_ok=True)

	messages_file = reports_dir / 'messages.json'
	timeline_file = reports_dir / 'timeline.csv'

	# Merge with existing messages.json (append new unique messages by message_id)
	existing = {}
	if messages_file.exists():
		try:
			with open(messages_file, 'r', encoding='utf-8') as f:
				old = json.load(f)
			for m in old:
				existing[m.get('message_id')] = m
		except Exception:
			existing = {}

	added = 0
	for m in messages:
		mid = m.get('message_id')
		if mid in existing:
			# update existing entry with newer fields (merge)
			existing[mid].update(m)
		else:
			existing[mid] = m
			added += 1

	merged = list(existing.values())
	with open(messages_file, 'w', encoding='utf-8') as f:
		json.dump(merged, f, indent=2, ensure_ascii=False)

	# Overwrite timeline (it's cheap) — keep the latest parsing results
	with open(timeline_file, 'w', newline='', encoding='utf-8') as f:
		writer = csv.DictWriter(f, fieldnames=['id', 'date', 'from', 'to', 'subject'])
		writer.writeheader()
		for row in timeline_rows:
			writer.writerow(row)

	print(f"[+] Merged {len(messages)} parsed messages into {messages_file} (added {added} new)")
	print(f"[+] Wrote timeline to {timeline_file}")


def main():
	mbox_arg = sys.argv[1] if len(sys.argv) > 1 else None
	if not mbox_arg:
		mbox_path = BASE_DIR / 'data' / 'raw_emails.mbox'
	else:
		mbox_path = Path(mbox_arg)

	if not mbox_path.exists():
		print(f"[ERROR] MBOX not found: {mbox_path}")
		sys.exit(1)

	messages, timeline = parse_mbox(mbox_path)
	write_outputs(messages, timeline)


if __name__ == '__main__':
	main()

