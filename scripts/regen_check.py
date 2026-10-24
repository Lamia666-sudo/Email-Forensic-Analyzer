import os
import shutil
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent.parent
os.chdir(ROOT)
reports = ROOT / 'reports'

def file_info(p):
    h = hashlib.sha256()
    with open(p,'rb') as f:
        while True:
            b = f.read(8192)
            if not b: break
            h.update(b)
    return {'name': p.name, 'mtime': p.stat().st_mtime, 'hash': h.hexdigest()}

print('--- PRE-RUN REPORTS ---')
pre = []
if reports.exists():
    for p in sorted(reports.iterdir()):
        if p.is_file():
            info = file_info(p)
            pre.append(info)
            print(f"{info['name']:30} mtime={datetime.fromtimestamp(info['mtime'])} hash={info['hash']}")
else:
    print('No reports folder or files found.')

old_messages_hash = None
if (reports / 'messages.json').exists():
    old_messages_hash = file_info(reports / 'messages.json')['hash']
    print('\nPre-run messages.json hash:', old_messages_hash)

# backup
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
backup = ROOT / f'reports_backup_{ts}'
if reports.exists():
    backup.mkdir(parents=True, exist_ok=True)
    for p in reports.iterdir():
        if p.is_file():
            shutil.move(str(p), str(backup))
    print('\nMoved existing reports to:', backup)
else:
    print('\nNo reports to backup')

# run pipeline
print('\nRunning pipeline on data/attempt.mbox...')
ret = subprocess.run([str(Path('python').absolute() if False else 'python'), 'pipeline.py', 'data/attempt.mbox'])
print('\nPipeline exit code:', ret.returncode)

print('\n--- POST-RUN REPORTS ---')
post = []
if reports.exists():
    for p in sorted(reports.iterdir()):
        if p.is_file():
            info = file_info(p)
            post.append(info)
            print(f"{info['name']:30} mtime={datetime.fromtimestamp(info['mtime'])} hash={info['hash']}")
else:
    print('No reports produced.')

new_messages_hash = None
if (reports / 'messages.json').exists():
    new_messages_hash = file_info(reports / 'messages.json')['hash']
    print('\nPost-run messages.json hash:', new_messages_hash)

if old_messages_hash:
    if new_messages_hash and old_messages_hash == new_messages_hash:
        print('\nmessages.json unchanged (hash equal).')
    else:
        print('\nmessages.json changed.')
        if backup.exists() and (backup / 'messages.json').exists():
            print('\n--- OLD messages.json (head 200 lines) ---')
            with open(backup / 'messages.json','r',encoding='utf-8') as f:
                for i,line in enumerate(f):
                    print(line.rstrip())
                    if i>199: break
            print('\n--- NEW messages.json (head 200 lines) ---')
            with open(reports / 'messages.json','r',encoding='utf-8') as f:
                for i,line in enumerate(f):
                    print(line.rstrip())
                    if i>199: break
else:
    print('\nNo previous messages.json to diff against.')
