import os
import shutil
import gzip
from pathlib import Path
from datetime import datetime, timedelta

ROOT = Path(__file__).parent.parent
BACKUP_GLOB = 'reports_backup_*'
KEEP_DAYS = 7
COMPRESS_OLDER_THAN_DAYS = 1

def compress_folder(folder: Path):
    tar_path = folder.with_suffix('.tar.gz')
    try:
        import tarfile
        with tarfile.open(tar_path, 'w:gz') as tar:
            tar.add(folder, arcname=folder.name)
        shutil.rmtree(folder)
        print(f'Compressed and removed {folder} -> {tar_path.name}')
    except Exception as e:
        print(f'Failed to compress {folder}: {e}')

def main():
    now = datetime.now()
    for p in ROOT.glob(BACKUP_GLOB):
        if not p.is_dir():
            continue
        mtime = datetime.fromtimestamp(p.stat().st_mtime)
        age = now - mtime
        if age > timedelta(days=KEEP_DAYS):
            # delete old backup
            shutil.rmtree(p)
            print(f'Deleted old backup {p.name}')
        elif age > timedelta(days=COMPRESS_OLDER_THAN_DAYS):
            # compress slightly older ones
            compress_folder(p)
        else:
            print(f'Keeping recent backup {p.name}')

if __name__ == '__main__':
    main()
