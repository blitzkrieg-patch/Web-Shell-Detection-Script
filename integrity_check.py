#!/usr/bin/env python3
# integrity_check.py - compare current files to baseline manifest

import json, hashlib, os
from pathlib import Path
from datetime import datetime

MANIFEST = Path('/opt/security/manifest.json')
ROOT = Path('/var/www/cyberwings.asia/public_html')

def hash_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

if not MANIFEST.exists():
    print("Manifest not found. Run integrity_init.py first.")
    exit(1)

with MANIFEST.open() as f:
    data = json.load(f)
baseline = data.get('manifest', {})

current = {}
for p in ROOT.rglob('*'):
    if p.is_file():
        current[str(p)] = {'sha256': hash_file(p), 'size': p.stat().st_size}

added = set(current) - set(baseline)
deleted = set(baseline) - set(current)
modified = {p for p in current if p in baseline and current[p]['sha256'] != baseline[p]['sha256']}

print(f"[{datetime.now()}] Integrity check results:")
print("Added:", len(added))
print("Deleted:", len(deleted))
print("Modified:", len(modified))

for p in modified:
    print("MODIFIED:", p)
for p in added:
    print("ADDED:", p)
for p in deleted:
    print("DELETED:", p)
