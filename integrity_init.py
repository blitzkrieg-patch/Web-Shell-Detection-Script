#!/usr/bin/env python3
# integrity_init.py - create baseline manifest

import hashlib, json, os
from pathlib import Path

ROOT = Path('/var/www/cyberwings.asia/public_html')
MANIFEST = Path('/opt/security/manifest.json')

def hash_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

manifest = {}
for p in ROOT.rglob('*'):
    if p.is_file():
        manifest[str(p)] = {'sha256': hash_file(p), 'size': p.stat().st_size}

MANIFEST.parent.mkdir(parents=True, exist_ok=True)
with MANIFEST.open('w') as f:
    json.dump({'generated': str(os.getlogin()), 'manifest': manifest}, f, indent=2)

print("Baseline manifest created:", MANIFEST)
