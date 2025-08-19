#!/usr/bin/env python3
# shell_exec_detector.py


import re
from datetime import datetime
from pathlib import Path

ACCESS_LOG = Path('/var/log/nginx/cyberwings.asia.access.log')
PATTERNS = [
    r'(wget|curl)\s',           # attempted download
    r'(bash\s+-i|-i\s+bash)',   # interactive shell attempts
    r'(\|\s*sh|\|\s*bash)',     # piping to shell
    r'(;|\|\||&&)\s*\w+',       # command chaining
    r'\b(nc|netcat|telnet)\b',  # netcat/telnet
]

def scan_log(lines=500):
    if not ACCESS_LOG.exists():
        print("Access log not found.")
        return
    with ACCESS_LOG.open('r', errors='ignore') as f:
        data = f.readlines()[-lines:]
    hits = []
    for ln in data:
        for p in PATTERNS:
            if re.search(p, ln, re.IGNORECASE):
                hits.append(ln.strip())
                break
    if hits:
        print(f"[{datetime.now()}] Suspicious access entries: {len(hits)}")
        for h in hits:
            print(h)
    else:
        print(f"[{datetime.now()}] No suspicious access patterns found.")

if __name__ == '__main__':
    scan_log(400)
