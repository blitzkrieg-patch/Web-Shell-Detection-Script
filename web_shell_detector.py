#!/usr/bin/env python3
# web_shell_detector.py

import os
import re
import hashlib
import math
from collections import Counter
from datetime import datetime

# Configuration (adjust paths in real deployment)
WEB_ROOTS = ['/var/www/example.com/public_html']
SUSPICIOUS_PATTERNS = [
    r'\b(exec|shell_exec|system|passthru|popen|proc_open)\b',
    r'\beval\s*\(',
    r'base64_decode\s*\(',
    r'gzuncompress\s*\(',
]

EXT_SUSPICIOUS = {'.php', '.php5', '.phtml', '.pl', '.cgi', '.jsp'}

def entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

def scan_file(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
        text = data.decode('utf-8', errors='ignore')
    except Exception:
        return None

    findings = []
    # check patterns
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            findings.append(f"pattern:{pat}")
    # entropy check (heuristic)
    ent = entropy(data)
    if ent > 7.5 and len(data) > 200:  # heuristic threshold
        findings.append(f"high_entropy:{ent:.2f}")
    return findings

def main():
    suspects = []
    for root in WEB_ROOTS:
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                _, ext = os.path.splitext(fn)
                if ext.lower() in EXT_SUSPICIOUS:
                    path = os.path.join(dirpath, fn)
                    res = scan_file(path)
                    if res:
                        suspects.append((path, res))
    # Output (for screenshot)
    if suspects:
        print(f"[{datetime.now()}] Suspicious files found: {len(suspects)}")
        for p, r in suspects:
            print(p, "->", ", ".join(r))
    else:
        print(f"[{datetime.now()}] No suspicious files detected.")

if __name__ == '__main__':
    main()
