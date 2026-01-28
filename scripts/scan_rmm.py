#!/usr/bin/env python3
import re
import csv
from pathlib import Path

VENDOR_PAT = re.compile(
    r"teamviewer|anydesk|connectwise|screenconnect|kaseya|ninjaone|splashtop|logmein|goto|gotomeeting|vnc|dameware|beyondtrust|bomgar|rustdesk|meshcentral|n-able|nable|atera|manageengine|zoho",
    re.IGNORECASE,
)
GUID_PAT = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def scan_file(path: Path) -> dict:
    text = path.read_text(errors='ignore')
    vendors = sorted(set(m.group(0) for m in VENDOR_PAT.finditer(text)))
    guids = sorted(set(m.group(0).lower() for m in GUID_PAT.finditer(text)))

    # Try to extract rule Name and Description if present in small getters
    # Look for lines like: R0["Name"] := "..."
    name = None
    desc = None
    name_m = re.search(r'\["Name"\]\s*:?=\s*"([^"]+)"', text)
    if name_m:
        name = name_m.group(1)
    desc_m = re.search(r'\["Description"\]\s*:?=\s*"([^"]+)"', text)
    if desc_m:
        desc = desc_m.group(1)

    return {
        'file': path.name,
        'name': name or '',
        'description': desc or '',
        'vendors': ';'.join(vendors),
        'guids': ';'.join(guids),
    }


def main():
    root = Path('asr_lua')
    out_path = Path('asr_rmm_index.csv')
    rows = []
    for p in sorted(root.glob('*.bin.txt')):
        rows.append(scan_file(p))

    with out_path.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['file', 'name', 'description', 'vendors', 'guids'])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"Wrote {out_path} with {len(rows)} rows")


if __name__ == '__main__':
    main()


