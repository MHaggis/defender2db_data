#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path

def read_index(path: Path):
    rows = {}
    with path.open('r', newline='') as f:
        r = csv.DictReader(f)
        for row in r:
            rows[row['file']] = row
    return rows

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--old', required=True, help='Old asr_index.csv path')
    p.add_argument('--new', default='asr_index.csv', help='New asr_index.csv path (default: current)')
    args = p.parse_args()

    old = read_index(Path(args.old))
    new = read_index(Path(args.new))

    old_keys = set(old.keys())
    new_keys = set(new.keys())

    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    changed = sorted([k for k in (new_keys & old_keys) if new[k]['sha256'] != old[k]['sha256']])

    print(f"Added: {len(added)}")
    for k in added:
        print(f" + {k}")
    print(f"Removed: {len(removed)}")
    for k in removed:
        print(f" - {k}")
    print(f"Changed: {len(changed)}")
    for k in changed:
        print(f" * {k}")

if __name__ == '__main__':
    main()


