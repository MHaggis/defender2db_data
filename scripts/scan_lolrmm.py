#!/usr/bin/env python3
import argparse
import csv
import json
import re
import urllib.request
from pathlib import Path


def fetch_lolrmm(url: str) -> list[dict]:
    with urllib.request.urlopen(url) as resp:
        return json.load(resp)


def path_to_regex(pattern: str) -> re.Pattern | None:
    # Normalize Windows-style separators; keep wildcards
    norm = pattern.replace('\\', '/').strip()
    # Extract basename to increase chance of match inside binaries
    base = norm.rsplit('/', 1)[-1]
    base = base.strip()
    # Drop empty or generic basenames to prevent matching everything
    if not base or base == '*':
        return None
    # Require at least one token of 3+ letters to avoid generic matches
    if not re.search(r'[A-Za-z]{3,}', base):
        return None
    # Escape regex, then re-enable wildcard
    rx = re.escape(base).replace(r'\*', '.*')
    return re.compile(rx, re.IGNORECASE)


GUID_PAT = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def read_text_for_scan(p: Path) -> str:
    if p.suffix == '.bin':
        # Best-effort; keep ASCII strings
        return p.read_bytes().decode('utf-8', errors='ignore')
    return p.read_text(errors='ignore')


def scan_files(asr_dir: Path, regexes: list[re.Pattern]) -> tuple[set[str], set[str]]:
    matched_files: set[str] = set()
    guids: set[str] = set()
    for path in sorted(list(asr_dir.glob('*.bin')) + list(asr_dir.glob('*.bin.txt'))):
        text = read_text_for_scan(path)
        if any(r.search(text) for r in regexes):
            matched_files.add(path.name)
            guids.update(g.lower() for g in GUID_PAT.findall(text))
    return matched_files, guids


def main() -> None:
    ap = argparse.ArgumentParser(description='Scan ASR Lua for LOLRMM installation paths')
    ap.add_argument('--url', default='https://lolrmm.io/api/rmm_tools.json', help='LOLRMM tools JSON URL')
    ap.add_argument('--asr-dir', default='asr_lua', help='Directory with .bin and .bin.txt')
    ap.add_argument('--output', default='asr_rmm_lolrmm_matches.csv', help='Output CSV path')
    args = ap.parse_args()

    tools = fetch_lolrmm(args.url)
    asr_dir = Path(args.asr_dir)

    rows: list[dict] = []
    for t in tools:
        name = t.get('Name', '')
        details = t.get('Details', {}) or {}
        install_paths = details.get('InstallationPaths', []) or []
        if not install_paths:
            continue
        regexes = []
        for p in install_paths:
            if not isinstance(p, str) or not p.strip():
                continue
            r = path_to_regex(p)
            if r is not None:
                regexes.append(r)
        if not regexes:
            continue
        matched_files, guids = scan_files(asr_dir, regexes)
        rows.append({
            'rmm_name': name,
            'indicators': ';'.join(install_paths),
            'matched_files': ';'.join(sorted(matched_files)),
            'match_count': len(matched_files),
            'guids': ';'.join(sorted(guids)),
        })

    with open(args.output, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rmm_name', 'indicators', 'matched_files', 'match_count', 'guids'])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f'Wrote {args.output} with {len(rows)} rows')


if __name__ == '__main__':
    main()


