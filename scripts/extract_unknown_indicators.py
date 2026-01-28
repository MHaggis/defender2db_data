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


def iter_lua_strings_from_txt(text: str):
    # Capture luadec-disassembled string constants
    for m in re.finditer(r':=\s*"([^"]+)"', text):
        yield m.group(1)


def extract_ascii_strings(data: bytes, min_len: int = 4):
    s = []
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                s.append(cur.decode('ascii', errors='ignore'))
            cur = bytearray()
    if len(cur) >= min_len:
        s.append(cur.decode('ascii', errors='ignore'))
    return s


def is_indicator_string(s: str) -> bool:
    sl = s.lower()
    if '.exe' in sl or '.dll' in sl:
        return True
    if '\\' in s or '/' in s or '%' in s:
        # likely a path or env-based pattern
        return True
    return False


def basename_from_pattern(p: str) -> str:
    # Normalize path separators and wildcards
    p = p.replace('\\', '/').rstrip()
    base = p.rsplit('/', 1)[-1]
    # Strip simple wildcard suffixes
    base = base.strip('*')
    return base.lower()


def main():
    ap = argparse.ArgumentParser(description='Extract indicators present in ASR LUA not covered by LOLRMM dataset')
    ap.add_argument('--asr-dir', default='asr_lua', help='Directory with .bin and .bin.txt')
    ap.add_argument('--lolrmm-url', default='https://lolrmm.io/api/rmm_tools.json')
    ap.add_argument('--dump-json', default='asr_dump.json', help='asr_dump.json with rule names/descriptions')
    ap.add_argument('--out', default='asr_indicators_unknown_with_names.csv')
    args = ap.parse_args()

    # Build known basenames set from LOLRMM InstallationPaths
    tools = fetch_lolrmm(args.lolrmm_url)
    known_basenames: set[str] = set()
    for t in tools:
        details = t.get('Details') or {}
        paths = details.get('InstallationPaths') or []
        for pat in paths:
            if not isinstance(pat, str) or not pat.strip():
                continue
            bn = basename_from_pattern(pat)
            if bn:
                known_basenames.add(bn)

    # Build map from asr file -> rule name and GUIDs (if available)
    file_to_name: dict[str, str] = {}
    file_to_guids: dict[str, set[str]] = {}
    dump_path = Path(args.dump_json)
    if dump_path.exists():
        try:
            dump = json.loads(dump_path.read_text())
            for e in dump:
                fname = e.get('file') or ''
                name = (e.get('name') or '').strip()
                if fname and name:
                    file_to_name[fname] = name
                # Collect GUIDs from txt parse and from strings
                guids = set()
                for key in ('guids', 'strings_guid'):
                    vals = e.get(key) or []
                    for g in vals:
                        if isinstance(g, str) and g:
                            guids.add(g.lower())
                if fname and guids:
                    file_to_guids.setdefault(fname, set()).update(guids)
        except Exception:
            pass

    # Walk ASR files and collect candidate indicators
    asr_dir = Path(args.asr_dir)
    indicator_to_files: dict[str, set[str]] = {}
    indicator_to_example: dict[str, str] = {}

    files = list(sorted(asr_dir.glob('*.bin'))) + list(sorted(asr_dir.glob('*.bin.txt')))
    for p in files:
        text_candidates: list[str] = []
        if p.suffix == '.txt':
            txt = p.read_text(errors='ignore')
            text_candidates.extend(iter_lua_strings_from_txt(txt))
        else:
            data = p.read_bytes()
            text_candidates.extend(extract_ascii_strings(data))

        for s in text_candidates:
            if not is_indicator_string(s):
                continue
            base = basename_from_pattern(s)
            if not base:
                continue
            # Skip if covered by LOLRMM
            if base in known_basenames:
                continue
            # Skip obviously generic base names
            if base in {'true', 'false', 'nil', 'null'}:
                continue
            indicator_to_files.setdefault(base, set()).add(p.name)
            indicator_to_example.setdefault(base, s)

    # Write CSV
    out_path = Path(args.out)
    with out_path.open('w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['indicator_basename', 'example_string', 'matched_files', 'count_files', 'rule_names', 'guids', 'has_rmm_guid'])
        for ind, fileset in sorted(indicator_to_files.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            names = sorted({file_to_name.get(fn, '') for fn in fileset if file_to_name.get(fn, '')})
            # Aggregate GUIDs across matched files
            guids = set()
            for fn in fileset:
                guids.update(file_to_guids.get(fn, set()))
            guids_out = ';'.join(sorted(guids))
            has_rmm_guid = 'yes' if 'd7c7c745-195f-4223-9c7a-99fb420fd000' in guids else 'no'
            w.writerow([
                ind,
                indicator_to_example.get(ind, ''),
                ';'.join(sorted(fileset)),
                len(fileset),
                ';'.join(names),
                guids_out,
                has_rmm_guid,
            ])

    print(f'Wrote {out_path} with {len(indicator_to_files)} indicators')


if __name__ == '__main__':
    main()


