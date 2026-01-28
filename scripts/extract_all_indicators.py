#!/usr/bin/env python3
import argparse
import csv
import json
import re
from pathlib import Path


RMM_GUID = 'd7c7c745-195f-4223-9c7a-99fb420fd000'


def iter_lua_strings_from_txt(text: str):
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
        return True
    return False


def basename_from_pattern(p: str) -> str:
    p = p.replace('\\', '/').rstrip()
    base = p.rsplit('/', 1)[-1]
    base = base.strip('*').strip().lower()
    return base


def main():
    ap = argparse.ArgumentParser(description='Extract ALL indicators present in ASR LUA (no external filtering)')
    ap.add_argument('--asr-dir', default='asr_lua', help='Directory with .bin and .bin.txt')
    ap.add_argument('--dump-json', default='asr_dump.json', help='asr_dump.json with rule names/descriptions and GUIDs')
    ap.add_argument('--out', default='asr_indicators_all_with_names.csv')
    args = ap.parse_args()

    # Map: file -> name, file -> guids
    file_to_name: dict[str, str] = {}
    file_to_guids: dict[str, set[str]] = {}
    dump_path = Path(args.dump_json)
    if dump_path.exists():
        dump = json.loads(dump_path.read_text())
        for e in dump:
            fname = e.get('file') or ''
            name = (e.get('name') or '').strip()
            if fname and name:
                file_to_name[fname] = name
            guids = set()
            for key in ('guids', 'strings_guid'):
                vals = e.get(key) or []
                for g in vals:
                    if isinstance(g, str) and g:
                        guids.add(g.lower())
            if fname and guids:
                file_to_guids.setdefault(fname, set()).update(guids)

    asr_dir = Path(args.asr_dir)
    indicator_to_files: dict[str, set[str]] = {}
    indicator_to_example: dict[str, str] = {}

    files = list(sorted(asr_dir.glob('*.bin'))) + list(sorted(asr_dir.glob('*.bin.txt')))
    for p in files:
        candidates: list[str] = []
        if p.suffix == '.txt':
            candidates.extend(iter_lua_strings_from_txt(p.read_text(errors='ignore')))
        else:
            candidates.extend(extract_ascii_strings(p.read_bytes()))
        for s in candidates:
            if not is_indicator_string(s):
                continue
            base = basename_from_pattern(s)
            if not base:
                continue
            indicator_to_files.setdefault(base, set()).add(p.name)
            indicator_to_example.setdefault(base, s)

    out_path = Path(args.out)
    with out_path.open('w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['indicator_basename', 'example_string', 'matched_files', 'count_files', 'rule_names', 'guids', 'has_rmm_guid'])
        for ind, fileset in sorted(indicator_to_files.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            names = sorted({file_to_name.get(fn, '') for fn in fileset if file_to_name.get(fn, '')})
            guids = set()
            for fn in fileset:
                guids.update(file_to_guids.get(fn, set()))
            w.writerow([
                ind,
                indicator_to_example.get(ind, ''),
                ';'.join(sorted(fileset)),
                len(fileset),
                ';'.join(names),
                ';'.join(sorted(guids)),
                'yes' if RMM_GUID in guids else 'no',
            ])
    print(f'Wrote {out_path} with {len(indicator_to_files)} indicators')


if __name__ == '__main__':
    main()



