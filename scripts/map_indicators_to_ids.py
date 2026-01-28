#!/usr/bin/env python3
import argparse
import csv
import json
import re
from pathlib import Path

GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def is_indicator_string(s: str) -> bool:
    sl = s.lower()
    if '.exe' in sl or '.dll' in sl:
        return True
    if '\\' in s or '/' in s or '%' in s:
        return True
    return False


def extract_strings_from_line(line: str) -> list[str]:
    # luadec places human-readable strings after ';'
    # Example: ; R0["%programfiles%\\Zscaler\\ZSAUpm\\ZSAUpm.exe"] := 2
    out = []
    # capture anything in double quotes in the comment part
    if ';' in line:
        comment = line.split(';', 1)[1]
        out += re.findall(r'"([^"]+)"', comment)
    return out


def nearest_guid_for_line(idx: int, guid_positions: list[tuple[int, str]]) -> tuple[str, int] | tuple[None, None]:
    if not guid_positions:
        return (None, None)
    # Find guid with minimal absolute distance to idx
    best = None
    best_dist = None
    for (gline, guid) in guid_positions:
        d = abs(gline - idx)
        if best is None or d < best_dist:
            best = guid
            best_dist = d
    return (best, best_dist if best is not None else None)


def load_rule_names(dump_json: Path) -> dict[str, str]:
    names: dict[str, str] = {}
    if dump_json.exists():
        try:
            data = json.loads(dump_json.read_text())
            for e in data:
                fname = e.get('file') or ''
                name = (e.get('name') or '').strip()
                if fname and name:
                    names[fname] = name
        except Exception:
            pass
    return names


def main():
    ap = argparse.ArgumentParser(description='Map ASR indicator strings to nearest ASR GUID and rule name')
    ap.add_argument('--txt-dir', default='asr_dump_txt', help='Directory with copied .bin.txt files')
    ap.add_argument('--dump-json', default='asr_dump.json')
    ap.add_argument('--out', default='asr_indicator_id_map.csv')
    args = ap.parse_args()

    rule_names = load_rule_names(Path(args.dump_json))

    rows: list[list[str]] = []
    txt_dir = Path(args.txt_dir)
    for p in sorted(txt_dir.glob('asr_lua_*.bin.txt')):
        lines = p.read_text(errors='ignore').splitlines()
        # collect guid occurrences with line numbers
        guid_positions: list[tuple[int, str]] = []
        for i, line in enumerate(lines, start=1):
            for g in GUID_RE.findall(line):
                guid_positions.append((i, g.lower()))

        # collect indicator strings and map to nearest guid
        for i, line in enumerate(lines, start=1):
            for s in extract_strings_from_line(line):
                if not is_indicator_string(s):
                    continue
                guid, dist = nearest_guid_for_line(i, guid_positions)
                rows.append([
                    s,
                    p.name.replace('.txt', ''),
                    rule_names.get(p.name.replace('.txt', ''), ''),
                    guid or '',
                    str(dist) if dist is not None else '',
                    str(i),
                ])

    with open(args.out, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['indicator', 'asr_file', 'rule_name', 'nearest_guid', 'guid_line_distance', 'line_no'])
        for r in rows:
            w.writerow(r)
    print(f'Wrote {args.out} with {len(rows)} rows')


if __name__ == '__main__':
    main()



