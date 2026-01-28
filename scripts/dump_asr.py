#!/usr/bin/env python3
import argparse
import csv
import json
import re
import shutil
from pathlib import Path

GUID_PAT = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
PATH_HINT = re.compile(r"(?i)(%\w+%|[A-Za-z]:\\\\|/usr/|/etc/|/opt/|/Applications/|Program Files|ProgramData|AppData|Users|System32|SysWOW64|\\\\)".encode())


def read_bin_strings(p: Path) -> list[str]:
    data = p.read_bytes()
    out: list[str] = []
    cur: bytearray = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= 4:
                out.append(cur.decode('ascii', errors='ignore'))
            cur = bytearray()
    if len(cur) >= 4:
        out.append(cur.decode('ascii', errors='ignore'))
    return out


def parse_txt(p: Path) -> dict:
    text = p.read_text(errors='ignore')
    # Try to extract Name/Description
    name = None
    desc = None
    m = re.search(r'\["Name"\]\s*:?=\s*"([^"]+)"', text)
    if m:
        name = m.group(1)
    m = re.search(r'\["Description"\]\s*:?=\s*"([^"]+)"', text)
    if m:
        desc = m.group(1)
    guids = sorted(set(x.lower() for x in GUID_PAT.findall(text)))
    return {'name': name or '', 'description': desc or '', 'guids': guids}


def main():
    ap = argparse.ArgumentParser(description='Dump ASR Lua artifacts into JSON and CSV')
    ap.add_argument('--asr-dir', default='asr_lua', help='Directory with .bin and .bin.txt')
    ap.add_argument('--json-out', default='asr_dump.json')
    ap.add_argument('--csv-out', default='asr_dump.csv')
    ap.add_argument('--strings-dir', default='asr_dump_strings', help='Output dir for full ASCII strings per bin')
    ap.add_argument('--hex-dir', default='asr_dump_hex', help='Output dir for full hexdump per bin')
    ap.add_argument('--txt-dir', default='asr_dump_txt', help='Output dir to copy .bin.txt for convenience')
    args = ap.parse_args()

    root = Path(args.asr_dir)
    strings_root = Path(args.strings_dir); strings_root.mkdir(parents=True, exist_ok=True)
    hex_root = Path(args.hex_dir); hex_root.mkdir(parents=True, exist_ok=True)
    txt_root = Path(args.txt_dir); txt_root.mkdir(parents=True, exist_ok=True)
    entries: list[dict] = []
    for p in sorted(root.glob('asr_lua_*.bin')):
        entry: dict = {'file': p.name}
        # Strings from bin
        strings = read_bin_strings(p)
        entry['strings_sample'] = strings[:200]
        entry['strings_count'] = len(strings)
        entry['strings_guid'] = sorted(set(x.lower() for x in GUID_PAT.findall('\n'.join(strings))))
        entry['strings_paths'] = [s for s in strings if PATH_HINT.search(s.encode())][:200]
        # Write full strings file
        strings_file = strings_root / f"{p.name}.strings.txt"
        strings_file.write_text('\n'.join(strings))
        entry['strings_file'] = str(strings_file)

        # Write full hexdump
        data = p.read_bytes()
        def _hexdump(b: bytes, width: int = 16) -> str:
            lines = []
            for off in range(0, len(b), width):
                chunk = b[off:off+width]
                hexs = ' '.join(f"{x:02x}" for x in chunk)
                ascii_ = ''.join(chr(x) if 32 <= x <= 126 else '.' for x in chunk)
                lines.append(f"{off:08x}  {hexs:<{width*3}}  |{ascii_}|")
            return '\n'.join(lines)
        hex_file = hex_root / f"{p.name}.hex.txt"
        hex_file.write_text(_hexdump(data))
        entry['hex_file'] = str(hex_file)

        # If txt is available, parse
        txt = p.with_suffix(p.suffix + '.txt')
        if txt.exists():
            meta = parse_txt(txt)
            entry.update(meta)
            # Copy txt for centralized review
            dst = txt_root / txt.name
            try:
                shutil.copy2(txt, dst)
                entry['txt_file'] = str(dst)
            except Exception:
                entry['txt_file'] = str(txt)

        entries.append(entry)

    Path(args.json_out).write_text(json.dumps(entries, indent=2))

    with open(args.csv_out, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['file', 'name', 'description', 'strings_count', 'guid_in_txt', 'guid_in_bin', 'path_strings_sample'])
        for e in entries:
            w.writerow([
                e.get('file',''),
                e.get('name',''),
                e.get('description',''),
                e.get('strings_count',0),
                ';'.join(e.get('guids', [])),
                ';'.join(e.get('strings_guid', [])),
                ';'.join(e.get('strings_paths', [])[:20]),
            ])
    print(f"Wrote {args.json_out} and {args.csv_out} with {len(entries)} entries")


if __name__ == '__main__':
    main()


