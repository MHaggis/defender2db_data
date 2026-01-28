#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(description='Generate RMM summary from LOLRMM matches')
    ap.add_argument('--input', default='asr_rmm_lolrmm_matches.csv', help='Input LOLRMM matches CSV')
    ap.add_argument('--output', default='asr_rmm_summary.csv', help='Output summary CSV')
    ap.add_argument('--min-matches', type=int, default=1, help='Minimum matches to include')
    args = ap.parse_args()

    rows = []
    with open(args.input, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            count = int(row.get('match_count', 0))
            if count >= args.min_matches:
                # Truncate indicators for summary (first 5)
                indicators = row.get('indicators', '').split(';')
                sample = ';'.join(indicators[:5])
                if len(indicators) > 5:
                    sample += f';...({len(indicators)-5} more)'
                
                rows.append({
                    'rmm_name': row.get('rmm_name', ''),
                    'sample_indicators': sample,
                    'asr_files': row.get('matched_files', ''),
                    'count_files': count,
                    'guids': row.get('guids', ''),
                })
    
    # Sort by match count descending
    rows.sort(key=lambda x: x['count_files'], reverse=True)
    
    with open(args.output, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rmm_name', 'sample_indicators', 'asr_files', 'count_files', 'guids'])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    
    print(f'Wrote {args.output} with {len(rows)} matched RMM tools')


if __name__ == '__main__':
    main()
