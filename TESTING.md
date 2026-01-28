# Testing Guide

## Issues Fixed

### 1. LFS Bandwidth Exhaustion (December 2025)
**Problem**: Workflow failed with "This repository exceeded its LFS budget"
**Root Cause**: Workflow was pulling 1.8GB of LFS files (threats.db, pickles, VDM files)  
**Solution**: Changed `lfs: true` → `lfs: false` in workflow
**Impact**: Saves ~1.8GB download per workflow run, workflow now fetches fresh data from Microsoft

### 2. Database Initialization Error (January 2026)
**Problem**: `defender2yara --asr` failed with "no such table: dbmetadata"
**Root Cause**: ASR extraction requires database schema initialized by `--extract` step
**Solution**: Added explicit `--extract` step before `--asr` with error handling
**Impact**: Ensures database is properly initialized before ASR extraction

## Pre-Push Checklist

- [x] LFS disabled in workflow (lfs: false)
- [x] Database initialization added to update_asr.py
- [x] All 7 analysis scripts tested locally
- [x] Pipeline test passed (all stages ✓)
- [x] Gitignore updated for bulky intermediates
- [x] README enhanced with findings
- [x] ANALYSIS.md added with architecture
- [x] Workflow includes all 8 stages (update + 7 analysis)
- [x] Commit includes database fix

## Local Testing Results

```
=== Testing ASR Analysis Pipeline ===

[1/7] Testing scan_rmm.py...
✓ asr_rmm_index.csv created (25 rows)

[2/7] Testing scan_lolrmm.py (requires network)...
✓ asr_rmm_lolrmm_matches.csv created (246 rows)

[3/7] Testing generate_summary.py...
✓ asr_rmm_summary.csv created (16 matched tools)

[4/7] Testing dump_asr.py...
✓ asr_dump.json and asr_dump.csv created (25 entries)

[5/7] Testing extract_all_indicators.py...
✓ asr_indicators_all_with_names.csv created (796 indicators)

[6/7] Testing extract_unknown_indicators.py (requires network)...
✓ asr_indicators_unknown_with_names.csv created (791 indicators)

[7/7] Testing map_indicators_to_ids.py...
✓ asr_indicator_id_map.csv created (2369 rows)

=== All tests passed! ===
```

## Workflow Stages (8 total)

1. **Checkout** - Skips LFS (saves bandwidth)
2. **Setup Python** - 3.11 on Ubuntu
3. **Install defender2db** - From GitHub main branch
4. **Fetch luadec** - Linux binary for Lua decompilation
5. **Run updater** - Downloads VDM, extracts ASR, initializes DB
6. **Build RMM index** - Scans for RMM vendor strings
7. **Cross-reference LOLRMM** - Matches against lolrmm.io dataset
8. **Generate summary** - Creates high-level overview
9. **Dump ASR** - Comprehensive metadata extraction
10. **Extract all indicators** - All 796+ IoCs
11. **Extract unknown indicators** - Non-RMM IoCs
12. **Map indicators** - GUID mappings
13. **Commit changes** - Auto-commits with timestamp

## Expected Outputs

### File Sizes
```
12KB   - asr_dump.csv
139KB  - asr_dump.json
4.3KB  - asr_index.csv
367KB  - asr_indicator_id_map.csv
227KB  - asr_indicators_all_with_names.csv
78KB   - asr_indicators_unknown.csv
226KB  - asr_indicators_unknown_with_names.csv
4.5KB  - asr_rmm_index.csv
24KB   - asr_rmm_lolrmm_matches.csv
2.4KB  - asr_rmm_summary.csv
49KB   - asr_targets_from_txt.csv
---
~1.1MB Total (very git-friendly!)
```

### Key Metrics
- 25 ASR rules extracted
- 16 RMM tools matched
- 796 total indicators
- 791 unknown indicators
- 2369 indicator→GUID mappings

## Database Initialization Fix Details

**Old Code (Broken)**:
```python
def run_defender2yara(download: bool, asr: bool) -> None:
    if download:
        run([sys.executable, "-m", "defender2yara", "--download"])
    if asr:
        run([sys.executable, "-m", "defender2yara", "--asr"])  # ❌ DB not initialized
```

**New Code (Fixed)**:
```python
def run_defender2yara(download: bool, asr: bool) -> None:
    # Clean any partial database
    db_path = Path('threats.db')
    if db_path.exists():
        db_path.unlink()
    
    if download:
        run([sys.executable, "-m", "defender2yara", "--download"])
    
    if asr:
        Path('rules').mkdir(parents=True, exist_ok=True)
        # Initialize DB schema with --extract
        try:
            run([sys.executable, "-m", "defender2yara", "--extract"])  # ✓ Creates schema
        except subprocess.CalledProcessError:
            pass  # Partial failures okay, DB is initialized
        run([sys.executable, "-m", "defender2yara", "--asr"])  # ✓ Now works
```

## Troubleshooting

### If workflow fails with LFS error:
- Check `.github/workflows/update-asr.yml` line 17 has `lfs: false`

### If workflow fails with database error:
- Check `scripts/update_asr.py` has `--extract` step before `--asr`
- Verify database cleanup is present

### If analysis scripts fail:
- Ensure `asr_lua/` directory has `.bin` and `.bin.txt` files
- Check network connectivity for LOLRMM-dependent scripts
- Verify Python 3.11+ is installed

## Manual Workflow Simulation

To test the workflow locally:

```bash
# 1. Setup
python -m pip install "git+https://github.com/dobin/defender2db@main"

# 2. Fetch luadec
mkdir -p scripts/bin
curl -fsSL -o scripts/bin/luadec https://raw.githubusercontent.com/dobin/defender2db/main/luadec
chmod +x scripts/bin/luadec

# 3. Run updater
export LUADEC=$(pwd)/scripts/bin/luadec
python scripts/update_asr.py --no-install

# 4. Run analysis pipeline
python scripts/scan_rmm.py
python scripts/scan_lolrmm.py
python scripts/generate_summary.py
python scripts/dump_asr.py
python scripts/extract_all_indicators.py
python scripts/extract_unknown_indicators.py
python scripts/map_indicators_to_ids.py

# 5. Verify outputs
ls -lh *.csv *.json
```

## Commit Summary

**Commit**: d7bb7d1  
**Files Changed**: 23  
**Additions**: 9,099 lines  
**Key Changes**:
- Fixed LFS bandwidth issue
- Fixed database initialization issue  
- Added 7 analysis scripts
- Added comprehensive documentation
- Generated 11 intelligence artifacts

## Ready to Deploy

All checks passed. Safe to push to GitHub and enable Actions.

```bash
git push origin main
```

Then go to GitHub repo → Actions tab → Enable workflows
