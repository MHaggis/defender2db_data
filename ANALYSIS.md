# ASR Analysis Pipeline

This document describes the automated analysis pipeline that extracts intelligence from Microsoft Defender ASR (Attack Surface Reduction) rules.

## Pipeline Overview

The pipeline runs daily via GitHub Actions and consists of 7 analysis stages that generate comprehensive intelligence artifacts.

```
┌─────────────────┐
│ Update ASR Lua  │  Downloads & extracts latest ASR rules from Microsoft
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Scan for RMM   │  Identifies RMM vendor strings in rules
└────────┬────────┘
         │
         v
┌─────────────────┐
│ LOLRMM X-Ref    │  Cross-references with LOLRMM.io dataset
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Generate Summary│  Creates high-level RMM detection summary
└────────┬────────┘
         │
         v
┌─────────────────┐
│   Dump ASR      │  Comprehensive dump with strings, GUIDs, paths
└────────┬────────┘
         │
         v
┌─────────────────┐
│Extract Indicators│ Extracts all IoCs (796+)
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Unknown IoCs    │  Finds non-RMM indicators (791+)
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Map to IDs     │  Maps indicators to ASR rule GUIDs (2369+)
└─────────────────┘
```

## Generated Artifacts

### Core Files (Daily Updates)
- `asr_lua/` - 25 ASR rules in Lua bytecode + decompiled text
- `asr_index.csv` - File inventory with SHA256 hashes (4.3KB)

### RMM Detection Intelligence
- `asr_rmm_index.csv` - RMM vendor references in ASR rules (4.5KB)
- `asr_rmm_lolrmm_matches.csv` - Full LOLRMM cross-reference (24KB, 246 tools)
- `asr_rmm_summary.csv` - High-level summary (2.4KB, 16 matched tools)

### Comprehensive Analysis
- `asr_dump.json` - Full structured dump with metadata (139KB)
- `asr_dump.csv` - CSV version of dump (12KB)

### Indicator Extraction
- `asr_indicators_all_with_names.csv` - All indicators with rule context (227KB, 796 IoCs)
- `asr_indicators_unknown.csv` - Non-RMM indicators only (78KB)
- `asr_indicators_unknown_with_names.csv` - Unknown indicators with context (226KB, 791 IoCs)
- `asr_indicator_id_map.csv` - Indicator→GUID mapping (367KB, 2369 mappings)
- `asr_targets_from_txt.csv` - Extracted targets from decompiled Lua (49KB)

**Total artifact size: ~1.1MB** (very git-friendly!)

## Key Findings

### RMM Tools Actively Targeted by Microsoft ASR Rules

Microsoft's ASR rules detect these **16+ legitimate RMM tools**:

| RMM Tool | Match Count | ASR Rule(s) |
|----------|-------------|-------------|
| RuDesktop | 6 files | Office child process blocks, Adobe child process, Office comms |
| RemoteView | 4 files | LSASS credential theft, Office comms |
| LabTech/ConnectWise Automate | 2 files | LSASS credential theft |
| Adobe Connect | 2 files | Execution blocks |
| Site24x7 | 2 files | LSASS credential theft |
| Rapid7 | 2 files | LSASS credential theft |
| BeAnyWhere | 2 files | LSASS credential theft |
| Parsec | 2 files | LSASS credential theft |
| MSP360 | 2 files | Execution blocks |
| Itarian | 2 files | Office comms |
| ManageEngine | 2 files | LSASS credential theft |
| Zoho Assist | 2 files | Execution blocks |
| Atera | 2 files | Execution blocks |

### Most Targeted ASR Rules

1. **asr_lua_21.bin** - "Block credential stealing from LSASS"
   - Targets: ConnectWise, ManageEngine, Site24x7, Rapid7, BeAnyWhere, Parsec, and more
   - Detects: Dameware, ManageEngine, N-able

2. **asr_lua_23.bin** - "Block all Office applications from creating child processes"
   - Targets: RuDesktop
   - Critical for blocking Office-based lateral movement

3. **asr_lua_24.bin** - "Block Office communication apps from creating child processes"
   - Targets: RemoteView, Itarian, RuDesktop
   - Focuses on Outlook/Teams child process creation

## Intelligence Use Cases

### For Blue Teams
- **Baseline legitimate tools** - Know which RMM tools may trigger ASR rules
- **False positive planning** - Exclude known-good RMM tools before ASR deployment
- **Change detection** - Track when Microsoft adds new detections
- **Threat hunting** - Use extracted IoCs for proactive searches

### For Red Teams
- **ASR evasion research** - Understand what behaviors trigger rules
- **Tool selection** - Avoid RMM tools actively targeted by ASR
- **Payload development** - Design around known detection logic
- **Client communication** - Explain why certain tools trigger alerts

### For Threat Intelligence
- **Microsoft's priorities** - See what Microsoft considers high-risk
- **Trend analysis** - Track rule additions/changes over time
- **TTPs correlation** - Map ASR rules to MITRE ATT&CK
- **Emerging threats** - Identify new detection logic as it's added

## Script Reference

| Script | Purpose | Output | Network Required |
|--------|---------|--------|------------------|
| `update_asr.py` | Downloads & extracts ASR rules | `asr_lua/`, `asr_index.csv` | Yes (Microsoft CDN) |
| `scan_rmm.py` | Scans for RMM vendor strings | `asr_rmm_index.csv` | No |
| `scan_lolrmm.py` | Cross-refs LOLRMM dataset | `asr_rmm_lolrmm_matches.csv` | Yes (lolrmm.io) |
| `generate_summary.py` | Creates RMM summary | `asr_rmm_summary.csv` | No |
| `dump_asr.py` | Comprehensive ASR dump | `asr_dump.json/csv` | No |
| `extract_all_indicators.py` | Extracts all IoCs | `asr_indicators_all_with_names.csv` | No |
| `extract_unknown_indicators.py` | Finds non-RMM IoCs | `asr_indicators_unknown_with_names.csv` | Yes (lolrmm.io) |
| `map_indicators_to_ids.py` | Maps IoCs to GUIDs | `asr_indicator_id_map.csv` | No |
| `diff-asr.py` | Compares ASR changes | Terminal output | No |

## Running Locally

```bash
# Full pipeline
python scripts/update_asr.py
python scripts/scan_rmm.py
python scripts/scan_lolrmm.py
python scripts/generate_summary.py
python scripts/dump_asr.py
python scripts/extract_all_indicators.py
python scripts/extract_unknown_indicators.py
python scripts/map_indicators_to_ids.py

# Or individually analyze existing data (no download)
python scripts/scan_rmm.py  # Fast, no network
python scripts/dump_asr.py  # Fast, no network
```

## GitHub Actions Workflow

The workflow (`.github/workflows/update-asr.yml`):
- Runs daily at **06:23 UTC**
- Can be manually triggered via Actions tab
- Uses **Python 3.11** on Ubuntu latest
- Downloads **luadec** for Lua decompilation
- Skips **Git LFS** downloads (saves bandwidth, fetches fresh data instead)
- Commits all analysis artifacts automatically
- Commit message includes date: `chore: update ASR Lua and analysis artifacts [YYYY-MM-DD]`

## Data Retention

### Committed to Git
- All CSV/JSON analysis artifacts (~1.1MB total)
- ASR Lua bytecode and decompiled text
- Index files for change tracking

### Excluded from Git (`.gitignore`)
- `asr_dump_hex/` - Hexdumps (too large, regenerable)
- `asr_dump_strings/` - ASCII strings (redundant with JSON)
- `asr_dump_txt/` - Copied txt files (redundant with asr_lua/)
- Virtual environments

### Git LFS (Not Downloaded by CI)
- `*.db` - SQLite threat databases
- `*.pickle` - Serialized signature data
- `*.vdm` - Defender signature files
- `*.dll` - Engine binaries

## Insights & Statistics

As of the last run:
- **25 ASR rules** actively deployed by Microsoft
- **796 total indicators** extracted
- **791 unknown indicators** (not in LOLRMM dataset)
- **16 RMM tools** matched in ASR rules
- **246 total RMM tools** checked against rules
- **2369 indicator→GUID mappings** created

## Future Enhancements

Potential additions:
- MITRE ATT&CK technique mapping
- ASR rule timeline visualization
- Automated diff reports on changes
- Threat actor TTP correlation
- EDR rule comparisons (CrowdStrike, SentinelOne, etc.)

## Credits

- [defender2db](https://github.com/dobin/defender2db/) - Core extraction tooling
- [LOLRMM.io](https://lolrmm.io) - RMM tool reference dataset
- Microsoft Defender team - For ASR rules

---

**Last Updated**: Auto-generated by GitHub Actions
**Data Source**: Microsoft Defender Update Channel
**Analysis Pipeline Version**: 1.0
