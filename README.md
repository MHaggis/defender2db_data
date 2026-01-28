# Defender2db_data

Automated extraction and analysis of Microsoft Defender Attack Surface Reduction (ASR) rules with daily updates.

## What's Inside

Data extracted with [defender2db](https://github.com/dobin/defender2db/):

### Core Data
* `asr_lua/` - ASR (Attack Surface Reduction) rules in Lua bytecode and decompiled text
* `asr_index.csv` - File inventory with SHA256 hashes for tracking changes
* `engine/` and `vdm/` - Defender VDM signature files (Git LFS)
* `threats.db` - Threat signatures as SQLite database (Git LFS)
* `mpas.vdm.pickle` and `mpav.vdm.pickle` - Signatures as pickle files (Git LFS)

### Analysis Artifacts (Generated Daily)
* `asr_dump.json` / `asr_dump.csv` - Comprehensive dump of all ASR rules with metadata, GUIDs, and path strings
* `asr_rmm_index.csv` - RMM (Remote Monitoring & Management) tool references found in ASR rules
* `asr_rmm_lolrmm_matches.csv` - Cross-reference with [LOLRMM](https://lolrmm.io) dataset (16+ tools detected!)
* `asr_rmm_summary.csv` - High-level summary of RMM detection coverage
* `asr_indicators_all_with_names.csv` - All extracted indicators (796+) with rule names
* `asr_indicators_unknown.csv` - Indicators not matching known RMM tools
* `asr_indicators_unknown_with_names.csv` - Unknown indicators with context (791+)
* `asr_indicator_id_map.csv` - Mapping of indicators to ASR rule IDs (2369+ entries)
* `asr_targets_from_txt.csv` - Target extraction from decompiled Lua

### RMM Tools Detected in ASR Rules
Microsoft's ASR rules actively target these legitimate remote management tools:
- **ConnectWise** (LabTech/Automate, ScreenConnect)
- **ManageEngine** (Desktop Central)
- **Atera** Networks
- **Zoho Assist**
- **Site24x7**
- **Rapid7**
- **BeAnyWhere**
- **Parsec**
- **MSP360**
- **Itarian**
- **RuDesktop**
- **RemoteView**
- **Adobe Connect**
- ...and more!

> **Note**: Git LFS files (`.db`, `.pickle`, `.vdm`, `.dll`) are not downloaded by GitHub Actions workflow to avoid bandwidth costs. The workflow fetches fresh data from Microsoft daily instead. 

## Windows quickstart (automated)

- Install Python 3.11+ and Git.
- Open PowerShell, then run the updater:

```
pwsh -File scripts/update-asr.ps1
```

What it does:
- Installs `defender2db` tooling directly from GitHub ([dobin/defender2db](https://github.com/dobin/defender2db/)).
- Downloads latest Defender VDM/engine, extracts ASR Lua, and updates `asr_lua/`.
- Writes an index file at `asr_index.csv` for quick diffs.

## GitHub Actions (Automated Daily Updates)

This repo includes a workflow at `.github/workflows/update-asr.yml` that:
- **Runs daily at 06:23 UTC** and on manual trigger
- Fetches latest Microsoft Defender signatures
- Extracts and decompiles ASR Lua rules
- Scans for RMM tool references
- Cross-references with LOLRMM.io dataset
- Extracts all indicators and creates comprehensive analysis artifacts
- Commits changes automatically

The workflow:
1. Downloads fresh VDM files from Microsoft
2. Extracts ASR Lua bytecode with `defender2db`
3. Decompiles Lua to readable text with `luadec`
4. Runs analysis pipeline:
   - `scan_rmm.py` - Finds RMM vendor strings
   - `scan_lolrmm.py` - Matches against LOLRMM.io dataset
   - `dump_asr.py` - Creates comprehensive dumps
   - `extract_all_indicators.py` - Extracts all IoCs
   - `extract_unknown_indicators.py` - Finds non-RMM indicators
   - `map_indicators_to_ids.py` - Maps indicators to rule GUIDs
5. Commits all analysis artifacts

Enable it by pushing to your fork and ensuring Actions are enabled.

## Manual notes

If you want to run the upstream tool yourself:

1. Install Python 3.11+.
2. In an empty working directory, run:

```
python -m pip install --upgrade pip
python -m pip install "git+https://github.com/dobin/defender2db@main"
python -m defender2yara --download
python -m defender2yara --asr
```

ASR rules will be in the tool's `result/asr_rules/`. Copy them into this repo's `asr_lua/` to analyze and commit.

## macOS quickstart (Python)

- Ensure Python 3.11+ is installed (e.g., via Homebrew).
- From the repo root, run:

```
python3 scripts/update_asr.py
```

Outputs:
- `asr_lua/` synchronized with latest extracted ASR Lua.
- `asr_index.csv` for change tracking.
- `.bin.txt` decompiled files (if `luadec` available) for readable diffing.

Notes on decompilation:
- Upstream `--asr` produces `.bin` files only ([dobin/defender2db](https://github.com/dobin/defender2db/)).
- This repo adds readable `.bin.txt` via decompilers:
  - Tries `luadec` first.
  - Falls back to `unluac.jar` if available (Java required).
- Provide tools one of these ways:
  - Put `luadec` at `scripts/bin/luadec`, or install on PATH, or set `LUADEC=/full/path/to/luadec`.
  - Put `unluac.jar` at `scripts/bin/unluac.jar`, or set `UNLUAC_JAR=/full/path/to/unluac.jar`.

## Analysis Scripts

All scripts are in the `scripts/` directory:

| Script | Purpose | Output |
|--------|---------|--------|
| `update_asr.py` | Downloads and extracts latest ASR rules | `asr_lua/`, `asr_index.csv` |
| `scan_rmm.py` | Scans for RMM vendor strings in rules | `asr_rmm_index.csv` |
| `scan_lolrmm.py` | Cross-references with LOLRMM.io dataset | `asr_rmm_lolrmm_matches.csv` |
| `dump_asr.py` | Creates comprehensive ASR dumps | `asr_dump.json`, `asr_dump.csv` |
| `extract_all_indicators.py` | Extracts all indicators from rules | `asr_indicators_all_with_names.csv` |
| `extract_unknown_indicators.py` | Finds non-RMM indicators | `asr_indicators_unknown_with_names.csv` |
| `map_indicators_to_ids.py` | Maps indicators to ASR rule GUIDs | `asr_indicator_id_map.csv` |
| `diff-asr.py` | Compares ASR index between commits | Terminal output |
| `update-asr.ps1` | PowerShell wrapper for Windows | Various |

### Running Analysis Locally

Run the full analysis pipeline:

```bash
# Install defender2db
python -m pip install "git+https://github.com/dobin/defender2db@main"

# Download and extract ASR rules
python scripts/update_asr.py

# Run analysis pipeline
python scripts/scan_rmm.py
python scripts/scan_lolrmm.py
python scripts/dump_asr.py
python scripts/extract_all_indicators.py
python scripts/extract_unknown_indicators.py
python scripts/map_indicators_to_ids.py
```

## Use Cases

### Security Research
- Track Microsoft's ASR rule evolution over time
- Identify which legitimate tools trigger ASR rules
- Find new indicators and behaviors Microsoft is targeting
- Correlate ASR rules with specific threats

### Blue Team / Defense
- Understand false positive risks from legitimate RMM tools
- Plan ASR deployment with awareness of tool conflicts
- Monitor for new ASR rule additions that may impact operations
- Extract IoCs for additional detection logic

### Red Team / Adversary Emulation
- Identify behaviors and tools that trigger ASR rules
- Plan payload delivery strategies that avoid ASR detection
- Test evasion techniques against known ASR logic
- Understand detection surface for common tools

### Threat Intelligence
- Track Microsoft's detection priorities over time
- Identify emerging threat patterns from new ASR rules
- Correlate ASR rule changes with threat actor TTPs
- Extract actionable indicators for threat hunting

## Data Format Examples

### asr_dump.json
Comprehensive dump with metadata, strings, GUIDs, and paths:
```json
{
  "file": "asr_lua_21.bin",
  "name": "Block credential stealing from LSASS",
  "description": "Windows Defender detected credential theft attempt",
  "strings_count": 1247,
  "guids": ["...", "..."],
  "strings_paths": ["C:\\Windows\\System32\\lsass.exe", ...]
}
```

### asr_rmm_lolrmm_matches.csv
Cross-reference showing which ASR rules target which RMM tools:
```csv
rmm_name,indicators,matched_files,match_count,guids
ConnectWise Automate,ltsvc.exe;ltsvcmon.exe,asr_lua_21.bin,2,guid1;guid2
```

## Contributing

Found interesting patterns in the data? Open an issue or PR!

## Credits

- [defender2db](https://github.com/dobin/defender2db/) by @dobin - Core extraction tooling
- [LOLRMM.io](https://lolrmm.io) - RMM tool reference dataset
- Microsoft Defender team - For the ASR rules themselves

## License

Data extracted from Microsoft Defender. Analysis scripts and tooling: MIT License.
