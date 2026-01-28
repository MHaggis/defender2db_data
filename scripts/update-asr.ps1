$ErrorActionPreference = 'Stop'

param(
    [string]$Python = 'python',
    [string]$ToolRef = 'git+https://github.com/dobin/defender2db@main'
)

Write-Host 'Ensuring pip and defender2db are installed...'
& $Python -m pip install --upgrade pip
& $Python -m pip install $ToolRef

Write-Host 'Downloading latest Defender VDM/engine...'
& $Python -m defender2yara --download

Write-Host 'Extracting ASR rules...'
& $Python -m defender2yara --asr

Write-Host 'Syncing ASR rules into repo as asr_lua/ ...'
New-Item -ItemType Directory -Force -Path 'asr_lua' | Out-Null
robocopy "result\asr_rules" "asr_lua" /MIR | Out-Null

Write-Host 'Building asr_index.csv...'
$indexPy = @'
import hashlib, os, csv
root = 'asr_lua'
rows = []
for dirpath, _dirnames, filenames in os.walk(root):
    for fn in sorted(filenames):
        path = os.path.join(dirpath, fn)
        rel = os.path.relpath(path, root)
        with open(path, 'rb') as f:
            data = f.read()
        sha = hashlib.sha256(data).hexdigest()
        rows.append((rel, sha, len(data)))
with open('asr_index.csv', 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['file', 'sha256', 'bytes'])
    for r in rows:
        w.writerow(r)
print(f"Indexed {len(rows)} files")
'@

& $Python - <<"PY"
$indexPy
PY

Write-Host 'Done. Updated asr_lua/ and asr_index.csv'

