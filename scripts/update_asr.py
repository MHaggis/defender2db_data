#!/usr/bin/env python3
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
import csv
import stat
import urllib.request
from shutil import which


def run(cmd: list[str], env: dict[str, str] | None = None) -> None:
    subprocess.check_call(cmd, env=env)


def in_virtualenv() -> bool:
    base = getattr(sys, 'base_prefix', sys.prefix)
    return (sys.prefix != base) or ('VIRTUAL_ENV' in os.environ)


def ensure_tool_installed(tool_ref: str) -> None:
    # Force PyPI and ignore local pip config/env
    env = os.environ.copy()
    env["PIP_INDEX_URL"] = "https://pypi.org/simple"
    env["PIP_EXTRA_INDEX_URL"] = ""
    env["PIP_CONFIG_FILE"] = os.devnull

    args_common = [sys.executable, "-m", "pip", "--isolated", "install", "--index-url", "https://pypi.org/simple"]
    if in_virtualenv():
        # Safe to upgrade pip in a venv
        try:
            run([sys.executable, "-m", "pip", "--isolated", "install", "--upgrade", "pip", "--index-url", "https://pypi.org/simple"], env=env)
        except Exception:
            pass
        user_args: list[str] = []
    else:
        # Avoid PEP 668 issues by using --user when not in a venv
        user_args = ["--user"]

    try:
        run(args_common + user_args + [tool_ref], env=env)
    except subprocess.CalledProcessError:
        # Fallback: explicitly install build requirements then retry
        run(args_common + user_args + ["poetry-core", "build", "setuptools", "wheel"], env=env)
        run(args_common + user_args + [tool_ref], env=env)


def run_defender2yara(download: bool, asr: bool) -> None:
    # Clean any partial database to ensure fresh start
    db_path = Path('threats.db')
    if db_path.exists():
        print(f"Removing existing database: {db_path}")
        db_path.unlink()
    
    if download:
        run([sys.executable, "-m", "defender2yara", "--download"])
    
    if asr:
        # Ensure default output dir used by defender2yara exists
        Path('rules').mkdir(parents=True, exist_ok=True)
        # Run extract first to populate the database schema
        print("Initializing database with --extract...")
        try:
            run([sys.executable, "-m", "defender2yara", "--extract"])
        except subprocess.CalledProcessError as e:
            print(f"Extract step had issues (exit {e.returncode}), continuing to ASR...")
            # Extract might have partial failures but still initialize DB
        # Now run ASR extraction
        print("Extracting ASR rules...")
        run([sys.executable, "-m", "defender2yara", "--asr"])


def mirror_tree(source_dir: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    source_files: set[Path] = set()

    for root, _dirs, files in os.walk(source_dir):
        root_path = Path(root)
        rel_root = root_path.relative_to(source_dir)
        target_root = dest_dir / rel_root
        target_root.mkdir(parents=True, exist_ok=True)

        for name in files:
            src = root_path / name
            dst = target_root / name
            source_files.add(dst)

            try:
                dst_stat = dst.stat()
                src_stat = src.stat()
                # Copy if size differs or src is newer
                if src_stat.st_size != dst_stat.st_size or src_stat.st_mtime > dst_stat.st_mtime:
                    shutil.copy2(src, dst)
            except FileNotFoundError:
                shutil.copy2(src, dst)

    # Remove files in dest that are not in source
    for root, _dirs, files in os.walk(dest_dir):
        for name in files:
            candidate = Path(root) / name
            if candidate not in source_files:
                candidate.unlink(missing_ok=True)

    # Clean up empty directories
    for root, dirs, _files in os.walk(dest_dir, topdown=False):
        for d in dirs:
            p = Path(root) / d
            if not any(p.iterdir()):
                p.rmdir()


def build_index(root: Path, output_csv: Path) -> int:
    rows: list[tuple[str, str, int]] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in sorted(filenames):
            path = Path(dirpath) / fn
            rel = path.relative_to(root).as_posix()
            with path.open('rb') as f:
                data = f.read()
            sha = hashlib.sha256(data).hexdigest()
            rows.append((rel, sha, len(data)))

    with output_csv.open('w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['file', 'sha256', 'bytes'])
        for r in rows:
            w.writerow(r)
    return len(rows)


def ensure_luadec_binary() -> Path | None:
    # Prefer env override
    env_path = os.environ.get('LUADEC')
    if env_path and Path(env_path).is_file():
        return Path(env_path)

    # PATH lookup
    found = which('luadec')
    if found:
        return Path(found)

    # Try download a bundled binary from upstream
    try:
        bin_dir = Path('scripts') / 'bin'
        bin_dir.mkdir(parents=True, exist_ok=True)
        target = bin_dir / 'luadec'
        if not target.exists():
            url = 'https://raw.githubusercontent.com/dobin/defender2db/main/luadec'
            with urllib.request.urlopen(url) as r, open(target, 'wb') as f:
                f.write(r.read())
            mode = os.stat(target).st_mode
            os.chmod(target, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return target
    except Exception:
        return None


def decompile_bins_with_luadec(root: Path, luadec: Path) -> int:
    made = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in sorted(filenames):
            if not fn.endswith('.bin'):
                continue
            src = Path(dirpath) / fn
            out = Path(dirpath) / f"{fn}.txt"
            # Skip if up-to-date
            try:
                if out.exists() and out.stat().st_mtime >= src.stat().st_mtime:
                    continue
            except FileNotFoundError:
                pass
            try:
                res = subprocess.run([str(luadec), '-dis', str(src)], capture_output=True, text=True, check=True)
                out.write_text(res.stdout, encoding='utf-8', errors='ignore')
                made += 1
            except Exception:
                # Leave a stub so diffs show an attempt
                out.write_text('// decompile failed\n', encoding='utf-8')
    return made


def find_unluac_jar() -> Path | None:
    jar_env = os.environ.get('UNLUAC_JAR')
    if jar_env and Path(jar_env).is_file():
        return Path(jar_env)
    candidate = Path('scripts') / 'bin' / 'unluac.jar'
    if candidate.is_file():
        return candidate
    return None


def decompile_bins_with_unluac(root: Path, jar_path: Path) -> int:
    # Requires a working 'java' on PATH
    if which('java') is None:
        return 0
    made = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in sorted(filenames):
            if not fn.endswith('.bin'):
                continue
            src = Path(dirpath) / fn
            out = Path(dirpath) / f"{fn}.txt"
            try:
                if out.exists() and out.stat().st_mtime >= src.stat().st_mtime:
                    continue
            except FileNotFoundError:
                pass
            try:
                res = subprocess.run(['java', '-jar', str(jar_path), str(src)], capture_output=True, text=True, check=True)
                out.write_text(res.stdout, encoding='utf-8', errors='ignore')
                made += 1
            except Exception:
                # leave as is
                pass
    return made


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch and extract latest Defender ASR Lua")
    parser.add_argument('--tool-ref', default='git+https://github.com/dobin/defender2db@main', help='pip reference for defender2db tool')
    parser.add_argument('--no-install', action='store_true', help='skip pip install of tool')
    parser.add_argument('--result-dir', default='result/asr_rules', help='source dir produced by defender2yara --asr')
    parser.add_argument('--dest-dir', default='asr_lua', help='destination dir in repo')
    args = parser.parse_args()

    if not args.no_install:
        ensure_tool_installed(args.tool_ref)

    run_defender2yara(download=True, asr=True)

    source_dir = Path(args.result_dir)
    if not source_dir.exists():
        # Fallback to defender2yara default output location
        fallback = Path('rules')
        if fallback.exists():
            source_dir = fallback
        else:
            raise SystemExit(f"Source directory not found: {source_dir}")

    dest_dir = Path(args.dest_dir)
    mirror_tree(source_dir, dest_dir)

    # Decompile .bin to .bin.txt for readability
    luadec = ensure_luadec_binary()
    if luadec:
        made = decompile_bins_with_luadec(dest_dir, luadec)
        print(f"luadec wrote {made} files")
    else:
        # Optional alternative if luadec not available
        jar = find_unluac_jar()
        alt = 0
        if jar:
            alt = decompile_bins_with_unluac(dest_dir, jar)
        if alt:
            print(f"unluac wrote {alt} files")
        else:
            print("No luadec/unluac available; skipping .bin.txt generation")

    count = build_index(dest_dir, Path('asr_index.csv'))
    print(f"Indexed {count} files")


if __name__ == '__main__':
    main()


