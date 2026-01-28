#!/usr/bin/env python3
"""
Fetch and extract latest Microsoft Defender ASR Lua rules.

This script downloads the latest Defender signatures and extracts ASR rules.
It works around bugs in the upstream defender2db tool by directly calling
the relevant functions instead of using the CLI.
"""
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
    env = os.environ.copy()
    env["PIP_INDEX_URL"] = "https://pypi.org/simple"
    env["PIP_EXTRA_INDEX_URL"] = ""
    env["PIP_CONFIG_FILE"] = os.devnull

    args_common = [sys.executable, "-m", "pip", "--isolated", "install", "--index-url", "https://pypi.org/simple"]
    if in_virtualenv():
        try:
            run([sys.executable, "-m", "pip", "--isolated", "install", "--upgrade", "pip", "--index-url", "https://pypi.org/simple"], env=env)
        except Exception:
            pass
        user_args: list[str] = []
    else:
        user_args = ["--user"]

    try:
        run(args_common + user_args + [tool_ref], env=env)
    except subprocess.CalledProcessError:
        run(args_common + user_args + ["poetry-core", "build", "setuptools", "wheel"], env=env)
        run(args_common + user_args + [tool_ref], env=env)


def download_signatures(cache_dir: str = "cache") -> tuple[str, str]:
    """Download latest signatures using defender2yara's download function."""
    from defender2yara.defender.download import download_latest_signature
    
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    signature_version, engine_version, _ = download_latest_signature(cache_dir)
    print(f"Downloaded signatures: {signature_version}, engine: {engine_version}")
    return signature_version, engine_version


def get_version_from_cache(cache_dir: str = "cache") -> tuple[str, str]:
    """Get version info from cached files."""
    from packaging.version import Version
    
    vdm_path = os.path.join(cache_dir, "vdm")
    engine_path = os.path.join(cache_dir, "engine")
    
    # Get signature version
    sig_version = None
    if os.path.exists(vdm_path):
        major_minor_versions = []
        for entry in os.listdir(vdm_path):
            if os.path.isdir(os.path.join(vdm_path, entry)):
                try:
                    major_minor_versions.append(Version(entry))
                except:
                    continue
        if major_minor_versions:
            latest_major_minor = str(max(major_minor_versions))
            sub_path = os.path.join(vdm_path, latest_major_minor)
            builds = []
            for entry in os.listdir(sub_path):
                try:
                    builds.append(Version(entry))
                except:
                    continue
            if builds:
                latest_build = str(max(builds))
                sig_version = f"{latest_major_minor}.{latest_build}"
    
    # Get engine version
    eng_version = None
    if os.path.exists(engine_path):
        versions = []
        for entry in os.listdir(engine_path):
            try:
                versions.append(Version(entry))
            except:
                continue
        if versions:
            eng_version = str(max(versions))
    
    return sig_version or "", eng_version or ""


def extract_asr_rules(cache_dir: str = "cache", output_dir: str = "rules") -> int:
    """Extract ASR rules directly from VDM files, bypassing the buggy database code."""
    from defender2yara.defender.vdm import Vdm
    from defender2yara.defender.luaparse import fixup_lua_data
    
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    sig_version, _ = get_version_from_cache(cache_dir)
    if not sig_version:
        raise RuntimeError("No signature files found in cache")
    
    major_version = ".".join(sig_version.split(".")[0:2])
    minor_version = ".".join(sig_version.split(".")[2:4])
    
    n = 0
    for name in ["mpav", "mpas"]:
        vdm_base_path = os.path.join(cache_dir, "vdm", major_version, '0.0')
        vdm_delta_path = os.path.join(cache_dir, "vdm", major_version, minor_version)
        base_file = os.path.join(vdm_base_path, name + "base.vdm")
        delta_file = os.path.join(vdm_delta_path, name + "dlta.vdm")
        
        if not os.path.exists(base_file):
            print(f"Base file not found: {base_file}")
            continue
            
        print(f"Loading VDM: {base_file}")
        vdm = Vdm(base_file)
        vdm.parse_files()
        
        if os.path.exists(delta_file):
            print(f"Applying delta: {delta_file}")
            vdm.apply_delta_vdm(delta_file)
        
        # Extract ASR rules
        threats = vdm.get_threats()
        for threat in threats:
            if threat.threat_id != 2147483632:  # !InfrastructureShared
                continue
            
            for sig in threat.signatures:
                if len(sig.sig_data) < 42:
                    continue
                idx = sig.sig_data.find(b'-')
                if idx == -1:
                    continue
                
                # Heuristics to find GUID format
                if (sig.sig_data[16] == 0x2d and 
                    sig.sig_data[idx+5] == 0x2d and 
                    sig.sig_data[idx+5+5] == 0x2d and 
                    sig.sig_data[idx+5+5+5] == 0x2d):
                    
                    # Skip CVE false positives
                    if sig.sig_data[8:8+4] == b"CVE-":
                        continue
                    
                    lua_header_offset = sig.sig_data.find(b'\x1bLuaQ')
                    if lua_header_offset == -1:
                        continue
                    
                    lua_fixed, error = fixup_lua_data(sig.sig_data[lua_header_offset:])
                    if lua_fixed is None:
                        print(f"Failed to fixup Lua: {error}")
                        continue
                    
                    filename_out = os.path.join(output_dir, f"asr_lua_{n}.bin")
                    with open(filename_out, "wb") as f:
                        f.write(lua_fixed)
                    print(f"Extracted: {filename_out}")
                    n += 1
    
    return n


def run_defender2yara(download: bool, asr: bool) -> None:
    """Run defender2yara operations with proper error handling."""
    Path('rules').mkdir(parents=True, exist_ok=True)
    Path('cache').mkdir(parents=True, exist_ok=True)
    
    if download:
        print("Downloading latest signatures...")
        download_signatures("cache")
    
    if asr:
        print("Extracting ASR rules...")
        count = extract_asr_rules("cache", "rules")
        print(f"Extracted {count} ASR rules")


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
                if src_stat.st_size != dst_stat.st_size or src_stat.st_mtime > dst_stat.st_mtime:
                    shutil.copy2(src, dst)
            except FileNotFoundError:
                shutil.copy2(src, dst)

    for root, _dirs, files in os.walk(dest_dir):
        for name in files:
            candidate = Path(root) / name
            if candidate not in source_files:
                candidate.unlink(missing_ok=True)

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
    env_path = os.environ.get('LUADEC')
    if env_path and Path(env_path).is_file():
        return Path(env_path)

    found = which('luadec')
    if found:
        return Path(found)

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
                pass
    return made


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch and extract latest Defender ASR Lua")
    parser.add_argument('--tool-ref', default='git+https://github.com/dobin/defender2db@main', help='pip reference for defender2db tool')
    parser.add_argument('--no-install', action='store_true', help='skip pip install of tool')
    parser.add_argument('--result-dir', default='rules', help='source dir for extracted rules')
    parser.add_argument('--dest-dir', default='asr_lua', help='destination dir in repo')
    args = parser.parse_args()

    if not args.no_install:
        ensure_tool_installed(args.tool_ref)

    run_defender2yara(download=True, asr=True)

    source_dir = Path(args.result_dir)
    if not source_dir.exists():
        raise SystemExit(f"Source directory not found: {source_dir}")

    dest_dir = Path(args.dest_dir)
    mirror_tree(source_dir, dest_dir)

    luadec = ensure_luadec_binary()
    if luadec:
        made = decompile_bins_with_luadec(dest_dir, luadec)
        print(f"luadec wrote {made} files")
    else:
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
