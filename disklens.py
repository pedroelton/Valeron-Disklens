#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DiskLens - see what is eating your disk, clean it safely.

A local disk analyzer with a web interface. No dependencies, no telemetry,
no network access. Everything runs on your own machine.

Basic usage:
    python disklens.py

Advanced:
    python disklens.py --path "C:\\" --min-dup 5 --port 8765
    python disklens.py --allow-permanent    (enables permanent delete)

Then open the URL printed in the terminal.
"""

import argparse
import ctypes
import glob as globlib
import hashlib
import heapq
import json
import os
import secrets
import shutil
import sys
import threading
import time
import webbrowser
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

APP_NAME = "DiskLens"
APP_VERSION = "1.0.0"

IS_WIN = os.name == "nt"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
TOKEN_HEADER = "X-DiskLens-Token"

# ---------------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------------

LOCK = threading.Lock()
CANCEL = threading.Event()
SESSION_TOKEN = secrets.token_urlsafe(24)

STATE = {
    "status": "idle",          # idle | scanning | hashing | done | error | cancelled
    "phase": "",
    "root": "",
    "current": "",
    "files": 0,
    "bytes": 0,
    "dirs": 0,
    "errors": 0,
    "dup_done": 0,
    "dup_total": 0,
    "started": 0.0,
    "elapsed": 0.0,
    "message": "",
}

RESULTS = {}
CONFIG = {
    "min_dup": 5 * 1024 * 1024,
    "top": 400,
    "max_hash": 2 * 1024 ** 3,
    "port": 8765,
    "allow_permanent": False,
}

# Build folders that are safe to remove because a single command recreates them.
PROJECT_JUNK = {
    "node_modules": "node_deps",
    "__pycache__": "pycache",
    ".venv": "venv",
    "venv": "venv",
    ".next": "next_build",
    "dist": "build_output",
    "build": "build_output",
    ".gradle": "gradle_cache",
    "target": "build_output",
    ".cache": "generic_cache",
}


def set_state(**kw):
    with LOCK:
        STATE.update(kw)
        if STATE["started"]:
            STATE["elapsed"] = time.time() - STATE["started"]


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------

def is_reparse(entry):
    """Symlinks and junctions: never follow. They cause loops and double counting."""
    try:
        st = entry.stat(follow_symlinks=False)
        return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        return True


def dir_size(path):
    """Total size of a folder. Tolerates permission errors."""
    total = 0
    stack = [path]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if not is_reparse(entry):
                                stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            if not is_reparse(entry):
                                total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def path_size(path):
    try:
        if os.path.isfile(path):
            return os.path.getsize(path)
        if os.path.isdir(path):
            return dir_size(path)
    except OSError:
        return None
    return None


def rel_depth(path, root):
    """Folder depth relative to the scan root. Root itself is 0."""
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return 0
    if rel in (".", ""):
        return 0
    return rel.count(os.sep) + 1


def list_drives():
    drives = []
    if IS_WIN:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                letter = "%s:\\" % chr(65 + i)
                try:
                    usage = shutil.disk_usage(letter)
                    drives.append({"path": letter, "total": usage.total,
                                   "used": usage.used, "free": usage.free})
                except OSError:
                    continue
    else:
        usage = shutil.disk_usage("/")
        drives.append({"path": "/", "total": usage.total,
                       "used": usage.used, "free": usage.free})
    return drives


def is_admin():
    if not IS_WIN:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan_tree(root):
    dir_own = defaultdict(int)
    dir_count = defaultdict(int)
    by_ext = defaultdict(lambda: [0, 0])
    size_groups = defaultdict(list)
    top_heap = []
    old_files = []
    files = 0
    total_bytes = 0
    dirs = 0
    errors = 0
    now = time.time()
    year = 365 * 86400
    min_dup = CONFIG["min_dup"]
    top_n = CONFIG["top"]

    stack = [root]
    while stack:
        if CANCEL.is_set():
            return None
        d = stack.pop()
        dirs += 1
        if dirs % 200 == 0:
            set_state(current=d, files=files, bytes=total_bytes, dirs=dirs, errors=errors)
        try:
            it = os.scandir(d)
        except OSError:
            errors += 1
            continue
        with it:
            while True:
                try:
                    entry = next(it)
                except StopIteration:
                    break
                except OSError:
                    errors += 1
                    break
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if not is_reparse(entry):
                            stack.append(entry.path)
                        dir_own[entry.path] += 0
                    elif entry.is_file(follow_symlinks=False):
                        if is_reparse(entry):
                            continue
                        st = entry.stat(follow_symlinks=False)
                        size = st.st_size
                        files += 1
                        total_bytes += size
                        dir_own[d] += size
                        dir_count[d] += 1

                        ext = os.path.splitext(entry.name)[1].lower() or "(no extension)"
                        rec = by_ext[ext]
                        rec[0] += size
                        rec[1] += 1

                        if size >= 1024 * 1024:
                            if len(top_heap) < top_n:
                                heapq.heappush(top_heap, (size, entry.path, st.st_mtime))
                            elif size > top_heap[0][0]:
                                heapq.heapreplace(top_heap, (size, entry.path, st.st_mtime))

                        if size >= min_dup:
                            size_groups[size].append(entry.path)

                        if size >= 100 * 1024 * 1024 and (now - st.st_mtime) > year:
                            old_files.append((size, entry.path, st.st_mtime))
                except OSError:
                    errors += 1
                    continue

    set_state(current="", phase="Aggregating folders",
              files=files, bytes=total_bytes, dirs=dirs, errors=errors)

    # Bottom-up aggregation: deepest folders first, each one adds itself to its parent.
    sep = os.sep
    total_by_dir = defaultdict(int)
    count_by_dir = defaultdict(int)
    ordered = sorted(dir_own.keys(), key=lambda p: p.count(sep), reverse=True)
    root_norm = os.path.normpath(root)
    for d in ordered:
        total_by_dir[d] += dir_own[d]
        count_by_dir[d] += dir_count[d]
        if os.path.normpath(d) == root_norm:
            continue
        parent = os.path.dirname(d)
        if parent and parent != d:
            total_by_dir[parent] += total_by_dir[d]
            count_by_dir[parent] += count_by_dir[d]

    top_dirs = heapq.nlargest(250, total_by_dir.items(), key=lambda kv: kv[1])

    junk_dirs = []
    for d, size in total_by_dir.items():
        key = PROJECT_JUNK.get(os.path.basename(d).lower())
        if key and size > 20 * 1024 * 1024:
            junk_dirs.append((size, d, key))
    junk_dirs.sort(reverse=True)

    top_files = sorted(top_heap, reverse=True)
    old_files.sort(reverse=True)

    return {
        "files": files,
        "bytes": total_bytes,
        "dirs": dirs,
        "errors": errors,
        "top_dirs": [
            {"path": d, "size": s, "files": count_by_dir.get(d, 0), "depth": rel_depth(d, root)}
            for d, s in top_dirs
        ],
        "top_files": [{"path": p, "size": s, "mtime": m} for s, p, m in top_files[:300]],
        "old_files": [{"path": p, "size": s, "mtime": m} for s, p, m in old_files[:150]],
        "by_ext": sorted(
            [{"ext": k, "size": v[0], "files": v[1]} for k, v in by_ext.items()],
            key=lambda x: x["size"], reverse=True)[:25],
        "project_junk": [{"path": p, "size": s, "kind": k} for s, p, k in junk_dirs[:60]],
        "_size_groups": size_groups,
        "_root_total": total_by_dir.get(root, total_bytes),
    }


# ---------------------------------------------------------------------------
# Duplicate detection
# ---------------------------------------------------------------------------

def hash_head_tail(path, chunk=65536):
    try:
        size = os.path.getsize(path)
        h = hashlib.blake2b(digest_size=16)
        with open(path, "rb") as f:
            h.update(f.read(chunk))
            if size > chunk * 2:
                f.seek(-chunk, os.SEEK_END)
                h.update(f.read(chunk))
        return h.hexdigest()
    except OSError:
        return None


def hash_full(path, chunk=1024 * 1024):
    try:
        h = hashlib.blake2b(digest_size=16)
        with open(path, "rb") as f:
            while True:
                if CANCEL.is_set():
                    return None
                block = f.read(chunk)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()
    except OSError:
        return None


def find_duplicates(size_groups):
    """Three passes: same size, then head+tail hash, then full content hash."""
    candidates = {s: p for s, p in size_groups.items() if len(p) > 1}
    total = sum(len(v) for v in candidates.values())
    set_state(status="hashing", phase="Comparing candidate files",
              dup_total=total, dup_done=0)

    done = 0
    partial = defaultdict(list)
    for size, paths in candidates.items():
        for p in paths:
            if CANCEL.is_set():
                return []
            h = hash_head_tail(p)
            done += 1
            if done % 50 == 0:
                set_state(dup_done=done, current=p)
            if h:
                partial[(size, h)].append(p)

    groups = []
    max_hash = CONFIG["max_hash"]
    for (size, _h), paths in partial.items():
        if len(paths) < 2:
            continue
        if size > max_hash:
            groups.append({"size": size, "paths": sorted(paths), "confidence": "partial"})
            continue
        full = defaultdict(list)
        for p in paths:
            if CANCEL.is_set():
                return []
            fh = hash_full(p)
            if fh:
                full[fh].append(p)
        for _fh, same in full.items():
            if len(same) > 1:
                groups.append({"size": size, "paths": sorted(same), "confidence": "exact"})

    for g in groups:
        g["waste"] = g["size"] * (len(g["paths"]) - 1)
    groups.sort(key=lambda g: g["waste"], reverse=True)
    return groups[:200]


# ---------------------------------------------------------------------------
# Known cleanup targets
#
# risk levels:
#   safe    - recreated automatically, nothing breaks
#   careful - recreated, but costs time or a download
#   info    - cannot be deleted here, needs a specific command
# ---------------------------------------------------------------------------

def junk_targets():
    env = os.environ.get
    local = env("LOCALAPPDATA", "")
    appdata = env("APPDATA", "")
    home = env("USERPROFILE", "") or os.path.expanduser("~")
    win = env("SystemRoot", r"C:\Windows")
    docs = os.path.join(home, "Documents") if home else ""
    targets = []

    def add(tid, name, path, risk, note, kind="contents", patterns=None):
        targets.append({"id": tid, "name": name, "path": path, "risk": risk,
                        "note": note, "kind": kind, "patterns": patterns})

    if not IS_WIN:
        add("unix_cache", "User cache", os.path.expanduser("~/.cache"), "safe",
            "Generic application cache on Linux and macOS.")
        add("unix_trash", "Trash", os.path.expanduser("~/.local/share/Trash"), "safe",
            "Deleted files still using disk space.")
        return targets

    # --- Windows system leftovers ---
    add("user_temp", "User temp files", os.path.join(local, "Temp"), "safe",
        "Temporary files from applications and installers. Recreated automatically.")
    add("windows_temp", "Windows temp files", os.path.join(win, "Temp"), "safe",
        "System temporary files. Needs administrator to clear completely.")
    add("windows_update_cache", "Windows Update cache",
        os.path.join(win, "SoftwareDistribution", "Download"), "safe",
        "Installers for updates that are already applied. Often several GB.")
    add("delivery_optimization", "Delivery Optimization cache",
        os.path.join(win, "ServiceProfiles", "NetworkService", "AppData", "Local",
                     "Microsoft", "Windows", "DeliveryOptimization"), "safe",
        "Peer-to-peer cache used to share Windows updates.")
    add("wer_user", "Error reports (user)", os.path.join(local, "Microsoft", "Windows", "WER"),
        "safe", "Crash reports from applications.")
    add("wer_system", "Error reports (system)", r"C:\ProgramData\Microsoft\Windows\WER",
        "safe", "Crash reports collected by the system.")
    add("crash_dumps", "Crash dumps", os.path.join(local, "CrashDumps"), "safe",
        "Memory dumps from programs that crashed.")
    add("thumbnail_cache", "Thumbnail and icon cache",
        os.path.join(local, "Microsoft", "Windows", "Explorer"), "safe",
        "Explorer thumbnails. Rebuilt as you browse folders.")
    add("inetcache", "Internet cache", os.path.join(local, "Microsoft", "Windows", "INetCache"),
        "safe", "Cache used by the system and by embedded browsers.")
    add("prefetch", "Prefetch", os.path.join(win, "Prefetch"), "careful",
        "Speeds up application startup. Clearing it makes boot slower for a few days.")
    add("windows_old", "Previous Windows installation", r"C:\Windows.old", "careful",
        "Old Windows install, usually 10 to 30 GB. Removing it means you cannot roll back.",
        kind="dir")

    # --- Browsers ---
    add("chrome_cache", "Chrome cache", "", "safe", "Page cache. Rebuilt as you browse.",
        patterns=[os.path.join(local, r"Google\Chrome\User Data\*\Cache"),
                  os.path.join(local, r"Google\Chrome\User Data\*\Code Cache"),
                  os.path.join(local, r"Google\Chrome\User Data\*\GPUCache")])
    add("edge_cache", "Edge cache", "", "safe", "Page cache. Rebuilt as you browse.",
        patterns=[os.path.join(local, r"Microsoft\Edge\User Data\*\Cache"),
                  os.path.join(local, r"Microsoft\Edge\User Data\*\Code Cache")])
    add("brave_cache", "Brave cache", "", "safe", "Page cache. Rebuilt as you browse.",
        patterns=[os.path.join(local, r"BraveSoftware\Brave-Browser\User Data\*\Cache")])
    add("firefox_cache", "Firefox cache", "", "safe", "Page cache. Rebuilt as you browse.",
        patterns=[os.path.join(local, r"Mozilla\Firefox\Profiles\*\cache2")])

    # --- Developer tools ---
    add("pip_cache", "pip cache", os.path.join(local, "pip", "Cache"), "safe",
        "Downloaded Python packages. Rebuilt on the next pip install.")
    add("npm_cache", "npm cache", os.path.join(appdata, "npm-cache"), "safe",
        "Downloaded Node packages. Rebuilt on the next npm install.")
    add("yarn_cache", "Yarn cache", os.path.join(local, "Yarn", "Cache"), "safe",
        "Downloaded Yarn packages.")
    add("vscode_cache", "VS Code cache", os.path.join(appdata, "Code", "Cache"), "safe",
        "Editor cache. Rebuilt when VS Code starts.")
    add("vscode_cacheddata", "VS Code cached data", os.path.join(appdata, "Code", "CachedData"),
        "safe", "Compiled bytecode from older VS Code versions.")
    add("nuget_packages", "NuGet packages", os.path.join(home, ".nuget", "packages"), "careful",
        "Downloaded .NET packages. Rebuilt on the next restore, offline builds break first.")
    add("docker_vhdx", "Docker WSL disk (ext4.vhdx)",
        os.path.join(local, r"Docker\wsl\data\ext4.vhdx"), "info",
        "Docker virtual disk. Never delete it. Run 'docker system prune -a', then compact the vhdx.",
        kind="info")

    # --- Trading platforms ---
    add("mt5_logs", "MetaTrader logs", "", "safe",
        "Terminal and Expert Advisor logs. They grow fast when backtesting.",
        patterns=[os.path.join(appdata, r"MetaQuotes\Terminal\*\logs"),
                  os.path.join(appdata, r"MetaQuotes\Terminal\*\MQL5\Logs"),
                  os.path.join(appdata, r"MetaQuotes\Terminal\*\Tester\logs")])
    add("mt5_tester", "MetaTrader Strategy Tester cache", "", "careful",
        "Optimization agents and caches. Rebuilt on the next backtest.",
        patterns=[os.path.join(appdata, r"MetaQuotes\Terminal\*\Tester\cache"),
                  os.path.join(appdata, r"MetaQuotes\Terminal\*\Tester\Agent-*")])
    add("mt5_bases", "MetaTrader price history", "", "careful",
        "Tick and bar history downloaded from the broker. Can reach tens of GB, re-downloadable.",
        patterns=[os.path.join(appdata, r"MetaQuotes\Terminal\*\bases")])
    add("nt8_logs", "NinjaTrader logs", "", "safe", "Daily log and trace files.",
        patterns=[os.path.join(docs, r"NinjaTrader 8\log"),
                  os.path.join(docs, r"NinjaTrader 8\trace")])
    add("nt8_db", "NinjaTrader market data", os.path.join(docs, "NinjaTrader 8", "db"), "careful",
        "Historical market data. Re-downloadable through the Historical Data Manager.")

    # --- Heavy consumer apps ---
    add("spotify_cache", "Spotify cache", os.path.join(local, "Spotify", "Storage"), "safe",
        "Songs cached for offline playback.")
    add("discord_cache", "Discord cache", os.path.join(appdata, "discord", "Cache"), "safe",
        "Cached images and attachments.")
    add("teams_cache", "Teams cache", os.path.join(appdata, r"Microsoft\Teams"), "careful",
        "Classic Teams cache. Close the app first.")

    # --- Information only ---
    add("hiberfil", "hiberfil.sys (hibernation)", r"C:\hiberfil.sys", "info",
        "Hibernation file, usually 40 percent of your RAM. Disable with: powercfg /h off",
        kind="info")
    add("pagefile", "pagefile.sys (virtual memory)", r"C:\pagefile.sys", "info",
        "Paging file. Do not delete. Resize it in System Properties, Advanced, Performance.",
        kind="info")
    add("swapfile", "swapfile.sys", r"C:\swapfile.sys", "info",
        "Paging for Store apps. Managed by the system.", kind="info")
    add("winsxs", "WinSxS (Windows components)", os.path.join(win, "WinSxS"), "info",
        "Never delete manually. Clean with: DISM /Online /Cleanup-Image /StartComponentCleanup",
        kind="info")
    add("system_restore", "System Restore (shadow copies)", "", "info",
        "Restore points can hold 10 percent of the disk. Inspect with: vssadmin list shadowstorage",
        kind="info")
    add("recycle_bin", "Recycle Bin", r"C:\$Recycle.Bin", "info",
        "Deleted files still occupy space. Use the Empty Recycle Bin button at the top.",
        kind="info")
    return targets


def measure_junk():
    out = []
    for t in junk_targets():
        entry = dict(t)
        entry["exists"] = False
        entry["size"] = 0
        entry["resolved"] = []
        paths = []
        if t.get("patterns"):
            for pattern in t["patterns"]:
                paths.extend(globlib.glob(pattern))
        elif t.get("path"):
            paths = [t["path"]] if os.path.exists(t["path"]) else []
        for p in paths:
            size = path_size(p)
            if size is None:
                continue
            entry["exists"] = True
            entry["size"] += size
            entry["resolved"].append({"path": p, "size": size})
        out.append(entry)
    out.sort(key=lambda e: (e["kind"] == "info", -e["size"]))
    return out


# ---------------------------------------------------------------------------
# Deletion guard rails
# ---------------------------------------------------------------------------

PROTECTED_EXACT = set()
ALLOWED_IN_WINDOWS = (
    "\\temp",
    "\\softwaredistribution\\download",
    "\\prefetch",
    "\\serviceprofiles\\networkservice\\appdata\\local\\microsoft\\windows\\deliveryoptimization",
    "\\logs",
    "\\minidump",
)


def _norm(p):
    return os.path.normpath(os.path.abspath(p)).rstrip("\\/").lower()


def build_protected():
    env = os.environ.get
    win = env("SystemRoot", r"C:\Windows")
    home = env("USERPROFILE", "") or os.path.expanduser("~")
    items = [win, os.path.join(win, "System32"), os.path.join(win, "SysWOW64"),
             os.path.join(win, "WinSxS"), os.path.join(win, "Boot"),
             r"C:\Program Files", r"C:\Program Files (x86)", r"C:\ProgramData",
             r"C:\Users", home, r"C:\$Recycle.Bin", r"C:\Recovery", r"C:\Boot",
             r"C:\pagefile.sys", r"C:\hiberfil.sys", r"C:\swapfile.sys",
             os.path.join(home, "Desktop"), os.path.join(home, "Documents"),
             os.path.join(home, "Downloads"), os.path.join(home, "Pictures"),
             os.path.join(home, "Videos"), os.path.join(home, "Music"), "/", "/home", "/etc",
             "/usr", "/var", "/bin", "/lib", "/System", "/Applications"]
    for i in items:
        if i:
            PROTECTED_EXACT.add(_norm(i))


def check_deletable(path):
    """Returns (allowed, reason). Reasons are translated in the interface."""
    if not path:
        return False, "empty_path"
    n = _norm(path)
    if not os.path.exists(path):
        return False, "not_found"
    if len(n) <= 3 or n.count(os.sep) < 1:
        return False, "too_shallow"
    if n in PROTECTED_EXACT:
        return False, "protected"
    if IS_WIN:
        win = _norm(os.environ.get("SystemRoot", r"C:\Windows"))
        if n.startswith(win + os.sep):
            rest = n[len(win):]
            if not any(rest.startswith(a) for a in ALLOWED_IN_WINDOWS):
                return False, "inside_windows"
        for pf in (r"c:\program files", r"c:\program files (x86)"):
            if n.startswith(pf + "\\"):
                return False, "installed_program"
        if n.endswith(("pagefile.sys", "hiberfil.sys", "swapfile.sys")):
            return False, "system_file"
    return True, ""


def recycle(paths):
    """Send to the Recycle Bin through the native Windows shell API."""
    if not IS_WIN:
        raise OSError("recycle_bin_windows_only")
    from ctypes import wintypes

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", ctypes.c_uint16),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    FO_DELETE = 3
    FOF_SILENT = 0x0004
    FOF_NOCONFIRMATION = 0x0010
    FOF_ALLOWUNDO = 0x0040
    FOF_NOCONFIRMMKDIR = 0x0200
    FOF_NOERRORUI = 0x0400

    buf = "\0".join(os.path.abspath(p) for p in paths) + "\0\0"
    op = SHFILEOPSTRUCTW()
    op.hwnd = None
    op.wFunc = FO_DELETE
    op.pFrom = buf
    op.pTo = None
    op.fFlags = (FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT |
                 FOF_NOERRORUI | FOF_NOCONFIRMMKDIR)
    res = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    if res != 0:
        raise OSError("shell operation returned code %s" % res)


def empty_recycle_bin():
    if not IS_WIN:
        raise OSError("recycle_bin_windows_only")
    SHERB_NOCONFIRMATION = 0x01
    SHERB_NOPROGRESSUI = 0x02
    SHERB_NOSOUND = 0x04
    res = ctypes.windll.shell32.SHEmptyRecycleBinW(
        None, None, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND)
    if res not in (0, -2147418113):  # the second code means it was already empty
        raise OSError("code %s" % res)


def delete_paths(paths, mode="trash", contents_only=None):
    contents_only = contents_only or []
    contents_set = {_norm(p) for p in contents_only}
    freed = 0
    ok, failed = [], []

    if mode == "permanent" and not CONFIG["allow_permanent"]:
        return {"deleted": [], "failed": [{"path": p, "error": "permanent_disabled"} for p in paths],
                "freed": 0}

    for p in paths:
        allowed, reason = check_deletable(p)
        if not allowed:
            failed.append({"path": p, "error": reason})
            continue
        size = path_size(p) or 0
        try:
            if _norm(p) in contents_set and os.path.isdir(p):
                # Clear the contents, keep the folder itself. Windows expects
                # folders like Temp to exist.
                for name in os.listdir(p):
                    child = os.path.join(p, name)
                    try:
                        if mode == "trash":
                            recycle([child])
                        elif os.path.isdir(child):
                            shutil.rmtree(child, ignore_errors=True)
                        else:
                            os.remove(child)
                    except OSError:
                        continue
            else:
                if mode == "trash":
                    recycle([p])
                elif os.path.isdir(p):
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    os.remove(p)
            freed += size
            ok.append(p)
        except Exception as exc:  # noqa: BLE001
            failed.append({"path": p, "error": str(exc)})
    return {"deleted": ok, "failed": failed, "freed": freed}


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------

def run_scan(root):
    CANCEL.clear()
    set_state(status="scanning", phase="Scanning files", root=root, started=time.time(),
              files=0, bytes=0, dirs=0, errors=0, dup_done=0, dup_total=0,
              message="", current=root)
    try:
        tree = scan_tree(root)
        if tree is None:
            set_state(status="cancelled", phase="Cancelled", current="")
            return
        size_groups = tree.pop("_size_groups")
        root_total = tree.pop("_root_total")

        dups = find_duplicates(size_groups)
        if CANCEL.is_set():
            set_state(status="cancelled", phase="Cancelled", current="")
            return

        set_state(status="hashing", phase="Measuring known cleanup targets", current="")
        junk = measure_junk()

        try:
            usage = shutil.disk_usage(root)
            disk = {"total": usage.total, "used": usage.used, "free": usage.free}
        except OSError:
            disk = {"total": 0, "used": 0, "free": 0}

        with LOCK:
            RESULTS.clear()
            RESULTS.update(tree)
            RESULTS.update({
                "root": root,
                "root_total": root_total,
                "disk": disk,
                "duplicates": dups,
                "dup_waste": sum(g["waste"] for g in dups),
                "junk": junk,
                "junk_safe_total": sum(j["size"] for j in junk if j["risk"] == "safe"),
                "junk_careful_total": sum(j["size"] for j in junk if j["risk"] == "careful"),
                "project_junk_total": sum(j["size"] for j in tree["project_junk"]),
                "finished_at": time.time(),
            })
        set_state(status="done", phase="Done", current="")
    except Exception as exc:  # noqa: BLE001
        set_state(status="error", phase="Error", message=str(exc))


# ---------------------------------------------------------------------------
# HTTP server
#
# Security model. The server listens on 127.0.0.1 only, but that alone is not
# enough: any website you visit could POST to localhost from your browser.
# Three layers prevent that:
#   1. every API call must carry the session token, injected into the page
#   2. the Host header must point at localhost, which blocks DNS rebinding
#   3. the Origin header, when present, must match this server
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "%s/%s" % (APP_NAME, APP_VERSION)

    def log_message(self, fmt, *args):
        pass

    # ---------------- helpers ----------------

    def _send(self, data, ctype, code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code=200):
        self._send(json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8", code)

    def _static(self, name, ctype, inject_token=False):
        path = os.path.join(BASE_DIR, name)
        try:
            with open(path, "rb") as f:
                data = f.read()
            if inject_token:
                data = data.replace(b"__DISKLENS_TOKEN__", SESSION_TOKEN.encode())
            self._send(data, ctype)
        except OSError:
            self._send(b"file not found: " + name.encode(), "text/plain; charset=utf-8", 404)

    def _host_ok(self):
        host = (self.headers.get("Host") or "").lower()
        allowed = {"127.0.0.1:%d" % CONFIG["port"], "localhost:%d" % CONFIG["port"]}
        if host not in allowed:
            return False
        origin = self.headers.get("Origin")
        if origin:
            netloc = urlparse(origin).netloc.lower()
            if netloc not in allowed:
                return False
        return True

    def _token_ok(self):
        sent = self.headers.get(TOKEN_HEADER, "")
        return secrets.compare_digest(sent, SESSION_TOKEN)

    def _guard(self):
        """Returns True when the request may proceed."""
        if not self._host_ok():
            self._json({"error": "blocked_host"}, 403)
            return False
        if not self._token_ok():
            self._json({"error": "invalid_token"}, 403)
            return False
        return True

    # ---------------- routes ----------------

    def do_GET(self):
        route = urlparse(self.path).path
        if route in ("/", "/index.html"):
            if not self._host_ok():
                return self._send(b"blocked host", "text/plain; charset=utf-8", 403)
            return self._static("index.html", "text/html; charset=utf-8", inject_token=True)
        if route == "/style.css":
            return self._static("style.css", "text/css; charset=utf-8")
        if route == "/app.js":
            return self._static("app.js", "application/javascript; charset=utf-8")

        if not self._guard():
            return

        if route == "/api/status":
            with LOCK:
                payload = dict(STATE)
            payload["elapsed"] = time.time() - payload["started"] if payload["started"] else 0
            payload["has_results"] = bool(RESULTS)
            return self._json(payload)

        if route == "/api/results":
            with LOCK:
                payload = dict(RESULTS)
            return self._json(payload)

        if route == "/api/info":
            return self._json({
                "app": APP_NAME,
                "version": APP_VERSION,
                "drives": list_drives(),
                "default": "C:\\" if IS_WIN else os.path.expanduser("~"),
                "admin": is_admin(),
                "windows": IS_WIN,
                "allow_permanent": CONFIG["allow_permanent"],
                "min_dup_mb": CONFIG["min_dup"] / 1024 / 1024,
            })

        return self._json({"error": "unknown_route"}, 404)

    def do_POST(self):
        if not self._guard():
            return
        route = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:  # noqa: BLE001
            body = {}

        if route == "/api/scan":
            with LOCK:
                busy = STATE["status"] in ("scanning", "hashing")
            if busy:
                return self._json({"error": "scan_running"}, 409)
            root = body.get("path") or CONFIG.get("default_path") or os.path.expanduser("~")
            if not os.path.isdir(root):
                return self._json({"error": "invalid_path", "detail": root}, 400)
            try:
                CONFIG["min_dup"] = max(1, int(float(body.get("min_dup_mb", 5)))) * 1024 * 1024
            except (TypeError, ValueError):
                pass
            threading.Thread(target=run_scan, args=(root,), daemon=True).start()
            return self._json({"ok": True, "root": root})

        if route == "/api/cancel":
            CANCEL.set()
            return self._json({"ok": True})

        if route == "/api/delete":
            paths = body.get("paths") or []
            mode = "permanent" if body.get("mode") == "permanent" else "trash"
            contents = body.get("contents_only") or []
            if not paths:
                return self._json({"error": "no_paths"}, 400)
            return self._json(delete_paths(paths, mode=mode, contents_only=contents))

        if route == "/api/empty-recycle":
            try:
                empty_recycle_bin()
                return self._json({"ok": True})
            except Exception as exc:  # noqa: BLE001
                return self._json({"error": str(exc)}, 500)

        if route == "/api/open":
            path = body.get("path", "")
            try:
                target = path if os.path.isdir(path) else os.path.dirname(path)
                if not os.path.isdir(target):
                    return self._json({"error": "not_found"}, 400)
                if IS_WIN:
                    os.startfile(target)  # noqa: S606
                elif sys.platform == "darwin":
                    os.system("open %s" % json.dumps(target))  # noqa: S605
                else:
                    os.system("xdg-open %s" % json.dumps(target))  # noqa: S605
                return self._json({"ok": True})
            except Exception as exc:  # noqa: BLE001
                return self._json({"error": str(exc)}, 500)

        return self._json({"error": "unknown_route"}, 404)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def banner(url):
    line = "=" * 62
    print(line)
    print(" %s %s" % (APP_NAME.upper(), APP_VERSION))
    print(line)
    print(" Interface : %s" % url)
    print(" Admin     : %s" % ("yes" if is_admin()
                               else "no  (run as administrator to see system folders)"))
    print(" Permanent : %s" % ("enabled" if CONFIG["allow_permanent"]
                               else "disabled (Recycle Bin only, use --allow-permanent to enable)"))
    print(" Stop      : press Ctrl+C")
    print(line)


def main():
    parser = argparse.ArgumentParser(
        description="%s - see what is eating your disk, clean it safely." % APP_NAME)
    parser.add_argument("--path", default="C:\\" if IS_WIN else os.path.expanduser("~"),
                        help="drive or folder to scan first")
    parser.add_argument("--port", type=int, default=8765, help="local port (default 8765)")
    parser.add_argument("--min-dup", type=float, default=5.0,
                        help="minimum file size in MB when looking for duplicates")
    parser.add_argument("--max-hash-gb", type=float, default=2.0,
                        help="files above this size are matched by sampling instead of full hash")
    parser.add_argument("--allow-permanent", action="store_true",
                        help="enable permanent delete (default: Recycle Bin only)")
    parser.add_argument("--auto", action="store_true", help="start scanning immediately")
    parser.add_argument("--no-browser", action="store_true", help="do not open the browser")
    parser.add_argument("--version", action="version", version="%s %s" % (APP_NAME, APP_VERSION))
    args = parser.parse_args()

    CONFIG["min_dup"] = int(args.min_dup * 1024 * 1024)
    CONFIG["max_hash"] = int(args.max_hash_gb * 1024 ** 3)
    CONFIG["port"] = args.port
    CONFIG["allow_permanent"] = args.allow_permanent
    CONFIG["default_path"] = args.path
    build_protected()

    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError as exc:
        print("Could not start on port %d: %s" % (args.port, exc))
        print("Try another port, for example: python disklens.py --port 8790")
        sys.exit(1)

    url = "http://127.0.0.1:%d" % args.port
    banner(url)

    if args.auto and os.path.isdir(args.path):
        threading.Thread(target=run_scan, args=(args.path,), daemon=True).start()
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping...")
        CANCEL.set()
        server.shutdown()


if __name__ == "__main__":
    main()
