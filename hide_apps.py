"""
Windows App Hider
=================

Hide a selected application so that:

  1. Searching for it in Start / Windows Search returns nothing
  2. Its taskbar button disappears (pinned shortcut and/or running window)

...until you restore it with this same tool. Every change is recorded in a
state file and is reversible.

What "hidden" covers, per app:
  * Start Menu shortcuts (per-user and machine-wide), plus the now-empty
    vendor folders left behind, whose names are searchable too
  * Desktop shortcuts (user, Public, and a OneDrive-redirected Desktop)
  * Taskbar and Start pins
  * Jump lists, which feed the Start menu's "Recent" section
  * UserAssist launch counts, which feed Start's "Most used"
  * The Settings > Installed apps entry (SystemComponent)
  * Optionally, the Hidden attribute on the .exe itself

Known limits:
  * Store/UWP apps are not covered. They have no .lnk to move and no
    per-app switch that hides them from Search; only removing the package
    does that, which is too destructive to do here.
  * This hides an app from view. It does not restrict access — anyone can
    still launch the .exe directly from its install folder.

Run as Administrator. Requires Python 3.8+ and `questionary`.
"""

import argparse
import base64
import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import winreg
from ctypes import byref, create_unicode_buffer, sizeof, wintypes

import questionary

# ---------------------------------------------------------------------------
# Paths / state location
# ---------------------------------------------------------------------------
# State lives in LOCALAPPDATA rather than next to the script so that it
# survives moving the script, and so the quarantine folder sits outside every
# location Windows Search indexes by default (Desktop, Documents, Downloads,
# Pictures, Music, Videos and the Start Menu).

APP_DIR_NAME = "WinAppHider"


def _script_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except NameError:
        return os.path.dirname(os.path.abspath(sys.argv[0]))


# Populated from argv in main() so that elevating through UAC with a *different*
# administrator account still targets the original user's profile.
USER_PATHS = {
    "appdata": os.environ.get("APPDATA", ""),
    "localappdata": os.environ.get("LOCALAPPDATA", ""),
    "userprofile": os.environ.get("USERPROFILE", ""),
    "programdata": os.environ.get("ALLUSERSPROFILE", r"C:\ProgramData"),
    "public": os.environ.get("PUBLIC", r"C:\Users\Public"),
}


def state_dir():
    base = USER_PATHS["localappdata"] or _script_dir()
    return os.path.join(base, APP_DIR_NAME)


def state_file():
    return os.path.join(state_dir(), "state.json")


def quarantine_dir():
    return os.path.join(state_dir(), "quarantine")


LEGACY_STATE_FILE = os.path.join(_script_dir(), ".app_hider_state.json")

# ---------------------------------------------------------------------------
# Win32 constants
# ---------------------------------------------------------------------------
GWL_EXSTYLE = -20
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_APPWINDOW = 0x00040000

SWP_FRAMECHANGED = 0x0020
SWP_NOMOVE = 0x0002
SWP_NOSIZE = 0x0001
SWP_NOZORDER = 0x0004
SWP_NOACTIVATE = 0x0010
SWP_HIDEWINDOW = 0x0080
SWP_SHOWWINDOW = 0x0040

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04

TB_BUTTONCOUNT = 0x0400 + 24
TB_GETBUTTON = 0x0400 + 23
TB_HIDEBUTTON = 0x0400 + 4

FILE_ATTRIBUTE_HIDDEN = 0x02

TASKBAND_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
USERASSIST_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

UNINSTALL_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]

HIVE_NAMES = {
    winreg.HKEY_LOCAL_MACHINE: "HKLM",
    winreg.HKEY_CURRENT_USER: "HKCU",
}
HIVE_BY_NAME = {v: k for k, v in HIVE_NAMES.items()}

# Executables that merely *launch* something else. Two shortcuts pointing at
# explorer.exe are not the same app, so their arguments join the grouping key.
LAUNCHER_EXES = {
    "explorer.exe", "cmd.exe", "rundll32.exe", "msiexec.exe", "control.exe",
    "wscript.exe", "cscript.exe", "powershell.exe", "pwsh.exe", "conhost.exe",
    "javaw.exe", "java.exe", "python.exe", "pythonw.exe", "mshta.exe",
}

# ---------------------------------------------------------------------------
# ctypes prototypes
# ---------------------------------------------------------------------------
# ctypes defaults every return value to c_int, which silently truncates 64-bit
# handles and pointers. Declaring these up front is what makes the tray reader
# and the window-style calls correct on 64-bit Python.

LRESULT = ctypes.c_ssize_t
SIZE_T = ctypes.c_size_t
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

_user32 = ctypes.windll.user32
_kernel32 = ctypes.windll.kernel32


def _setup_prototypes():
    u, k = _user32, _kernel32
    W, D, B, L = wintypes.HWND, wintypes.DWORD, wintypes.BOOL, wintypes.LONG
    P, H = wintypes.LPVOID, wintypes.HANDLE

    u.SendMessageW.argtypes = [W, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    u.SendMessageW.restype = LRESULT
    u.IsWindow.argtypes = [W]
    u.IsWindow.restype = B
    u.IsWindowVisible.argtypes = [W]
    u.IsWindowVisible.restype = B
    u.GetWindowTextLengthW.argtypes = [W]
    u.GetWindowTextLengthW.restype = ctypes.c_int
    u.GetWindowTextW.argtypes = [W, wintypes.LPWSTR, ctypes.c_int]
    u.GetWindowTextW.restype = ctypes.c_int
    u.GetWindowThreadProcessId.argtypes = [W, ctypes.POINTER(D)]
    u.GetWindowThreadProcessId.restype = D
    u.GetWindowLongW.argtypes = [W, ctypes.c_int]
    u.GetWindowLongW.restype = L
    u.SetWindowLongW.argtypes = [W, ctypes.c_int, L]
    u.SetWindowLongW.restype = L
    u.SetWindowPos.argtypes = [W, W, ctypes.c_int, ctypes.c_int,
                               ctypes.c_int, ctypes.c_int, wintypes.UINT]
    u.SetWindowPos.restype = B
    u.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    u.FindWindowW.restype = W
    u.FindWindowExW.argtypes = [W, W, wintypes.LPCWSTR, wintypes.LPCWSTR]
    u.FindWindowExW.restype = W

    k.OpenProcess.argtypes = [D, B, D]
    k.OpenProcess.restype = H
    k.CloseHandle.argtypes = [H]
    k.CloseHandle.restype = B
    k.VirtualAllocEx.argtypes = [H, P, SIZE_T, D, D]
    k.VirtualAllocEx.restype = P
    k.VirtualFreeEx.argtypes = [H, P, SIZE_T, D]
    k.VirtualFreeEx.restype = B
    k.ReadProcessMemory.argtypes = [H, P, P, SIZE_T, ctypes.POINTER(SIZE_T)]
    k.ReadProcessMemory.restype = B
    k.QueryFullProcessImageNameW.argtypes = [H, D, wintypes.LPWSTR,
                                             ctypes.POINTER(D)]
    k.QueryFullProcessImageNameW.restype = B
    k.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    k.GetFileAttributesW.restype = D
    k.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, D]
    k.SetFileAttributesW.restype = B


_setup_prototypes()


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_as_admin():
    """Re-launch elevated, carrying the current user's profile paths along."""
    script = os.path.abspath(sys.argv[0])
    extra = [
        "--appdata", USER_PATHS["appdata"],
        "--localappdata", USER_PATHS["localappdata"],
        "--userprofile", USER_PATHS["userprofile"],
    ]
    argv = sys.argv[1:] + extra
    params = " ".join('"{}"'.format(a) for a in argv)
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, '"{}" {}'.format(script, params), None, 1
    )
    if ret <= 32:
        print("[X] Failed to elevate (code {}).".format(ret))
        input("Press Enter to exit...")
        sys.exit(1)
    sys.exit(0)


def looks_like_fs_path(p):
    if not isinstance(p, str) or len(p) < 3:
        return False
    if p.startswith("\\\\"):
        return True
    return p[1] == ":" and p[2] in "\\/"


def norm(p):
    """Normalised absolute path for comparison, or '' for non-paths."""
    if not looks_like_fs_path(p):
        return ""
    try:
        return os.path.normcase(os.path.normpath(p))
    except Exception:
        return os.path.normcase(p)


def app_id_for(key):
    return hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:12]


def now_stamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def b64(data):
    return base64.b64encode(bytes(data)).decode("ascii")


def unb64(text):
    return base64.b64decode(text.encode("ascii"))


# ---------------------------------------------------------------------------
# PowerShell bridge
# ---------------------------------------------------------------------------
# The old version launched one `powershell.exe` per shortcut, which meant
# several minutes and hundreds of processes for a normal Start Menu. Everything
# now goes through a single batched call: the payload is written as JSON, the
# script writes JSON back, and Python reads the file (avoids console codepage
# mangling of non-ASCII app names entirely).

_PS_PREAMBLE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$Payload = @()
if (Test-Path -LiteralPath $InFile) {
    $raw = Get-Content -LiteralPath $InFile -Raw -Encoding UTF8
    # Windows PowerShell 5.1 hands the decoded array back as a single object,
    # so @(ConvertFrom-Json '["a","b"]') has Count 1 and every foreach below
    # would run once with $p bound to the whole array. Piping through
    # ForEach-Object forces real enumeration, and still yields a one-element
    # list for a lone object or string.
    if ($raw -and $raw.Trim()) {
        $Payload = @(ConvertFrom-Json $raw | ForEach-Object { $_ })
    }
}
function Emit($o) {
    if ($null -eq $o) { $o = @() }
    ConvertTo-Json @($o) -Depth 6 -Compress |
        Out-File -LiteralPath $OutFile -Encoding UTF8
}
"""


def ps_json(body, payload=None, timeout=240):
    """Run a PowerShell snippet with $Payload/$OutFile bound. Returns a list."""
    tmp = tempfile.mkdtemp(prefix="wah_")
    ps_path = os.path.join(tmp, "run.ps1")
    in_path = os.path.join(tmp, "in.json")
    out_path = os.path.join(tmp, "out.json")
    try:
        with open(in_path, "w", encoding="utf-8") as f:
            json.dump(payload if payload is not None else [], f)

        header = "$InFile = '{}'\n$OutFile = '{}'\n".format(
            in_path.replace("'", "''"), out_path.replace("'", "''")
        )
        # utf-8-sig: Windows PowerShell 5.1 needs the BOM to read the script
        # as Unicode, otherwise non-ASCII literals are mangled.
        with open(ps_path, "w", encoding="utf-8-sig") as f:
            f.write(header + _PS_PREAMBLE + "\n" + body)

        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", ps_path],
            capture_output=True, timeout=timeout,
        )

        if not os.path.exists(out_path):
            return []
        with open(out_path, "r", encoding="utf-8-sig") as f:
            text = f.read().strip()
        if not text:
            return []
        data = json.loads(text)
        if data is None:
            return []
        if isinstance(data, dict):
            return [data]
        return list(data)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- PowerShell snippets ---------------------------------------------------

PS_RESOLVE = r"""
$sh = New-Object -ComObject WScript.Shell
$res = New-Object System.Collections.ArrayList
foreach ($p in $Payload) {
    if (-not $p) { continue }
    $o = [ordered]@{ path = $p; target = ''; args = ''; workdir = ''; icon = '' }
    try {
        if ($p.ToLower().EndsWith('.url')) {
            $line = Get-Content -LiteralPath $p |
                Where-Object { $_ -like 'URL=*' } | Select-Object -First 1
            if ($line) { $o.target = $line.Substring(4) }
        } else {
            $sc = $sh.CreateShortcut($p)
            $o.target  = [string]$sc.TargetPath
            $o.args    = [string]$sc.Arguments
            $o.workdir = [string]$sc.WorkingDirectory
            $o.icon    = [string]$sc.IconLocation
        }
    } catch {}
    $null = $res.Add([PSCustomObject]$o)
}
Emit $res
"""

# Get-StartApps is the ground truth: it returns exactly what Start and Windows
# Search list under "Apps", for both Win32 shortcuts and Store packages.
PS_START_APPS = r"""
$res = @()
try { $res = Get-StartApps | Select-Object Name, AppID } catch {}
Emit $res
"""

_PS_SHELL_STRING = r"""
$def = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class WAHShell {
  [DllImport("shlwapi.dll", CharSet=CharSet.Unicode)]
  public static extern int SHLoadIndirectString(
      string pszSource, StringBuilder pszOutBuf, int cchOutBuf, IntPtr ppvReserved);
}
"@
try { Add-Type -TypeDefinition $def -ErrorAction Stop } catch {}

function Get-ShellString($id) {
    try {
        $sb = New-Object System.Text.StringBuilder 1024
        $src = "@$env:SystemRoot\system32\shell32.dll,-$id"
        if ([WAHShell]::SHLoadIndirectString($src, $sb, $sb.Capacity, [IntPtr]::Zero) -eq 0) {
            return $sb.ToString()
        }
    } catch {}
    return $null
}
function Clean($s) { return ($s -replace '&', '').Trim().ToLower() }
"""

# 5387 = "Unpin from tas&kbar", 5386 = "Pin to tas&kbar" in shell32.dll.
# Resolving the *localized* string is what makes this work on a non-English
# Windows; plain string matching on "Unpin from taskbar" does not.
PS_UNPIN_LNK = _PS_SHELL_STRING + r"""
$wanted = @('unpin from taskbar')
$loc = Get-ShellString 5387
if ($loc) { $wanted += (Clean $loc) }

$shell = New-Object -ComObject Shell.Application
$res = New-Object System.Collections.ArrayList
foreach ($p in $Payload) {
    $r = [ordered]@{ path = $p; ok = $false; verb = '' }
    try {
        $dir = Split-Path -Parent $p
        $leaf = Split-Path -Leaf $p
        $ns = $shell.NameSpace($dir)
        if ($ns) {
            $item = $ns.ParseName($leaf)
            if ($item) {
                foreach ($v in $item.Verbs()) {
                    if ($wanted -contains (Clean $v.Name)) {
                        $v.DoIt(); $r.ok = $true; $r.verb = $v.Name; break
                    }
                }
            }
        }
    } catch {}
    $null = $res.Add([PSCustomObject]$r)
}
Start-Sleep -Milliseconds 500
Emit $res
"""

# Best-effort only: Microsoft blocked programmatic "Pin to taskbar" in
# Windows 10 1709+, so this usually fails and we fall back to restoring the
# Taskband registry blob.
PS_PIN_LNK = _PS_SHELL_STRING + r"""
$wanted = @('pin to taskbar')
$loc = Get-ShellString 5386
if ($loc) { $wanted += (Clean $loc) }

$shell = New-Object -ComObject Shell.Application
$res = New-Object System.Collections.ArrayList
foreach ($p in $Payload) {
    $r = [ordered]@{ path = $p; ok = $false }
    try {
        $ns = $shell.NameSpace((Split-Path -Parent $p))
        if ($ns) {
            $item = $ns.ParseName((Split-Path -Leaf $p))
            if ($item) {
                foreach ($v in $item.Verbs()) {
                    if ($wanted -contains (Clean $v.Name)) {
                        $v.DoIt(); $r.ok = $true; break
                    }
                }
            }
        }
    } catch {}
    $null = $res.Add([PSCustomObject]$r)
}
Emit $res
"""

PS_RESTART_SHELL = r"""
$opts = @($Payload)[0]
$done = New-Object System.Collections.ArrayList

# Search / Start UI hosts. These are restarted by the shell automatically, and
# restarting them is what makes a removed app disappear from search results
# immediately instead of after an indexer pass.
if ($opts.search) {
    foreach ($n in 'StartMenuExperienceHost','SearchHost','SearchApp','ShellExperienceHost') {
        $procs = Get-Process -Name $n -ErrorAction SilentlyContinue
        if ($procs) {
            $procs | Stop-Process -Force -ErrorAction SilentlyContinue
            $null = $done.Add("restarted $n")
        }
    }
}

if ($opts.explorer) {
    Get-Process -Name explorer -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 1200
    if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
        Start-Process explorer.exe
    }
    $null = $done.Add("restarted explorer")
}
Emit $done
"""


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
def default_state():
    return {"version": 2, "apps": {}, "hidden_taskbar": {}, "hidden_tray": {}}


def load_state():
    path = state_file()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data.setdefault("apps", {})
            data.setdefault("hidden_taskbar", {})
            data.setdefault("hidden_tray", {})
            data["version"] = 2
            return data
        except (json.JSONDecodeError, IOError):
            pass

    state = default_state()
    if os.path.exists(LEGACY_STATE_FILE):
        state = _migrate_legacy(state)
    return state


def _migrate_legacy(state):
    """Carry v1 state (rename-in-place scheme) forward so old hides restore."""
    try:
        with open(LEGACY_STATE_FILE, "r", encoding="utf-8") as f:
            old = json.load(f)
    except (json.JSONDecodeError, IOError):
        return state

    entries = []
    for bucket, kind in (("hidden_start_menu", "start_menu"),
                         ("hidden_pinned_taskbar", "taskbar_pin")):
        for path, info in (old.get(bucket) or {}).items():
            entries.append({
                "original": info.get("original_path", path),
                "quarantined": info.get("hidden_path", path + ".hidden"),
                "kind": kind,
                "name": info.get("name", ""),
            })

    if entries:
        state["apps"]["legacy-v1"] = {
            "name": "Imported from previous version",
            "target": "",
            "date_hidden": now_stamp(),
            "shortcuts": entries,
            "pruned_dirs": [],
            "taskband": {},
            "userassist": [],
            "uninstall": [
                {"hive": HIVE_NAMES.get(i.get("hive"), "HKLM"),
                 "path": i.get("reg_path", ""),
                 "name": i.get("name", "")}
                for i in (old.get("hidden_registry") or {}).values()
            ],
            "exe_hidden": False,
        }
        print("[*] Imported {} item(s) from the old state file.".format(len(entries)))

    state["hidden_taskbar"] = old.get("hidden_taskbar", {})
    return state


def save_state(state):
    os.makedirs(state_dir(), exist_ok=True)
    path = state_file()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Discovery: shortcut locations
# ---------------------------------------------------------------------------
def shortcut_roots():
    """(kind, directory, recursive) for every place a launcher can live."""
    ad = USER_PATHS["appdata"]
    pd = USER_PATHS["programdata"]
    up = USER_PATHS["userprofile"]
    pub = USER_PATHS["public"]

    roots = [
        ("start_menu",
         os.path.join(pd, r"Microsoft\Windows\Start Menu\Programs"), True),
        ("start_menu",
         os.path.join(ad, r"Microsoft\Windows\Start Menu\Programs"), True),
        ("desktop", os.path.join(up, "Desktop"), False),
        ("desktop", os.path.join(pub, "Desktop"), False),
        # A OneDrive-redirected Desktop is the real one on many machines.
        ("desktop", os.path.join(os.environ.get("OneDrive", ""), "Desktop"), False),
        ("taskbar_pin",
         os.path.join(ad, r"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"),
         False),
        ("startmenu_pin",
         os.path.join(ad, r"Microsoft\Internet Explorer\Quick Launch\User Pinned\StartMenu"),
         False),
    ]
    # looks_like_fs_path guards against an unset env var collapsing a join into
    # a relative path that happens to exist in the current directory.
    seen = set()
    out = []
    for kind, d, rec in roots:
        if not (d and looks_like_fs_path(d) and os.path.isdir(d)):
            continue
        key = norm(d)
        if key in seen:
            continue
        seen.add(key)
        out.append((kind, d, rec))
    return out


KIND_LABELS = {
    "start_menu": "Start Menu",
    "desktop": "Desktop",
    "taskbar_pin": "Taskbar pin",
    "startmenu_pin": "Start pin",
    "jumplist": "Jump list",
}


def scan_shortcuts():
    """Collect every .lnk/.url under the roots and resolve targets in one call."""
    found = []
    seen = set()
    for kind, root, recursive in shortcut_roots():
        if recursive:
            walker = os.walk(root)
        else:
            try:
                walker = [(root, [], os.listdir(root))]
            except OSError:
                continue
        for cur, _dirs, files in walker:
            for name in files:
                low = name.lower()
                if not (low.endswith(".lnk") or low.endswith(".url")):
                    continue
                full = os.path.join(cur, name)
                key = norm(full)
                if key in seen:
                    continue
                seen.add(key)
                found.append({
                    "path": full,
                    "name": os.path.splitext(name)[0],
                    "kind": kind,
                    "root": root,
                })

    if not found:
        return []

    resolved = {}
    for row in ps_json(PS_RESOLVE, [f["path"] for f in found]):
        if not isinstance(row, dict):
            continue
        p = row.get("path")
        if isinstance(p, str) and p:
            resolved[norm(p) or p] = row

    for f in found:
        info = resolved.get(norm(f["path"]), {})
        f["target"] = (info.get("target") or "").strip()
        f["args"] = (info.get("args") or "").strip()
        f["icon"] = (info.get("icon") or "").strip()
    return found


# ---------------------------------------------------------------------------
# Discovery: installed apps (uninstall list)
# ---------------------------------------------------------------------------
def _read_value(key, name):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def get_installed_apps():
    apps = []
    seen = set()
    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY

    for hive, path in UNINSTALL_PATHS:
        try:
            root = winreg.OpenKey(hive, path, 0, access)
        except OSError:
            continue
        try:
            count = winreg.QueryInfoKey(root)[0]
            for i in range(count):
                try:
                    sub_name = winreg.EnumKey(root, i)
                    sub = winreg.OpenKey(root, sub_name, 0, access)
                except OSError:
                    continue
                try:
                    display = _read_value(sub, "DisplayName")
                    if not display or not str(display).strip():
                        continue
                    display = str(display).strip()
                    dedupe = (HIVE_NAMES.get(hive, "?"), path, sub_name)
                    if dedupe in seen:
                        continue
                    seen.add(dedupe)

                    icon = _read_value(sub, "DisplayIcon") or ""
                    # DisplayIcon is often "C:\...\app.exe,0"
                    icon_path = str(icon).split(",")[0].strip().strip('"')

                    apps.append({
                        "name": display,
                        "reg_key": sub_name,
                        "reg_path": "{}\\{}".format(path, sub_name),
                        "hive": HIVE_NAMES.get(hive, "HKLM"),
                        "install_location": str(
                            _read_value(sub, "InstallLocation") or "").strip().strip('"'),
                        "display_icon": icon_path,
                        "is_hidden": _read_value(sub, "SystemComponent") == 1,
                    })
                finally:
                    sub.Close()
        finally:
            root.Close()

    apps.sort(key=lambda a: a["name"].lower())
    return apps


def set_system_component(hive_name, reg_path, hide):
    """SystemComponent=1 removes an entry from Settings > Installed apps."""
    hive = HIVE_BY_NAME.get(hive_name, winreg.HKEY_LOCAL_MACHINE)
    try:
        key = winreg.OpenKey(hive, reg_path, 0,
                             winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
    except OSError as exc:
        print("    [FAIL]  registry {}: {}".format(reg_path, exc))
        return False
    try:
        if hide:
            winreg.SetValueEx(key, "SystemComponent", 0, winreg.REG_DWORD, 1)
        else:
            try:
                winreg.DeleteValue(key, "SystemComponent")
            except OSError:
                pass
        return True
    except OSError as exc:
        print("    [FAIL]  registry {}: {}".format(reg_path, exc))
        return False
    finally:
        key.Close()


# ---------------------------------------------------------------------------
# Grouping shortcuts + registry entries into apps
# ---------------------------------------------------------------------------
def _group_key(shortcut):
    """Group by resolved target executable — not by fuzzy name matching."""
    target = shortcut.get("target") or ""
    nt = norm(target)
    if nt:
        base = os.path.basename(nt)
        if base in LAUNCHER_EXES and shortcut.get("args"):
            return "exe::{}::{}".format(nt, shortcut["args"].lower())
        return "exe::{}".format(nt)
    return "name::{}".format(shortcut["name"].strip().lower())


def _generic_roots():
    """Directories too broad to prove ownership of an executable."""
    env = os.environ
    candidates = [
        env.get("ProgramFiles", r"C:\Program Files"),
        env.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        env.get("ProgramW6432", r"C:\Program Files"),
        env.get("SystemRoot", r"C:\Windows"),
        os.path.join(env.get("SystemRoot", r"C:\Windows"), "System32"),
        USER_PATHS["programdata"],
        USER_PATHS["userprofile"],
        USER_PATHS["appdata"],
        USER_PATHS["localappdata"],
        os.path.join(USER_PATHS["localappdata"], "Programs"),
    ]
    return {norm(c) for c in candidates if norm(c)}


def _usable_install_location(path):
    """Reject InstallLocation values that would swallow unrelated apps.

    Plenty of uninstall entries record InstallLocation as "C:\\Program Files"
    or the drive root; treating those as ownership would match every app
    installed underneath them.
    """
    n = norm(path)
    if not n:
        return ""
    n = n.rstrip("\\")
    if len([p for p in n.split("\\") if p]) < 2:
        return ""
    if n in _generic_roots():
        return ""
    return n


def _uninstall_matches(entry, exe_paths):
    """True when an uninstall entry provably belongs to one of these exes."""
    install = _usable_install_location(entry.get("install_location") or "")
    icon = norm(entry.get("display_icon") or "")
    for exe in exe_paths:
        if not exe:
            continue
        if icon and icon == exe:
            return True
        if install and exe.startswith(install + "\\"):
            return True
    return False


def build_app_groups(shortcuts, installed):
    groups = {}
    for sc in shortcuts:
        key = _group_key(sc)
        g = groups.setdefault(key, {
            "key": key,
            "id": app_id_for(key),
            "target": sc.get("target") or "",
            "shortcuts": [],
            "uninstall": [],
            "names": {},
        })
        g["shortcuts"].append(sc)
        g["names"][sc["name"]] = g["names"].get(sc["name"], 0) + 1
        if not g["target"] and sc.get("target"):
            g["target"] = sc["target"]

    # Attach uninstall entries by executable path. Name matching is used only
    # as a strict fallback (exact, case-folded) because the old substring rule
    # produced constant false positives.
    for g in groups.values():
        exes = {norm(g["target"])} if norm(g["target"]) else set()
        shortcut_names = {n.strip().lower() for n in g["names"]}
        for entry in installed:
            if exes and _uninstall_matches(entry, exes):
                g["uninstall"].append(entry)
            elif entry["name"].strip().lower() in shortcut_names:
                g["uninstall"].append(entry)

    for g in groups.values():
        if g["uninstall"]:
            g["name"] = g["uninstall"][0]["name"]
        elif g["names"]:
            g["name"] = max(g["names"].items(), key=lambda kv: kv[1])[0]
        elif g["target"]:
            g["name"] = os.path.basename(g["target"])
        else:
            g["name"] = g["key"]

    return sorted(groups.values(), key=lambda g: g["name"].lower())


def group_summary(g):
    counts = {}
    for sc in g["shortcuts"]:
        counts[sc["kind"]] = counts.get(sc["kind"], 0) + 1
    parts = ["{} x{}".format(KIND_LABELS.get(k, k), v)
             for k, v in sorted(counts.items())]
    if g["uninstall"]:
        parts.append("Uninstall entry")
    return ", ".join(parts) if parts else "no artifacts"


# ---------------------------------------------------------------------------
# Quarantine (move, don't rename-in-place)
# ---------------------------------------------------------------------------
def quarantine_file(src, app_id, copy=False):
    """Move (or copy) a file into quarantine; return the new path or None."""
    if not os.path.exists(src):
        return None
    dest_dir = os.path.join(quarantine_dir(), app_id)
    os.makedirs(dest_dir, exist_ok=True)
    base = os.path.basename(src)
    dest = os.path.join(dest_dir, base)
    n = 1
    while os.path.exists(dest):
        stem, ext = os.path.splitext(base)
        dest = os.path.join(dest_dir, "{}__{}{}".format(stem, n, ext))
        n += 1
    try:
        if copy:
            shutil.copy2(src, dest)
        else:
            shutil.move(src, dest)
        return dest
    except (OSError, shutil.Error) as exc:
        print("    [FAIL]  {} {}: {}".format(
            "copy" if copy else "move", base, exc))
        return None


def restore_file(quarantined, original):
    if not quarantined or not os.path.exists(quarantined):
        return False
    try:
        parent = os.path.dirname(original)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        if os.path.exists(original):
            os.remove(quarantined)
            return True
        shutil.move(quarantined, original)
        return True
    except (OSError, shutil.Error) as exc:
        print("    [FAIL]  restore {}: {}".format(
            os.path.basename(original), exc))
        return False


def prune_empty_dirs(path, stop_roots):
    """Remove now-empty Start Menu folders, whose names also leak in search."""
    removed = []
    stop = {norm(r) for r in stop_roots}
    cur = os.path.dirname(path)
    while cur and norm(cur) not in stop:
        try:
            if os.path.isdir(cur) and not os.listdir(cur):
                os.rmdir(cur)
                removed.append(cur)
                cur = os.path.dirname(cur)
                continue
        except OSError:
            pass
        break
    return removed


# ---------------------------------------------------------------------------
# Jump lists and Recent items
# ---------------------------------------------------------------------------
def _file_mentions(path, needle_lower):
    """Jump-list files embed the exe path as UTF-16LE; scan raw bytes for it."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return False
    for enc in ("utf-16-le", "latin-1"):
        try:
            if needle_lower in data.decode(enc, errors="ignore").lower():
                return True
        except Exception:
            continue
    return False


def find_jumplist_files(target_exe):
    """Jump lists feed the Start menu's 'Recent' section — they leak the app."""
    if not target_exe:
        return []
    needle = norm(target_exe)
    if not needle:
        return []

    recent = os.path.join(USER_PATHS["appdata"], r"Microsoft\Windows\Recent")
    hits = []
    for sub in ("AutomaticDestinations", "CustomDestinations"):
        folder = os.path.join(recent, sub)
        if not os.path.isdir(folder):
            continue
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        for name in names:
            full = os.path.join(folder, name)
            if os.path.isfile(full) and _file_mentions(full, needle):
                hits.append(full)
    return hits


# ---------------------------------------------------------------------------
# UserAssist ("Most used" in Start)
# ---------------------------------------------------------------------------
def _rot13(text):
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def clear_userassist(target_exe):
    """Remove launch-count entries so the app leaves Start's 'Most used'."""
    if not target_exe:
        return []
    needle = norm(target_exe)
    if not needle:
        return []

    backups = []
    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, USERASSIST_KEY)
    except OSError:
        return []
    try:
        for i in range(winreg.QueryInfoKey(root)[0]):
            try:
                guid = winreg.EnumKey(root, i)
                count_path = "{}\\{}\\Count".format(USERASSIST_KEY, guid)
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, count_path, 0,
                    winreg.KEY_READ | winreg.KEY_SET_VALUE)
            except OSError:
                continue
            try:
                doomed = []
                for j in range(winreg.QueryInfoKey(key)[1]):
                    try:
                        name, data, dtype = winreg.EnumValue(key, j)
                    except OSError:
                        continue
                    decoded = _rot13(name)
                    if needle in decoded.lower():
                        doomed.append((name, data, dtype))
                for name, data, dtype in doomed:
                    try:
                        winreg.DeleteValue(key, name)
                        backups.append({
                            "key": count_path, "name": name, "type": dtype,
                            "data": b64(data) if isinstance(data, (bytes, bytearray)) else data,
                            "binary": isinstance(data, (bytes, bytearray)),
                        })
                    except OSError:
                        pass
            finally:
                key.Close()
    finally:
        root.Close()
    return backups


def restore_userassist(backups):
    for item in backups or []:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, item["key"], 0,
                                 winreg.KEY_SET_VALUE)
        except OSError:
            continue
        try:
            data = unb64(item["data"]) if item.get("binary") else item["data"]
            winreg.SetValueEx(key, item["name"], 0, item["type"], data)
        except OSError:
            pass
        finally:
            key.Close()


# ---------------------------------------------------------------------------
# Taskbar pins (Taskband registry blob)
# ---------------------------------------------------------------------------
def read_taskband():
    """Snapshot the binary pin list so an unpin can be reversed exactly."""
    snap = {}
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, TASKBAND_KEY)
    except OSError:
        return snap
    try:
        for name in ("Favorites", "FavoritesResolve"):
            try:
                data, dtype = winreg.QueryValueEx(key, name)
                if isinstance(data, (bytes, bytearray)):
                    snap[name] = {"data": b64(data), "type": dtype}
            except OSError:
                pass
    finally:
        key.Close()
    return snap


def write_taskband(snap):
    if not snap:
        return False
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, TASKBAND_KEY, 0,
                                 winreg.KEY_SET_VALUE)
    except OSError:
        return False
    try:
        for name, item in snap.items():
            try:
                winreg.SetValueEx(key, name, 0, item["type"], unb64(item["data"]))
            except OSError:
                return False
        return True
    finally:
        key.Close()


def clear_taskband_values():
    """Drop the pin blob; Explorer rebuilds it from the pin folder on restart."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, TASKBAND_KEY, 0,
                             winreg.KEY_SET_VALUE)
    except OSError:
        return False
    try:
        for name in ("Favorites", "FavoritesResolve"):
            try:
                winreg.DeleteValue(key, name)
            except OSError:
                pass
        return True
    finally:
        key.Close()


def taskband_equal(a, b):
    if not a and not b:
        return True
    if not a or not b:
        return False
    return {k: v.get("data") for k, v in a.items()} == \
           {k: v.get("data") for k, v in b.items()}


def restart_shell(explorer=False, search=True):
    return ps_json(PS_RESTART_SHELL,
                   [{"explorer": bool(explorer), "search": bool(search)}],
                   timeout=90)


# ---------------------------------------------------------------------------
# Hide / restore a whole app
# ---------------------------------------------------------------------------
def hide_app(group, state, hide_exe_file=False):
    app_id = group["id"]
    print("\n>> Hiding: {}".format(group["name"]))

    record = state["apps"].get(app_id) or {
        "name": group["name"],
        "key": group["key"],
        "target": group["target"],
        "date_hidden": now_stamp(),
        "shortcuts": [],
        "pruned_dirs": [],
        "taskband": {},
        "userassist": [],
        "uninstall": [],
        "exe_hidden": False,
    }

    pins = [sc for sc in group["shortcuts"] if sc["kind"] == "taskbar_pin"]
    touched_taskbar = bool(pins)

    # --- 1. Taskbar pins ---------------------------------------------------
    if pins:
        if not record["taskband"]:
            record["taskband"] = {"before": read_taskband()}

        # Copy the pin shortcuts aside *before* unpinning: a successful
        # "Unpin from taskbar" verb deletes the .lnk itself, so without a copy
        # there would be nothing left to put back on restore.
        for p in pins:
            record["shortcuts"].append({
                "original": p["path"],
                "quarantined": quarantine_file(p["path"], app_id, copy=True),
                "kind": "taskbar_pin",
                "name": p["name"],
            })

        results = {r["path"]: r for r in
                   ps_json(PS_UNPIN_LNK, [p["path"] for p in pins])
                   if isinstance(r, dict) and isinstance(r.get("path"), str)}
        verb_worked = False
        for p in pins:
            r = results.get(p["path"]) or {}
            if r.get("ok"):
                verb_worked = True
                print("    [UNPIN] {} (via '{}')".format(p["name"], r.get("verb", "")))
            else:
                print("    [UNPIN] {} (shell verb unavailable)".format(p["name"]))

        # Whatever the verb did, the .lnk must not survive in the pin folder.
        for p in pins:
            if os.path.exists(p["path"]):
                try:
                    os.remove(p["path"])
                except OSError as exc:
                    print("    [FAIL]  remove pin {}: {}".format(p["name"], exc))

        if not verb_worked:
            # Explorer rebuilds Favorites from the pin folder when the value is
            # absent, so removing the .lnk plus clearing the blob is a reliable
            # fallback. The exact prior blob is already backed up.
            clear_taskband_values()
            print("    [UNPIN] cleared Taskband pin cache (rebuild on restart)")

    # --- 2. Move every other shortcut out of every indexed location --------
    roots = [d for (_k, d, _r) in shortcut_roots()]
    for sc in group["shortcuts"]:
        if sc["kind"] == "taskbar_pin":
            continue  # handled above
        dest = quarantine_file(sc["path"], app_id)
        if dest:
            record["shortcuts"].append({
                "original": sc["path"],
                "quarantined": dest,
                "kind": sc["kind"],
                "name": sc["name"],
            })
            print("    [HIDE]  {}: {}".format(
                KIND_LABELS.get(sc["kind"], sc["kind"]), sc["name"]))
            if sc["kind"] == "start_menu":
                record["pruned_dirs"].extend(prune_empty_dirs(sc["path"], roots))

    # --- 3. Jump lists (Start menu "Recent") -------------------------------
    for jl in find_jumplist_files(group["target"]):
        dest = quarantine_file(jl, app_id)
        if dest:
            record["shortcuts"].append({
                "original": jl, "quarantined": dest,
                "kind": "jumplist", "name": os.path.basename(jl),
            })
            print("    [HIDE]  Jump list: {}".format(os.path.basename(jl)))

    # --- 4. "Most used" launch counts --------------------------------------
    ua = clear_userassist(group["target"])
    if ua:
        record["userassist"].extend(ua)
        print("    [HIDE]  {} UserAssist entry(ies) ('Most used')".format(len(ua)))

    # --- 5. Settings > Installed apps --------------------------------------
    for entry in group["uninstall"]:
        if set_system_component(entry["hive"], entry["reg_path"], True):
            record["uninstall"].append({
                "hive": entry["hive"],
                "reg_path": entry["reg_path"],
                "name": entry["name"],
            })
            print("    [HIDE]  Uninstall entry: {}".format(entry["name"]))

    # --- 6. Optional: the .exe itself --------------------------------------
    if hide_exe_file and norm(group["target"]) and os.path.isfile(group["target"]):
        try:
            attrs = _kernel32.GetFileAttributesW(group["target"])
            if attrs != INVALID_FILE_ATTRIBUTES and not (attrs & FILE_ATTRIBUTE_HIDDEN):
                _kernel32.SetFileAttributesW(
                    group["target"], attrs | FILE_ATTRIBUTE_HIDDEN)
                record["exe_hidden"] = True
                print("    [HIDE]  file attribute on {}".format(
                    os.path.basename(group["target"])))
        except Exception as exc:
            print("    [FAIL]  hide exe: {}".format(exc))

    if touched_taskbar and record["taskband"]:
        record["taskband"]["after_pending"] = True

    state["apps"][app_id] = record
    return touched_taskbar


def restore_app(app_id, record, state):
    print("\n>> Restoring: {}".format(record.get("name", app_id)))
    touched_taskbar = False

    for sc in record.get("shortcuts", []):
        if sc.get("kind") == "taskbar_pin":
            touched_taskbar = True
        if restore_file(sc.get("quarantined"), sc.get("original")):
            print("    [BACK]  {}: {}".format(
                KIND_LABELS.get(sc.get("kind"), sc.get("kind")),
                sc.get("name", "")))

    restore_userassist(record.get("userassist"))
    if record.get("userassist"):
        print("    [BACK]  UserAssist entries")

    for entry in record.get("uninstall", []):
        path = entry.get("reg_path") or entry.get("path", "")
        if path and set_system_component(entry.get("hive", "HKLM"), path, False):
            print("    [BACK]  Uninstall entry: {}".format(entry.get("name", "")))

    if record.get("exe_hidden") and record.get("target"):
        try:
            attrs = _kernel32.GetFileAttributesW(record["target"])
            if attrs != INVALID_FILE_ATTRIBUTES and attrs & FILE_ATTRIBUTE_HIDDEN:
                _kernel32.SetFileAttributesW(
                    record["target"], attrs & ~FILE_ATTRIBUTE_HIDDEN)
                print("    [BACK]  file attribute cleared")
        except Exception:
            pass

    # Taskbar pin: try the (usually blocked) pin verb, else put the exact
    # pre-hide blob back — but only if the user has not re-arranged pins since,
    # because the blob is all-or-nothing.
    tb = record.get("taskband") or {}
    if touched_taskbar and tb.get("before"):
        pin_paths = [sc["original"] for sc in record.get("shortcuts", [])
                     if sc.get("kind") == "taskbar_pin"
                     and os.path.exists(sc.get("original", ""))]
        pinned = any(r.get("ok") for r in ps_json(PS_PIN_LNK, pin_paths)) if pin_paths else False

        if pinned:
            print("    [BACK]  re-pinned via shell verb")
        else:
            write_blob = True
            after = tb.get("after")
            if after and not taskband_equal(read_taskband(), after):
                # The blob is all-or-nothing, so overwriting it would also undo
                # any pinning the user did after the hide.
                print("    [WARN]  Taskbar pins changed since hiding.")
                write_blob = bool(questionary.confirm(
                    "    Overwrite current pin layout with the saved one? "
                    "(No = leave pins alone, re-pin manually)",
                    default=False,
                ).ask())
            if not write_blob:
                print("    [SKIP]  pin layout left as-is")
            elif write_taskband(tb["before"]):
                print("    [BACK]  restored taskbar pin layout")

    for d in record.get("pruned_dirs", []):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass

    if app_id in state["apps"]:
        del state["apps"][app_id]
    return touched_taskbar


# ---------------------------------------------------------------------------
# Verification — does Search still know about it?
# ---------------------------------------------------------------------------
def get_start_apps():
    out = []
    for row in ps_json(PS_START_APPS, timeout=90):
        if isinstance(row, dict) and row.get("Name"):
            out.append({"name": row["Name"], "appid": row.get("AppID", "")})
    return out


def verify(state):
    """Re-query the shell for each hidden app and report what still shows."""
    if not state["apps"]:
        print("\n[*] Nothing is currently hidden.")
        return

    print("\n[*] Asking the shell what Start/Search currently lists...")
    start_apps = get_start_apps()
    listed = {a["name"].strip().lower() for a in start_apps}
    print("    Start/Search reports {} app entries.\n".format(len(start_apps)))

    for app_id, rec in state["apps"].items():
        name = rec.get("name", app_id)
        problems = []

        if name.strip().lower() in listed:
            problems.append("still listed by Start/Search")

        for sc in rec.get("shortcuts", []):
            if os.path.exists(sc.get("original", "")):
                problems.append("shortcut reappeared: {}".format(sc["original"]))
            elif not os.path.exists(sc.get("quarantined", "")):
                problems.append("quarantined file missing: {}".format(
                    sc.get("quarantined", "")))

        status = "OK  " if not problems else "WARN"
        print("  [{}] {}".format(status, name))
        for p in problems:
            print("         - {}".format(p))
    print()


# ---------------------------------------------------------------------------
# Advanced: running windows (live taskbar buttons)
# ---------------------------------------------------------------------------
def get_process_name(pid):
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return "<PID:{}>".format(pid)
    try:
        buf = create_unicode_buffer(32768)
        size = wintypes.DWORD(32768)
        if kernel32.QueryFullProcessImageNameW(handle, 0, buf, byref(size)):
            return os.path.basename(buf.value) or "<PID:{}>".format(pid)
        return "<PID:{}>".format(pid)
    finally:
        kernel32.CloseHandle(handle)


WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


def enum_windows(callback):
    ctypes.windll.user32.EnumWindows(WNDENUMPROC(callback), 0)


def get_running_windows():
    user32 = ctypes.windll.user32
    windows = []

    def proc(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        buf = create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        title = buf.value.strip()
        if not title:
            return True
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, byref(pid))
        ex_style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
        windows.append({
            "hwnd": hwnd,
            "title": title,
            "pid": pid.value,
            "process_name": get_process_name(pid.value),
            "is_toolwindow": bool(ex_style & WS_EX_TOOLWINDOW),
            "ex_style": ex_style,
        })
        return True

    enum_windows(proc)
    windows.sort(key=lambda w: (w["process_name"].lower(), w["title"].lower()))
    return windows


def set_window_toolwindow(hwnd, toolwindow):
    """WS_EX_TOOLWINDOW removes a live window's taskbar button."""
    user32 = ctypes.windll.user32
    ex_style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
    if toolwindow:
        new_style = (ex_style | WS_EX_TOOLWINDOW) & ~WS_EX_APPWINDOW
    else:
        new_style = (ex_style & ~WS_EX_TOOLWINDOW) | WS_EX_APPWINDOW
    user32.SetWindowLongW(hwnd, GWL_EXSTYLE, new_style)

    # The taskbar only re-reads the style when the window is hidden and shown
    # again with SWP_FRAMECHANGED; ShowWindow alone is not enough on Win10/11.
    flags = SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE
    user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, flags | SWP_HIDEWINDOW)
    time.sleep(0.05)
    user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, flags | SWP_SHOWWINDOW)


# ---------------------------------------------------------------------------
# Advanced: system tray icons (cross-process toolbar read)
# ---------------------------------------------------------------------------
_IS_64 = ctypes.sizeof(ctypes.c_void_p) == 8
ULONG_PTR = ctypes.c_uint64 if _IS_64 else ctypes.c_uint32
INT_PTR = ctypes.c_int64 if _IS_64 else ctypes.c_int32


class TBBUTTON(ctypes.Structure):
    # bReserved is 6 bytes on x64 and 2 on x86; dwData/iString are pointer
    # sized. The previous fixed 32-bit layout misread every button on 64-bit.
    _fields_ = [
        ("iBitmap", ctypes.c_int),
        ("idCommand", ctypes.c_int),
        ("fsState", ctypes.c_byte),
        ("fsStyle", ctypes.c_byte),
        ("bReserved", ctypes.c_byte * (6 if _IS_64 else 2)),
        ("dwData", ULONG_PTR),
        ("iString", INT_PTR),
    ]


def _find_child_chain(parent, *classes):
    user32 = ctypes.windll.user32
    cur = parent
    for cls in classes:
        cur = user32.FindWindowExW(cur, 0, cls, None)
        if not cur:
            return None
    return cur


def _read_toolbar_buttons(tb_hwnd):
    """TB_GETBUTTON writes into the *owning* process, so allocate memory there."""
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32

    count = user32.SendMessageW(tb_hwnd, TB_BUTTONCOUNT, 0, 0)
    if count <= 0 or count > 512:
        return []

    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(tb_hwnd, byref(pid))
    handle = kernel32.OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE
        | PROCESS_QUERY_INFORMATION, False, pid.value)
    if not handle:
        return []

    size = sizeof(TBBUTTON)
    remote = kernel32.VirtualAllocEx(
        handle, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not remote:
        kernel32.CloseHandle(handle)
        return []

    buttons = []
    try:
        for i in range(count):
            if not user32.SendMessageW(tb_hwnd, TB_GETBUTTON, i, remote):
                continue
            local = TBBUTTON()
            read = ctypes.c_size_t(0)
            if kernel32.ReadProcessMemory(
                    handle, ctypes.c_void_p(remote), byref(local), size, byref(read)):
                buttons.append({
                    "index": i,
                    "id_command": local.idCommand,
                    "fs_state": local.fsState,
                    "dw_data": local.dwData,
                })
    finally:
        kernel32.VirtualFreeEx(handle, ctypes.c_void_p(remote), 0, MEM_RELEASE)
        kernel32.CloseHandle(handle)
    return buttons


def get_tray_icons():
    user32 = ctypes.windll.user32
    icons = []

    def collect(tb_hwnd, label):
        if not tb_hwnd:
            return
        for btn in _read_toolbar_buttons(tb_hwnd):
            owner = None
            try:
                candidate = wintypes.HWND(btn["dw_data"])
                if user32.IsWindow(candidate):
                    owner = candidate
            except Exception:
                owner = None
            proc = "TrayIcon#{}".format(btn["id_command"])
            if owner:
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(owner, byref(pid))
                if pid.value:
                    proc = get_process_name(pid.value)
            icons.append({
                "id_command": btn["id_command"],
                "index": btn["index"],
                "toolbar_hwnd": tb_hwnd,
                "label": label,
                "process_name": proc,
                "title": "[{}] {} (cmd#{})".format(label, proc, btn["id_command"]),
            })

    taskbar = user32.FindWindowW("Shell_TrayWnd", None)
    if taskbar:
        collect(_find_child_chain(taskbar, "TrayNotifyWnd", "SysPager",
                                  "ToolbarWindow32"), "Tray")
    overflow = user32.FindWindowW("NotifyIconOverflowWindow", None)
    if overflow:
        collect(user32.FindWindowExW(overflow, 0, "ToolbarWindow32", None),
                "Overflow")
    secondary = user32.FindWindowW("Shell_SecondaryTrayWnd", None)
    if secondary:
        collect(_find_child_chain(secondary, "TrayNotifyWnd", "SysPager",
                                  "ToolbarWindow32"), "Tray2")
    return icons


def hide_tray_icon(icon, hide):
    ctypes.windll.user32.SendMessageW(
        icon["toolbar_hwnd"], TB_HIDEBUTTON, icon["id_command"], 1 if hide else 0)


# ---------------------------------------------------------------------------
# Interactive flows
# ---------------------------------------------------------------------------
SELECT_HELP = "(ARROW keys = move | SPACE = select | ENTER = confirm)"


def _banner(text):
    print("\n" + "=" * 68)
    print("  " + text)
    print("=" * 68)


def flow_hide(state):
    print("\n[*] Scanning shortcuts (Start Menu, Desktop, taskbar pins)...")
    shortcuts = scan_shortcuts()
    print("    Found {} shortcut(s)".format(len(shortcuts)))

    print("[*] Reading installed-app registry...")
    installed = get_installed_apps()
    print("    Found {} installed app(s)".format(len(installed)))

    groups = build_app_groups(shortcuts, installed)
    already = set(state["apps"].keys())
    groups = [g for g in groups if g["id"] not in already]
    if not groups:
        print("\n[*] Nothing available to hide.")
        return

    choices = []
    for g in groups:
        choices.append(questionary.Choice(
            title="{}   [{}]".format(g["name"], group_summary(g)),
            value=g,
        ))

    _banner("Select the app(s) to hide. SPACE to tick, ENTER to confirm.")
    selected = questionary.checkbox(
        "Hide which application(s)?", choices=choices, instruction=SELECT_HELP,
    ).ask()
    if not selected:
        print("\n[*] Nothing selected.")
        return

    hide_exe = questionary.confirm(
        "Also set the Hidden attribute on the program's .exe "
        "(stops it appearing under file results)?",
        default=False,
    ).ask()

    print("\n[*] Applying to {} app(s)...".format(len(selected)))
    touched_taskbar = False
    for g in selected:
        if hide_app(g, state, hide_exe_file=bool(hide_exe)):
            touched_taskbar = True

    # Record the post-change pin blob so a later restore can tell whether the
    # user re-arranged their taskbar in the meantime.
    if touched_taskbar:
        restart_shell(explorer=True, search=True)
        # Explorer rewrites the pin blob a moment after it comes back up.
        time.sleep(3.0)
        after = read_taskband()
        for g in selected:
            rec = state["apps"].get(g["id"])
            if rec and rec.get("taskband", {}).pop("after_pending", None):
                rec["taskband"]["after"] = after
    else:
        restart_shell(explorer=False, search=True)

    save_state(state)
    print("\n[OK] Done. State: {}".format(state_file()))
    print("     Search/Start were refreshed. Run 'Verify' to confirm.")


def flow_restore(state):
    if not state["apps"]:
        print("\n[*] Nothing is currently hidden.")
        return

    choices = []
    for app_id, rec in sorted(state["apps"].items(),
                              key=lambda kv: kv[1].get("name", "").lower()):
        n = len(rec.get("shortcuts", []))
        choices.append(questionary.Choice(
            title="{}   [{} item(s), hidden {}]".format(
                rec.get("name", app_id), n, rec.get("date_hidden", "?")),
            value=app_id,
        ))

    _banner("Select the app(s) to bring back.")
    selected = questionary.checkbox(
        "Restore which application(s)?", choices=choices, instruction=SELECT_HELP,
    ).ask()
    if not selected:
        print("\n[*] Nothing selected.")
        return

    touched_taskbar = False
    for app_id in selected:
        rec = state["apps"].get(app_id)
        if rec and restore_app(app_id, rec, state):
            touched_taskbar = True

    restart_shell(explorer=touched_taskbar, search=True)
    save_state(state)
    print("\n[OK] Restored. State: {}".format(state_file()))


def flow_advanced(state):
    action = questionary.select(
        "Advanced:",
        choices=[
            questionary.Choice("Hide a running window's taskbar button", "window"),
            questionary.Choice("Restore hidden window taskbar buttons", "window_restore"),
            questionary.Choice("Hide a system tray icon (until restart)", "tray"),
            questionary.Choice("Back", "back"),
        ],
    ).ask()

    if action in (None, "back"):
        return

    if action == "window":
        windows = [w for w in get_running_windows() if not w["is_toolwindow"]]
        if not windows:
            print("\n[*] No eligible windows.")
            return
        _banner("Select running window(s) to remove from the taskbar.")
        selected = questionary.checkbox(
            "Hide which window(s)?",
            choices=[questionary.Choice(
                "{} - {}".format(w["process_name"], w["title"][:60]), w)
                for w in windows],
            instruction=SELECT_HELP,
        ).ask()
        for w in selected or []:
            set_window_toolwindow(w["hwnd"], True)
            state["hidden_taskbar"]["{}||{}".format(w["process_name"], w["title"])] = {
                "process_name": w["process_name"],
                "title": w["title"],
                "date_hidden": now_stamp(),
            }
            print("  [HIDE]  {} - {}".format(w["process_name"], w["title"][:50]))
        save_state(state)

    elif action == "window_restore":
        entries = state.get("hidden_taskbar", {})
        if not entries:
            print("\n[*] No hidden windows recorded.")
            return
        _banner("Select window(s) to bring back to the taskbar.")
        selected = questionary.checkbox(
            "Restore which?",
            choices=[questionary.Choice(
                "{} - {}".format(v.get("process_name", "?"), v.get("title", "")[:50]), k)
                for k, v in entries.items()],
            instruction=SELECT_HELP,
        ).ask()
        for key in selected or []:
            proc = entries[key].get("process_name", "")
            found = []

            def finder(hwnd, _lp):
                pid = wintypes.DWORD()
                ctypes.windll.user32.GetWindowThreadProcessId(hwnd, byref(pid))
                if get_process_name(pid.value) == proc:
                    found.append(hwnd)
                return True

            enum_windows(finder)
            for hwnd in found:
                set_window_toolwindow(hwnd, False)
            print("  [BACK]  {} ({} window(s))".format(proc, len(found)))
            del entries[key]
        save_state(state)

    elif action == "tray":
        icons = get_tray_icons()
        if not icons:
            print("\n[*] No tray icons readable.")
            return
        print("\n[!] Tray hiding is not persistent — icons return when the")
        print("    owning app or Explorer restarts.")
        _banner("Select tray icon(s) to hide.")
        selected = questionary.checkbox(
            "Hide which icon(s)?",
            choices=[questionary.Choice(i["title"], i) for i in icons],
            instruction=SELECT_HELP,
        ).ask()
        for icon in selected or []:
            hide_tray_icon(icon, True)
            print("  [HIDE]  {}".format(icon["title"]))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--appdata")
    p.add_argument("--localappdata")
    p.add_argument("--userprofile")
    args, _ = p.parse_known_args()
    if args.appdata:
        USER_PATHS["appdata"] = args.appdata
    if args.localappdata:
        USER_PATHS["localappdata"] = args.localappdata
    if args.userprofile:
        USER_PATHS["userprofile"] = args.userprofile


def main():
    parse_args()

    _banner("Windows App Hider  -  hide an app from Search and the taskbar")

    if not is_admin():
        print("\n[!] Administrator rights are required (machine-wide Start Menu")
        print("    entries and HKLM registry values). Re-launching elevated...")
        run_as_admin()
        return

    os.makedirs(quarantine_dir(), exist_ok=True)
    state = load_state()

    while True:
        hidden_count = len(state["apps"])
        action = questionary.select(
            "What would you like to do?  ({} app(s) currently hidden)".format(hidden_count),
            choices=[
                questionary.Choice(
                    "Hide an app  (Search + Start + Taskbar + Settings)", "hide"),
                questionary.Choice("Bring a hidden app back", "restore"),
                questionary.Choice("Verify what is currently hidden", "verify"),
                questionary.Choice("Advanced (running windows, tray icons)", "advanced"),
                questionary.Choice("Exit", "exit"),
            ],
        ).ask()

        if action in (None, "exit"):
            print("\nGoodbye!")
            return
        if action == "hide":
            flow_hide(state)
        elif action == "restore":
            flow_restore(state)
        elif action == "verify":
            verify(state)
        elif action == "advanced":
            flow_advanced(state)
        print()


if __name__ == "__main__":
    main()
