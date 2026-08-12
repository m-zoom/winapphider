"""
Windows App Hider - Hide and unhide applications from taskbar,
system tray, and Windows uninstall list (Apps & Features).

Run as Administrator. Requires Python 3.8+.
"""

import ctypes
from ctypes import wintypes, byref, sizeof, create_unicode_buffer
import winreg
import json
import os
import sys
import time

import questionary

# ---------------------------------------------------------------------------
# Windows API constants
# ---------------------------------------------------------------------------
GWL_EXSTYLE = -20
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_APPWINDOW = 0x00040000
SW_HIDE = 0
SW_SHOW = 5
SW_MINIMIZE = 6
SW_RESTORE = 9

# SetWindowPos flags
SWP_FRAMECHANGED = 0x0020
SWP_NOMOVE = 0x0002
SWP_NOSIZE = 0x0001
SWP_NOZORDER = 0x0004
SWP_NOACTIVATE = 0x0010
SWP_HIDEWINDOW = 0x0080
SWP_SHOWWINDOW = 0x0040

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# Toolbar messages
TB_BUTTONCOUNT = 0x0400 + 24
TB_GETBUTTON = 0x0400 + 23
TB_HIDEBUTTON = 0x0400 + 4
TB_GETBUTTONINFOW = 0x0400 + 63

TBIF_BYINDEX = 0x80000000
TBIF_COMMAND = 0x00000020

# Registry paths
UNINSTALL_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]

def _get_script_dir():
    """Get script directory - handles uv run, direct python, and frozen exe."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except NameError:
        return os.path.dirname(os.path.abspath(sys.argv[0]))

STATE_FILE = os.path.join(_get_script_dir(), ".app_hider_state.json")

# ---------------------------------------------------------------------------
# Win32 structures
# ---------------------------------------------------------------------------
class TBBUTTON(ctypes.Structure):
    _fields_ = [
        ("iBitmap", ctypes.c_int),
        ("idCommand", ctypes.c_int),
        ("fsState", ctypes.c_byte),
        ("fsStyle", ctypes.c_byte),
        ("bReserved", ctypes.c_byte * 6),
        ("dwData", ctypes.c_ulong),
        ("iString", ctypes.c_int),
    ]

class TBBUTTONINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint),
        ("dwMask", ctypes.c_uint),
        ("idCommand", ctypes.c_int),
        ("iImage", ctypes.c_int),
        ("fsState", ctypes.c_byte),
        ("fsStyle", ctypes.c_byte),
        ("cx", ctypes.c_ushort),
        ("lParam", ctypes.c_ulong),
        ("pszText", ctypes.c_wchar_p),
        ("cchText", ctypes.c_int),
    ]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def run_as_admin():
    """Re-launch the script with Administrator privileges."""
    if not is_admin():
        print("[!] Not running as Administrator. Requesting elevation...")
        script = os.path.abspath(sys.argv[0])
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        if ret <= 32:
            print(f"[X] Failed to elevate. Error code: {ret}")
            input("Press Enter to exit...")
            sys.exit(1)
        sys.exit(0)

# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------
def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {"hidden_registry": {}, "hidden_taskbar": {}, "hidden_start_menu": {}}


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)

# ---------------------------------------------------------------------------
# Registry - Installed applications
# ---------------------------------------------------------------------------
def get_installed_apps():
    """Return list of installed programs from registry uninstall keys."""
    apps = []
    seen = set()

    for hive, path in UNINSTALL_PATHS:
        try:
            key = winreg.OpenKey(hive, path)
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    try:
                        display_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                        display_name = display_name.strip()
                        if display_name and display_name.lower() not in seen:
                            seen.add(display_name.lower())
                            system_component = 0
                            try:
                                system_component, _ = winreg.QueryValueEx(subkey, "SystemComponent")
                            except OSError:
                                pass

                            apps.append({
                                "name": display_name,
                                "reg_key": subkey_name,
                                "reg_path": f"{path}\\{subkey_name}",
                                "hive": hive,
                                "is_hidden": system_component == 1,
                            })
                    except OSError:
                        pass
                    finally:
                        subkey.Close()
                except OSError:
                    pass
            key.Close()
        except OSError:
            pass

    apps.sort(key=lambda a: a["name"].lower())
    return apps


def toggle_registry_app(app_info, hide: bool):
    """Set or remove SystemComponent DWORD for an installed app."""
    hive_name = {
        winreg.HKEY_LOCAL_MACHINE: "HKLM",
        winreg.HKEY_CURRENT_USER: "HKCU",
    }
    full_path = f"{hive_name.get(app_info['hive'], 'UNKNOWN')}\\{app_info['reg_path']}"

    try:
        key = winreg.OpenKey(app_info["hive"], app_info["reg_path"], 0, winreg.KEY_SET_VALUE)
        if hide:
            winreg.SetValueEx(key, "SystemComponent", 0, winreg.REG_DWORD, 1)
            print(f"  [HIDDEN]  {app_info['name']}  ->  {full_path}")
        else:
            try:
                winreg.DeleteValue(key, "SystemComponent")
            except OSError:
                pass
            print(f"  [SHOWN]   {app_info['name']}  ->  {full_path}")
        key.Close()
        return True
    except OSError as e:
        print(f"  [FAIL]    {app_info['name']}: {e}")
        return False

# ---------------------------------------------------------------------------
# Windows - Running taskbar windows
# ---------------------------------------------------------------------------
def get_process_name(pid):
    kernel32 = ctypes.windll.kernel32
    try:
        handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not handle:
            return f"<PID:{pid}>"
        buf = create_unicode_buffer(260)
        size = wintypes.DWORD(260)
        kernel32.QueryFullProcessImageNameW(handle, 0, buf, byref(size))
        kernel32.CloseHandle(handle)
        name = os.path.basename(buf.value)
        return name if name else f"<PID:{pid}>"
    except Exception:
        return f"<PID:{pid}>"


def get_running_windows():
    """Return list of visible windows that appear in the taskbar."""
    user32 = ctypes.windll.user32
    windows = []

    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def enum_proc(hwnd, lParam):
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return True
            title_buf = create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, title_buf, length + 1)
            title = title_buf.value.strip()
            if not title:
                return True

            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, byref(pid))
            proc_name = get_process_name(pid.value)
            ex_style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            is_toolwindow = bool(ex_style & WS_EX_TOOLWINDOW)

            windows.append({
                "hwnd": hwnd,
                "title": title,
                "pid": pid.value,
                "process_name": proc_name,
                "is_toolwindow": is_toolwindow,
                "ex_style": ex_style,
            })
        return True

    user32.EnumWindows(WNDENUMPROC(enum_proc), 0)
    windows.sort(key=lambda w: (w["process_name"].lower(), w["title"].lower()))
    return windows


def set_window_toolwindow(hwnd, toolwindow: bool):
    """Add or remove WS_EX_TOOLWINDOW from a window."""
    user32 = ctypes.windll.user32
    ex_style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
    if toolwindow:
        new_style = ex_style | WS_EX_TOOLWINDOW
        # Remove WS_EX_APPWINDOW so taskbar button is properly removed
        new_style = new_style & ~WS_EX_APPWINDOW
    else:
        new_style = ex_style & ~WS_EX_TOOLWINDOW
        new_style = new_style | WS_EX_APPWINDOW

    user32.SetWindowLongW(hwnd, GWL_EXSTYLE, new_style)

    # Force Windows to re-evaluate the window's frame styles.
    # SetWindowPos with SWP_FRAMECHANGED is critical on Win10/11 —
    # ShowWindow alone is NOT enough to remove the taskbar button.
    flags = SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE
    if toolwindow:
        user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, flags | SWP_HIDEWINDOW)
        time.sleep(0.05)
        user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, flags | SWP_SHOWWINDOW)
    else:
        user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, flags | SWP_HIDEWINDOW)
        time.sleep(0.05)
        user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, flags | SWP_SHOWWINDOW)

    return True

# ---------------------------------------------------------------------------
# System Tray - Notification area icons
# ---------------------------------------------------------------------------

# NOTIFYICONDATA for Shell_NotifyIcon
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002
NIF_STATE = 0x00000008
NIS_HIDDEN = 0x00000001

class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", ctypes.c_uint),
        ("uFlags", ctypes.c_uint),
        ("uCallbackMessage", ctypes.c_uint),
        ("hIcon", wintypes.HICON),
        ("szTip", ctypes.c_wchar * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", ctypes.c_wchar * 256),
        ("uTimeoutOrVersion", ctypes.c_uint),
        ("szInfoTitle", ctypes.c_wchar * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", ctypes.c_char * 16),
        ("hBalloonIcon", wintypes.HICON),
    ]


def _find_tray_toolbar(hwnd_parent, *child_classes):
    """Walk the window hierarchy to find a ToolbarWindow32 child."""
    user32 = ctypes.windll.user32
    current = hwnd_parent
    for cls_name in child_classes:
        current = user32.FindWindowExW(current, 0, cls_name, None)
        if not current:
            return None
    return current


def get_tray_icons():
    """Enumerate notification area & overflow toolbar icons (Win10/Win11)."""
    user32 = ctypes.windll.user32
    icons = []

    def enum_toolbar(tb_hwnd, label):
        if not tb_hwnd:
            return
        count = user32.SendMessageW(tb_hwnd, TB_BUTTONCOUNT, 0, 0)
        if count <= 0 or count > 200:
            return
        for i in range(count):
            try:
                tb_btn = TBBUTTON()
                result = user32.SendMessageW(tb_hwnd, TB_GETBUTTON, i, byref(tb_btn))
                if not result:
                    continue

                # Try to get the notification icon's owner window
                owner_hwnd = _get_tray_owner_hwnd(tb_hwnd, tb_btn)
                proc_name = "Unknown"
                pid = 0
                if owner_hwnd:
                    pid_val = wintypes.DWORD()
                    user32.GetWindowThreadProcessId(owner_hwnd, byref(pid_val))
                    pid = pid_val.value
                    proc_name = get_process_name(pid) if pid else f"TrayIcon#{tb_btn.idCommand}"

                if proc_name == "Unknown" or proc_name.startswith("TrayIcon#"):
                    proc_name = f"TrayIcon#{tb_btn.idCommand}"

                icons.append({
                    "id_command": tb_btn.idCommand,
                    "index": i,
                    "toolbar_hwnd": tb_hwnd,
                    "label": label,
                    "owner_hwnd": owner_hwnd,
                    "pid": pid,
                    "process_name": proc_name,
                    "title": f"[{label}] {proc_name} (cmd#{tb_btn.idCommand})",
                })
            except Exception:
                continue

    # --- Main notification area (Win10 classic & Win11 hidden mirror) ---
    taskbar = user32.FindWindowW("Shell_TrayWnd", None)
    if taskbar:
        tb_main = _find_tray_toolbar(taskbar, "TrayNotifyWnd", "SysPager", "ToolbarWindow32")
        enum_toolbar(tb_main, "Tray")

    # --- Overflow (hidden icons popup) ---
    overflow = user32.FindWindowW("NotifyIconOverflowWindow", None)
    if overflow:
        tb_overflow = user32.FindWindowExW(overflow, 0, "ToolbarWindow32", None)
        enum_toolbar(tb_overflow, "Overflow")

    # --- Win11 secondary tray ---
    secondary = user32.FindWindowW("Shell_SecondaryTrayWnd", None)
    if secondary:
        tb_sec = _find_tray_toolbar(secondary, "TrayNotifyWnd", "SysPager", "ToolbarWindow32")
        enum_toolbar(tb_sec, "Tray")

    return icons


def _get_tray_owner_hwnd(tb_hwnd, tb_btn):
    """Try to get the owner window HWND from a tray toolbar button's dwData."""
    user32 = ctypes.windll.user32
    try:
        # dwData in a tray toolbar button sometimes points to NOTIFYICONDATA,
        # whose first DWORD field (after cbSize, hWnd) can help.
        # Another common pattern: dwData IS the hWnd of the owner.
        if tb_btn.dwData:
            candidate = wintypes.HWND(tb_btn.dwData)
            # Verify it looks like a valid window
            if user32.IsWindow(candidate):
                return candidate
    except Exception:
        pass
    return None


def hide_tray_icon(icon, hide: bool):
    """Hide or show a notification-area toolbar button.

    Uses two strategies:
      1) TB_HIDEBUTTON — classic toolbar message
      2) Shell_NotifyIcon(NIM_MODIFY, NIS_HIDDEN) — deeper, via the icon owner
    """
    user32 = ctypes.windll.user32
    shell32 = ctypes.windll.shell32

    if hide:
        # Strategy 1: toolbar button
        user32.SendMessageW(icon["toolbar_hwnd"], TB_HIDEBUTTON, icon["id_command"], 1)

        # Strategy 2: NIM_MODIFY with NIS_HIDDEN if we know the owner window
        if icon.get("owner_hwnd"):
            nid = NOTIFYICONDATAW()
            nid.cbSize = sizeof(NOTIFYICONDATAW)
            nid.hWnd = icon["owner_hwnd"]
            nid.uID = icon["id_command"]
            nid.uFlags = NIF_STATE
            nid.dwState = NIS_HIDDEN
            nid.dwStateMask = NIS_HIDDEN
            shell32.Shell_NotifyIconW(NIM_MODIFY, byref(nid))

        print(f"  [HIDDEN]  Tray icon {icon.get('process_name', icon['title'])} from {icon['label']}")
    else:
        user32.SendMessageW(icon["toolbar_hwnd"], TB_HIDEBUTTON, icon["id_command"], 0)

        if icon.get("owner_hwnd"):
            nid = NOTIFYICONDATAW()
            nid.cbSize = sizeof(NOTIFYICONDATAW)
            nid.hWnd = icon["owner_hwnd"]
            nid.uID = icon["id_command"]
            nid.uFlags = NIF_STATE
            nid.dwState = 0
            nid.dwStateMask = NIS_HIDDEN
            shell32.Shell_NotifyIconW(NIM_MODIFY, byref(nid))

        print(f"  [SHOWN]   Tray icon {icon.get('process_name', icon['title'])} from {icon['label']}")

# ---------------------------------------------------------------------------
# Start Menu - Hide from Windows Search results
# ---------------------------------------------------------------------------

def _get_start_menu_dirs():
    """Return the two main Start Menu Programs directories."""
    dirs = []
    all_users = os.path.join(
        os.environ.get("ALLUSERSPROFILE", "C:\\ProgramData"),
        "Microsoft\\Windows\\Start Menu\\Programs",
    )
    current_user = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft\\Windows\\Start Menu\\Programs",
    )
    if os.path.isdir(all_users):
        dirs.append(all_users)
    if os.path.isdir(current_user):
        dirs.append(current_user)
    return dirs


def _resolve_shortcut_target(lnk_path):
    """Resolve a .lnk shortcut to its target path using PowerShell COM."""
    import subprocess
    try:
        escaped = lnk_path.replace("'", "''")
        cmd = (
            f"(New-Object -ComObject WScript.Shell)"
            f".CreateShortcut('{escaped}').TargetPath"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=8,
        )
        target = result.stdout.strip()
        return target if target else None
    except Exception:
        return None


def get_start_menu_shortcuts(apps):
    """Find Start Menu shortcuts linked to any of the given installed apps."""
    shortcuts = []
    if not apps:
        return shortcuts

    # Build a set of executable basenames to match against
    app_names_lower = set()
    for a in apps:
        name = a["name"].lower()
        app_names_lower.add(name)
        # Also add individual words from the name for broader matching
        for word in name.split():
            if len(word) > 2:
                app_names_lower.add(word)

    seen_paths = set()
    for base_dir in _get_start_menu_dirs():
        for root, dirs, files in os.walk(base_dir):
            for f in files:
                if not f.lower().endswith(".lnk"):
                    continue
                full_path = os.path.join(root, f)
                if full_path in seen_paths:
                    continue
                seen_paths.add(full_path)

                shortcut_name = f[:-4]  # without .lnk
                target = _resolve_shortcut_target(full_path)
                if not target:
                    continue

                target_basename = os.path.splitext(os.path.basename(target))[0].lower()
                target_dir = os.path.dirname(target).lower()

                # Match: shortcut name or target contains an app name/word
                matched_app = None
                name_lower = shortcut_name.lower()
                for a in apps:
                    app_name_lower = a["name"].lower()
                    if app_name_lower in name_lower or app_name_lower in target_dir or app_name_lower in target_basename:
                        matched_app = a
                        break
                    # Also try word-level matching
                    for word in app_name_lower.split():
                        if len(word) > 3 and (word in name_lower or word in target_basename):
                            matched_app = a
                            break
                    if matched_app:
                        break

                if matched_app:
                    shortcuts.append({
                        "path": full_path,
                        "name": shortcut_name,
                        "target": target,
                        "app_name": matched_app["name"],
                        "app_reg_path": matched_app["reg_path"],
                    })

    # Deduplicate by path
    unique = {}
    for s in shortcuts:
        unique[s["path"]] = s
    return list(unique.values())


def toggle_start_menu_shortcut(shortcut_info, hide: bool):
    """Hide a Start Menu shortcut by renaming .lnk -> .lnk.hidden, or restore it."""
    src = shortcut_info["path"]
    if hide:
        dst = src + ".hidden"
        if os.path.exists(src):
            os.rename(src, dst)
            print(f"  [HIDDEN]  Start Menu: {shortcut_info['name']}")
        else:
            print(f"  [SKIP]    Start Menu: {shortcut_info['name']} (already hidden)")
        return dst
    else:
        if src.endswith(".hidden"):
            dst = src[:-7]  # remove .hidden
        else:
            dst = src + ".hidden"  # src is the .lnk, try the .hidden path
            src, dst = dst, src
        if os.path.exists(src):
            os.rename(src, dst)
            print(f"  [SHOWN]   Start Menu: {shortcut_info['name']}")
        else:
            print(f"  [SKIP]    Start Menu: {shortcut_info['name']} (not hidden)")
        return dst

# ---------------------------------------------------------------------------
# Build display labels
# ---------------------------------------------------------------------------
def build_choices(apps, windows, tray_icons, start_menu, state):
    """Build choice items for questionary.checkbox."""
    choices = []

    hidden_registry = set(state.get("hidden_registry", {}).keys())

    # --- INSTALLED APPS (uninstall list) ---
    if apps:
        choices.append(questionary.Separator("─ INSTALLED APPS (hide from Settings > Apps & Features) ─"))
        for a in apps:
            is_hidden = a["is_hidden"] or a["reg_path"] in hidden_registry
            prefix = "[HIDDEN] " if is_hidden else "[visible] "
            label = f"{prefix}{a['name']}"
            choices.append(questionary.Choice(
                title=label,
                value={"type": "installed_app", "data": a, "action": "show" if is_hidden else "hide"},
            ))

    # --- RUNNING WINDOWS (taskbar) ---
    if windows:
        choices.append(questionary.Separator("─ RUNNING WINDOWS (hide from taskbar) ─"))
        for w in windows:
            is_hidden = w["is_toolwindow"]
            prefix = "[HIDDEN] " if is_hidden else "[visible] "
            label = f"{prefix}{w['process_name']} - {w['title'][:60]}"
            if len(w["title"]) > 60:
                label += "..."
            choices.append(questionary.Choice(
                title=label,
                value={"type": "running_window", "data": w, "action": "show" if is_hidden else "hide"},
            ))

    # --- SYSTEM TRAY ICONS ---
    if tray_icons:
        choices.append(questionary.Separator("─ SYSTEM TRAY ICONS (notification area / overflow) ─"))
        for t in tray_icons:
            label = f"[visible] {t['title']}"
            choices.append(questionary.Choice(
                title=label,
                value={"type": "tray_icon", "data": t, "action": "hide"},
            ))

    # --- START MENU SHORTCUTS (hide from Windows Search) ---
    if start_menu:
        choices.append(questionary.Separator("─ START MENU SHORTCUTS (hide from Windows Search) ─"))
        existing_hidden = state.get("hidden_start_menu", {})
        for s in start_menu:
            is_hidden = s["path"] in existing_hidden
            prefix = "[HIDDEN] " if is_hidden else "[visible] "
            label = f"{prefix}{s['name']}  (-> {os.path.basename(s['target'])})"
            choices.append(questionary.Choice(
                title=label,
                value={"type": "start_menu", "data": s, "action": "show" if is_hidden else "hide"},
            ))

    return choices


def build_unhide_choices(state):
    """Build choices for unhiding previously hidden items."""
    choices = []

    hidden_registry = state.get("hidden_registry", {})
    hidden_taskbar = state.get("hidden_taskbar", {})
    hidden_start_menu = state.get("hidden_start_menu", {})

    if hidden_registry:
        choices.append(questionary.Separator("─ PREVIOUSLY HIDDEN APPS (unhide from Settings) ─"))
        for path, info in hidden_registry.items():
            label = f"{info.get('name', 'Unknown')}"
            choices.append(questionary.Choice(
                title=label,
                value={"type": "unhide_registry", "data": info, "reg_path": path},
            ))

    if hidden_taskbar:
        choices.append(questionary.Separator("─ PREVIOUSLY HIDDEN WINDOWS (unhide from taskbar) ─"))
        for key, info in hidden_taskbar.items():
            label = f"{info.get('process_name', 'Unknown')}"
            choices.append(questionary.Choice(
                title=label,
                value={"type": "unhide_taskbar", "data": info, "key": key},
            ))

    if hidden_start_menu:
        choices.append(questionary.Separator("─ PREVIOUSLY HIDDEN START MENU SHORTCUTS (restore to Search) ─"))
        for path, info in hidden_start_menu.items():
            label = f"{info.get('name', 'Unknown')}"
            choices.append(questionary.Choice(
                title=label,
                value={"type": "unhide_start_menu", "data": info, "path": path},
            ))

    return choices

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 65)
    print("  Windows App Hider")
    print("  Hide apps from taskbar, system tray, Search & uninstall list")
    print("=" * 65)

    # 1. Admin check
    if not is_admin():
        print("\n[!] Administrator privileges required for registry changes.")
        print("[*] Re-launching as Administrator...")
        run_as_admin()

    # 2. Load state
    state = load_state()

    # 3. Scan system
    print("\n[*] Scanning installed applications...")
    apps = get_installed_apps()
    print(f"    Found {len(apps)} installed apps")

    print("[*] Scanning running windows...")
    windows = get_running_windows()
    print(f"    Found {len(windows)} visible windows")

    print("[*] Scanning system tray icons...")
    tray_icons = get_tray_icons()
    print(f"    Found {len(tray_icons)} tray icons")

    print("[*] Scanning Start Menu shortcuts...")
    start_menu = get_start_menu_shortcuts(apps)
    print(f"    Found {len(start_menu)} matching Start Menu shortcuts")

    # 5. Main menu
    action = questionary.select(
        "What would you like to do?",
        choices=[
            questionary.Choice(
                title="Hide applications (show me all apps, I'll select which to hide)",
                value="hide",
            ),
            questionary.Choice(
                title="Unhide / Restore previously hidden applications",
                value="unhide",
            ),
            questionary.Choice(
                title="Exit",
                value="exit",
            ),
        ],
    ).ask()

    if action == "exit" or action is None:
        print("\nGoodbye!")
        return

    if action == "hide":
        choices = build_choices(apps, windows, tray_icons, start_menu, state)
        if not choices:
            print("\n[*] Nothing to hide. Exiting.")
            return

        print("\n" + "=" * 65)
        print("  HOW TO SELECT: Use ARROW KEYS to move, SPACE to check/uncheck,")
        print("  then press ENTER when you're done selecting.")
        print("=" * 65)

        selected = questionary.checkbox(
            "Select items to HIDE:",
            choices=choices,
            instruction="(ARROW keys = move | SPACE = select | ENTER = confirm)",
        ).ask()

        if not selected:
            print("\n[*] Nothing selected. Exiting.")
            return

        print(f"\n[*] Processing {len(selected)} item(s)...\n")

        for item in selected:
            typ = item["type"]
            data = item["data"]
            act = item["action"]

            if typ == "installed_app":
                should_hide = act == "hide"
                success = toggle_registry_app(data, should_hide)
                if success and should_hide:
                    state["hidden_registry"][data["reg_path"]] = {
                        "name": data["name"],
                        "hive": data["hive"],
                        "reg_path": data["reg_path"],
                        "reg_key": data["reg_key"],
                        "date_hidden": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                elif success and not should_hide:
                    if data["reg_path"] in state["hidden_registry"]:
                        del state["hidden_registry"][data["reg_path"]]

            elif typ == "running_window":
                should_hide = act == "hide"
                set_window_toolwindow(data["hwnd"], should_hide)
                key = f"{data['process_name']}||{data['title']}"
                if should_hide:
                    data_copy = {k: v for k, v in data.items() if k != "hwnd"}
                    state["hidden_taskbar"][key] = {
                        "process_name": data["process_name"],
                        "title": data["title"],
                        "pid": data["pid"],
                        "original_ex_style": data["ex_style"],
                        "date_hidden": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    print(f"  [HIDDEN]  {data['process_name']} - {data['title'][:50]}")
                else:
                    if key in state["hidden_taskbar"]:
                        del state["hidden_taskbar"][key]
                    print(f"  [SHOWN]   {data['process_name']} - {data['title'][:50]}")

            elif typ == "tray_icon":
                hide_tray_icon(data, True)

            elif typ == "start_menu":
                should_hide = act == "hide"
                if should_hide:
                    dst = toggle_start_menu_shortcut(data, True)
                    state["hidden_start_menu"][data["path"]] = {
                        "name": data["name"],
                        "target": data["target"],
                        "app_name": data["app_name"],
                        "hidden_path": dst,
                        "original_path": data["path"],
                        "date_hidden": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                else:
                    toggle_start_menu_shortcut(data, False)
                    if data["path"] in state["hidden_start_menu"]:
                        del state["hidden_start_menu"][data["path"]]

        save_state(state)
        print(f"\n[√] Done! State saved to {STATE_FILE}")

    elif action == "unhide":
        unhide_choices = build_unhide_choices(state)
        if not unhide_choices:
            print("\n[*] No previously hidden items found.")
            return

        print("\n" + "=" * 65)
        print("  HOW TO SELECT: Use ARROW KEYS to move, SPACE to check/uncheck,")
        print("  then press ENTER when you're done selecting.")
        print("=" * 65)

        selected = questionary.checkbox(
            "Select items to UNHIDE / RESTORE:",
            choices=unhide_choices,
            instruction="(ARROW keys = move | SPACE = select | ENTER = confirm)",
        ).ask()

        if not selected:
            print("\n[*] Nothing selected. Exiting.")
            return

        print(f"\n[*] Restoring {len(selected)} item(s)...\n")

        for item in selected:
            typ = item["type"]

            if typ == "unhide_registry":
                info = item["data"]
                reg_path = item["reg_path"]
                hive = info["hive"]
                # Re-open registry key and remove SystemComponent
                try:
                    key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_SET_VALUE)
                    try:
                        winreg.DeleteValue(key, "SystemComponent")
                    except OSError:
                        pass
                    key.Close()
                    print(f"  [RESTORED] {info['name']}")
                except OSError as e:
                    print(f"  [FAIL]     {info['name']}: {e}")

                if reg_path in state["hidden_registry"]:
                    del state["hidden_registry"][reg_path]

            elif typ == "unhide_taskbar":
                info = item["data"]
                key_id = item["key"]
                process_name = info["process_name"]
                # Try to find the window by process name and remove WS_EX_TOOLWINDOW
                user32 = ctypes.windll.user32
                found_windows = []

                def find_window(hwnd, lParam):
                    pid = wintypes.DWORD()
                    user32.GetWindowThreadProcessId(hwnd, byref(pid))
                    if get_process_name(pid.value) == process_name:
                        length = user32.GetWindowTextLengthW(hwnd)
                        if length > 0:
                            title_buf = create_unicode_buffer(length + 1)
                            user32.GetWindowTextW(hwnd, title_buf, length + 1)
                            if title_buf.value.strip():
                                found_windows.append(hwnd)
                    return True

                WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
                user32.EnumWindows(WNDENUMPROC(find_window), 0)

                if found_windows:
                    for hwnd in found_windows:
                        set_window_toolwindow(hwnd, False)
                    print(f"  [RESTORED] {process_name} ({len(found_windows)} window(s))")
                else:
                    print(f"  [SKIP]     {process_name} - process not running")

                if key_id in state["hidden_taskbar"]:
                    del state["hidden_taskbar"][key_id]

            elif typ == "unhide_start_menu":
                info = item["data"]
                path = item["path"]
                # Try both the original .lnk path and the .lnk.hidden path
                hidden_path = info.get("hidden_path", path)
                if os.path.exists(hidden_path):
                    toggle_start_menu_shortcut({"path": hidden_path, "name": info.get("name", "Unknown")}, False)
                    print(f"  [RESTORED] Start Menu: {info.get('name', 'Unknown')}")
                else:
                    # Maybe it was already restored manually
                    print(f"  [SKIP]     Start Menu: {info.get('name', 'Unknown')} (already restored)")
                if path in state["hidden_start_menu"]:
                    del state["hidden_start_menu"][path]

        save_state(state)
        print(f"\n[√] Done! State saved to {STATE_FILE}")

    print()


if __name__ == "__main__":
    main()
