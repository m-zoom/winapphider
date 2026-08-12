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
    return {"hidden_registry": {}, "hidden_taskbar": {}}


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

    # Force taskbar refresh: briefly hide then show
    if toolwindow:
        user32.ShowWindow(hwnd, SW_HIDE)
        time.sleep(0.05)
        user32.ShowWindow(hwnd, SW_SHOW)
    else:
        user32.ShowWindow(hwnd, SW_MINIMIZE)
        time.sleep(0.05)
        user32.ShowWindow(hwnd, SW_RESTORE)

    return True

# ---------------------------------------------------------------------------
# System Tray - Notification area icons
# ---------------------------------------------------------------------------
def get_tray_icons():
    """Enumerate notification area & overflow toolbar icons."""
    user32 = ctypes.windll.user32
    icons = []

    # Helper: enumerate a toolbar's buttons
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

                # Get button info to retrieve command ID
                bi = TBBUTTONINFOW()
                bi.cbSize = sizeof(TBBUTTONINFOW)
                bi.dwMask = TBIF_COMMAND
                bi.idCommand = tb_btn.idCommand
                bi.pszText = None
                bi.cchText = 0
                _ = user32.SendMessageW(tb_hwnd, TB_GETBUTTONINFOW,
                                        tb_btn.idCommand, byref(bi))

                # Get the owning window via NIS_HIDDEN message
                # Try to get window handle from the notification icon data
                try:
                    tb_data = TBBUTTONINFOW()
                    tb_data.cbSize = sizeof(TBBUTTONINFOW)
                    tb_data.dwMask = TBIF_BYINDEX | 0x00000001  # TBIF_IMAGE | TBIF_STATE
                    user32.SendMessageW(tb_hwnd, TB_GETBUTTONINFOW, i, byref(tb_data))
                except Exception:
                    pass

                icons.append({
                    "id_command": tb_btn.idCommand,
                    "index": i,
                    "toolbar_hwnd": tb_hwnd,
                    "label": label,
                    "process_name": f"TrayIcon#{tb_btn.idCommand}",
                    "title": f"[{label}] Icon #{tb_btn.idCommand}",
                })
            except Exception:
                continue

    # Main notification area
    taskbar = user32.FindWindowW("Shell_TrayWnd", None)
    if taskbar:
        tray_notify = user32.FindWindowExW(taskbar, 0, "TrayNotifyWnd", None)
        if tray_notify:
            sys_pager = user32.FindWindowExW(tray_notify, 0, "SysPager", None)
            if sys_pager:
                tb_main = user32.FindWindowExW(sys_pager, 0, "ToolbarWindow32", None)
                enum_toolbar(tb_main, "Tray")

    # Overflow (hidden icons popup)
    overflow = user32.FindWindowW("NotifyIconOverflowWindow", None)
    if overflow:
        tb_overflow = user32.FindWindowExW(overflow, 0, "ToolbarWindow32", None)
        enum_toolbar(tb_overflow, "Overflow")

    return icons


def hide_tray_icon(icon, hide: bool):
    """Hide or show a toolbar button in the notification area."""
    user32 = ctypes.windll.user32
    if hide:
        user32.SendMessageW(icon["toolbar_hwnd"], TB_HIDEBUTTON, icon["id_command"], 1)  # TRUE
        print(f"  [HIDDEN]  Tray icon #{icon['id_command']} from {icon['label']}")
    else:
        user32.SendMessageW(icon["toolbar_hwnd"], TB_HIDEBUTTON, icon["id_command"], 0)  # FALSE
        print(f"  [SHOWN]   Tray icon #{icon['id_command']} from {icon['label']}")

# ---------------------------------------------------------------------------
# Build display labels
# ---------------------------------------------------------------------------
def build_choices(apps, windows, tray_icons, state):
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

    return choices


def build_unhide_choices(state):
    """Build choices for unhiding previously hidden items."""
    choices = []

    hidden_registry = state.get("hidden_registry", {})
    hidden_taskbar = state.get("hidden_taskbar", {})

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

    return choices

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 65)
    print("  Windows App Hider")
    print("  Hide apps from taskbar, system tray & uninstall list")
    print("=" * 65)

    # 1. Admin check
    if not is_admin():
        print("\n[!] Administrator privileges required for registry changes.")
        print("[*] Re-launching as Administrator...")
        run_as_admin()

    # 2. Load state
    state = load_state()

    # 3. Import questionary
    try:
        import questionary
    except ImportError:
        print("\n[X] 'questionary' package is required.")
        print("    Install it with: pip install questionary")
        print("    Or use: uv run --with questionary hide_apps.py")
        input("\nPress Enter to exit...")
        sys.exit(1)

    # 4. Scan system
    print("\n[*] Scanning installed applications...")
    apps = get_installed_apps()
    print(f"    Found {len(apps)} installed apps")

    print("[*] Scanning running windows...")
    windows = get_running_windows()
    print(f"    Found {len(windows)} visible windows")

    print("[*] Scanning system tray icons...")
    tray_icons = get_tray_icons()
    print(f"    Found {len(tray_icons)} tray icons")

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
        choices = build_choices(apps, windows, tray_icons, state)
        if not choices:
            print("\n[*] Nothing to hide. Exiting.")
            return

        selected = questionary.checkbox(
            "Select items to HIDE (SPACE to select, ENTER to confirm):",
            choices=choices,
            instruction="(Use arrow keys to move, SPACE to select/deselect, ENTER to confirm)",
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

        save_state(state)
        print(f"\n[√] Done! State saved to {STATE_FILE}")

    elif action == "unhide":
        unhide_choices = build_unhide_choices(state)
        if not unhide_choices:
            print("\n[*] No previously hidden items found.")
            return

        selected = questionary.checkbox(
            "Select items to UNHIDE / RESTORE:",
            choices=unhide_choices,
            instruction="(Use arrow keys to move, SPACE to select, ENTER to confirm)",
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

        save_state(state)
        print(f"\n[√] Done! State saved to {STATE_FILE}")

    print()


if __name__ == "__main__":
    main()
