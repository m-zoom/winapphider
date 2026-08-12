# WinAppHider

Hide and unhide Windows applications from the **taskbar**, **system tray** (notification area overflow), and **Settings > Apps & Features** uninstall list — without uninstalling them.

## What it does

- Lists all installed applications (from registry)
- Lists all running windows visible in the taskbar
- Lists system tray icons (notification area + overflow)
- Interactive multi-select UI (arrow keys + spacebar)
- Hides selected items so they disappear from Windows UI
- Run again to unhide/restore previously hidden apps

## One-liner (PowerShell as Administrator)

Copy and paste this into an **Administrator PowerShell** window:

```powershell
powershell -NoProfile -Command "& { if (!(Get-Command uv -ErrorAction SilentlyContinue)) { irm https://astral.sh/uv/install.ps1 | iex }; $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User'); uv run --with questionary https://raw.githubusercontent.com/nick-fields/winapphider/main/hide_apps.py }"
```

> **Note:** Replace `nick-fields/winapphider` with the actual repo name once created.

## Manual install

```powershell
# 1. Install UV (if you don't have it)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# 2. Clone the repo
git clone https://github.com/YOUR_USERNAME/winapphider.git
cd winapphider

# 3. Run
uv run --with questionary hide_apps.py
```

## How it works

| Hide from | Technique |
|-----------|-----------|
| **Uninstall list** (Settings > Apps) | Sets `SystemComponent=1` in the app's registry key under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` |
| **Taskbar** | Adds `WS_EX_TOOLWINDOW` to the window's extended style via `SetWindowLongW` |
| **System tray** | Sends `TB_HIDEBUTTON` message to the notification area toolbar |

All changes are trackable and reversible. State is saved to `.app_hider_state.json`.

## Requirements

- Windows 10 or 11
- Administrator privileges (required for registry changes)
- (UV will handle Python + packages automatically)

## License

MIT
