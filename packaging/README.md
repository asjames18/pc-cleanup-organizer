# PC Cleanup & Organizer for Windows

Find what's filling your PC, clean safe junk, organize folders (with undo), review startup apps and installed programs. Scans are read-only; nothing is deleted or moved until you confirm it.

## Install (about 1 minute)

1. Open the downloaded `PCCleanup-Setup-<version>.zip` and double-click **`Install-PCCleanup.cmd`**. (Extracting first with right-click, **Extract All...** also works. Run straight from the zip, it finds the download in Downloads, Desktop or Documents and unpacks it for you.)
   - Windows may say *"Windows protected your PC"* (SmartScreen) or *"unknown publisher"*, because the installer isn't code-signed. Click **More info**, then **Run anyway**.
2. The app only needs **Python 3.10 or newer** (it uses the standard library, no extra packages). If Python is missing, the installer asks *"Python is needed, install it now? [Y/n]"*, downloads the official **Python 3.13.17** from python.org (about 29 MB), checks its SHA-256 checksum and Python Software Foundation signature, and installs it for your Windows account only (no admin needed).
3. It copies the app to `%LOCALAPPDATA%\PCCleanup\app`, keeps your settings, logs, undo history and registry backups in `%LOCALAPPDATA%\PCCleanup\data`, adds **Desktop** and **Start menu** shortcuts (**Ctrl+Alt+C**, skipped if another shortcut uses it) and opens the app.

Running it again is safe (upgrade or repair, your data is kept). Offline or a failed download: it says so and stops without changing anything.

Requirements: Windows 10 or 11 (64-bit), about 50 MB of disk. Optional: **winget** (App Installer from the Microsoft Store, built into Windows 11) for the app-updates list; NVIDIA drivers for GPU figures on the Monitor view. Some actions (like uninstalling programs installed for all users) show Windows' own admin prompt.

## Uninstall

Double-click **`Uninstall-PCCleanup.cmd`**, or **Start menu > Uninstall PC Cleanup & Organizer**. Your settings and logs are kept unless you choose to delete them. Python stays installed.
