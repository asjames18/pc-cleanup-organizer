# PC Cleanup & Organizer

A local Windows app for cleanup, organization, protection, startup, uninstall, and system monitoring.

![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)
![Python](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-3.1.0-informational)
![Dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-lightgrey)
![Status](https://img.shields.io/badge/status-public-2ea44f)

## Download and install

Most people should grab the ready-made installer, not this source. It sets up everything the app needs:

1. Download **`PCCleanup-Setup-<version>.zip`** from the latest release on this repository's Releases page.
2. Open the zip and double-click **`Install-PCCleanup.cmd`** (it unpacks itself if you run it from inside the zip). Windows SmartScreen may warn because the installer isn't code-signed: click **More info**, then **Run anyway**.
3. It installs, asking before anything is downloaded:
   - Python 3.10+ only (standard library, no pip packages). If it's missing, the installer asks, then installs the official python.org Python 3.13.17 for your account (SHA-256 and signature checked, no admin).
   - About 1 MB on disk; under a minute (plus about a minute if Python has to be installed).
   - winget (App Installer) is optional; the installer tells you if it's missing.
4. It adds Desktop and Start menu shortcuts and opens the app. Code goes to `%LOCALAPPDATA%\PCCleanup\app`, your data to `%LOCALAPPDATA%\PCCleanup\data`. Running it again is safe (repair or upgrade, data kept); offline or a failed download stops safely. Uninstall from the Start menu or with `Uninstall-*.cmd`.

The end-user guide is [`packaging/README.md`](packaging/README.md) (it ships inside the zip). `python packaging/build_dist.py . dist` builds the zip and its `.sha256` and refuses to build if it finds keys or personal strings.

## Overview

PC Cleanup & Organizer (v3) runs a private HTTP server on `127.0.0.1` (default port `48251`) and opens in its own Microsoft Edge window. It uses the Python standard library only; no pip packages are required.

Scans are read-only. Nothing is deleted or moved until you confirm the action in the app.

## Key Features

- **Dashboard / Smart Scan** — A read-only overview of disk space, cleanup categories, downloads, startup items, protection status, and health information, with a health score and optional recommendations.
- **Scan & disk map** — Walk a folder (read-only) to see a disk map, largest files, duplicate groups (hashed above a size threshold), and old files in Downloads.
- **Cleanup** — Measure and, after confirmation, remove selected temp and cache categories (user TEMP, browser caches, crash dumps, optional shader/thumbnail/log/developer caches). Browser cleanup touches cache folders only. Some Windows Update and NVIDIA installer locations are measured for review but are never cleaned by this app.
- **Organize** — Preview, then move top-level files in a folder into subfolders by type or by date (`YYYY\MM`). Shortcuts can be skipped. Undo puts every moved file back.
- **Applications** — Installed programs, Microsoft Store apps, uninstall with leftover-folder review, an orphan-folder scan (review-only), and optional upgrades through winget.
- **Protection** — A read-only check of Microsoft Defender / Security Center status, browser extensions, home pages and search settings, the hosts file, proxy settings, and notable startup or scheduled-task items. You can start a Defender Quick Scan from the app.
- **Startup** — Review and toggle startup items (and, where allowed, scheduled tasks). Items can be switched back on; nothing is deleted here.
- **Monitor** — Live CPU, memory, disk, network, and (when NVIDIA tools are available) GPU usage, plus a process list. Monitoring runs only while the Monitor view is being watched. Ending a process requires an explicit action and refuses protected Windows processes.
- **Activity & safety** — A local log of actions taken in the app.
- **Recommendations (optional, off by default)** — Built-in rules with no network, or an OpenAI-compatible provider such as OpenRouter, LM Studio, or Ollama. Suggestions are allowlisted and re-validated on the server. The recommender never proposes emptying the Recycle Bin or sending raw file lists to recycle. Every apply step still requires confirmation.
- **Admin relaunch** — Some Windows locations need elevation. The app can request a UAC prompt; it never elevates automatically.

## Screenshots

<!-- ![Screenshot](docs/screenshot.png) -->

## Requirements

- Windows
- Python 3.10 or newer (standard library only; no pip packages)
- Microsoft Edge (used to host the app window; the system browser is used as a fallback)
- winget / App Installer (optional), for the application-update list and upgrades
- NVIDIA drivers and `nvidia-smi` (optional), for GPU figures on the Monitor view

## Running from source

From this folder:

```bat
C:\Python314\pythonw.exe cleanup.pyw
```

Or double-click `cleanup.pyw` if `.pyw` is associated with Python 3.14.

Create a Desktop shortcut:

- **Target:** `C:\Python314\pythonw.exe`
- **Arguments:** `"C:\path\to\pc-cleanup-organizer\cleanup.pyw"`
- **Start in:** the `pc-cleanup-organizer` folder
- **Icon:** `cleanup.ico`
- **Suggested shortcut key:** `Ctrl+Alt+C`

On first run the app creates `settings.json` and `ai-settings.json`. You can copy the `*.example.json` files to those names and edit them; leave `last_scan` empty. Do not commit the live settings files.

`pc_test.py` is a small local test helper. Destructive steps it performs are limited to a `test-sandbox` folder next to the app. `research/cleanmymac-notes.md` is background research from an earlier design pass.

## Configuration

Settings live in `settings.json` (scan age threshold, duplicate minimum size, whether to skip shortcuts when organizing, and the default organize rule). AI recommendation settings live in `ai-settings.json`. Use the example files as a starting point:

- `settings.example.json`
- `ai-settings.example.json`

Smart recommendations can use built-in rules (no network) or an OpenAI-compatible provider. The API key is never stored in the app. In `ai-settings.json`, `key_env` must be the **name** of an environment variable, not the key itself. The default name is:

```bat
OPENROUTER_API_KEY
```

Set that as a User environment variable. The key is read at call time and is never written to `ai-settings.json`, `settings.json`, or logs.

The default organize rule is `type` (by file type). `date` organizes into `YYYY\MM` folders. `old_days` defaults to 90, and `dup_min_kb` defaults to 100.

Optional environment variable: `CLEANUP_PORT` (default: `48251`).

## Usage

1. Start `cleanup.pyw`. The Dashboard is the first view.
2. Run a Smart Scan or open **Scan & disk map** to inspect a folder. Scanning does not change files.
3. On **Cleanup**, measure categories, review what would be removed, then confirm. Use a dry run first if you want a preview. Emptying the Recycle Bin requires typing `EMPTY`.
4. On **Organize**, choose a folder and a rule, preview the plan, then confirm. Use Undo (or `Ctrl+Z` on that tab) to restore the last organize operation.
5. Review **Applications**, **Protection**, and **Startup** before changing anything. Uninstalls, leftover removal, winget upgrades, and startup toggles are explicit, confirmed actions.
6. Optionally turn on recommendations in **Settings & AI** and review each suggested action before applying it.

Press `?` in the app for keyboard shortcuts. Number keys `1`–`9` switch the main views.

## Privacy & Safety

- The server binds to `127.0.0.1` only and rejects requests whose `Host` header is not `127.0.0.1` or `localhost` on the app port. State-changing POST requests also require a custom header, so other websites cannot trigger them.
- Scans are read-only. Deletes, recycles, moves, uninstalls, leftover removal, registry-key deletion, Recycle Bin emptying, process termination, and startup changes all require confirmation in the app.
- Recycle and organize operations are limited to an allowlist: the user profile, Desktop, Documents, Downloads, and a local test sandbox. Windows, Program Files, ProgramData, AppData, drive roots, and tool/dot folders such as `.git` or `.venv` are treated as protected and are refused.
- Browser cleanup is limited to cache folders (for example Cache, Code Cache, and GPUCache, or Firefox `cache2`). Cookies, history, passwords, and profiles are never touched.
- Several system locations (Windows Update download cache, Delivery Optimization cache, NVIDIA installer cache) can be measured but are review-only; this app will not clean them.
- Temp and cache files that are cleaned are deleted (not recycled) and are skipped when in use. User files sent from Scan can go to the Recycle Bin, and the app refuses to recycle every copy in a duplicate group.
- Organize can be undone from the last operation. An action log is written under `logs/`.
- When recommendations use an OpenAI-compatible provider, the app sends a compact snapshot (sizes, names, ages, and ids). File contents and secrets are not included. The API key is read from an environment variable and is never stored or logged. The model may only pick from a capability-filtered allowlist; emptying the Recycle Bin and raw recycle lists are forbidden for the recommender.
- Admin rights are never taken automatically. Elevation uses a standard UAC prompt, and only when you ask.

## Project Structure

| File | Description |
| --- | --- |
| `cleanup.pyw` | Main app: local server, UI, scan, cleanup, organize, apps, protection, startup, monitor, and recommendations |
| `settings.example.json` | Example general settings. Copy to `settings.json` if you want a starter file |
| `ai-settings.example.json` | Example recommendation settings. Copy to `ai-settings.json` if you want a starter file |
| `pc_test.py` | Local test helper; destructive steps are confined to `test-sandbox` |
| `research/cleanmymac-notes.md` | Background research notes from an earlier design pass |
| `cleanup.ico` | Application icon |
| `.gitignore` | Excludes live settings, scan results, logs, undo history, and secrets |

Runtime files such as `settings.json`, `ai-settings.json`, `scan-summary.json`, `undo-history.json`, and `logs/` are gitignored and are not part of this repository.

## Author

[Antonio James](https://github.com/asjames18) · Melanated in Tech
