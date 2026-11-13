# CleanMyMac (MacPaw): research notes, Oct 30, 2026

Public-web research for the PC Cleanup & Organizer v2 build. Mac-only product; MacPaw's Windows app (CleanMy PC) was discontinued on April 22, 2025.

## What it is now
- Current app: "CleanMyMac" (the 2024 rebrand/rebuild of CleanMyMac X, v5.0 on Oct 16, 2024). Latest version 5.7.3 (Oct 29, 2026), macOS 11+.
- Modules: **Smart Care** (one scan with 5 routines: junk, threats, performance, app updates, duplicate downloads), **Cleanup** (system junk, caches, logs, mail attachments, Trash), **Protection** (Moonlock malware/adware engine with Quick/Normal/Deep scans, privacy items, app permissions), **Performance** (login items, background items, maintenance tasks, "Free Up Purgeable Space"), **Applications** (uninstaller with leftovers, updater, app reset, old installers), **My Clutter** (large & old files, duplicates, similar images, downloads), **Space Lens** (bubble map of the disk), **Cloud Cleanup** (iCloud, Google Drive, OneDrive, Dropbox; Remove and Unsync), **CleanMyMac Menu** (menu-bar monitor for CPU, RAM, disk, network, battery), **My Activity**, **My Tools**.

## 2025-2026 updates
- Feb 10, 2025 (5.0.5): Free Up Purgeable Space maintenance task.
- Jun 12, 2025 (5.1.0): Space Lens returns, redesigned.
- Jul 29, 2025 (5.2.1): Cloud Cleanup launched; plans split into Basic and Plus (Cloud Cleanup is Plus-only).
- Oct 20 / Nov 4, 2025 (5.2.6): Smart Insights, the first AI feature, uses on-device Apple Intelligence to explain unfamiliar files (Apple Silicon, macOS Tahoe 26).
- Dec 17, 2025 (5.3.0): Dropbox in Cloud Cleanup, better OneDrive support.
- Feb 26, 2026 (5.4.0): My Activity dashboard with health recommendations.
- Apr 2, 2026 (5.5.0): My Tools (pinned favorite tools).
- Jul 9, 2026 (5.5.5): Applications scans in the background.
- Aug 17, 2026 (5.6.0): Notification Center.
- Sep 25, 2026 (5.7.0): Email Cleanup for Gmail (newsletters, promos, unsubscribe).
- Oct 1, 2026 (5.7.1): Screen Cleaning Mode.
- Oct 15, 2026 (5.7.2): Browser Care Chrome extension (memory and CPU per tab, duplicate tabs).
- In progress: AI-agent junk cleanup, Safari and Chrome browser tools, a CleanMyMac CLI.

## Pricing (MacPaw store, Oct 2026)
- Subscription for 1 Mac: $39.95/yr (about $3.33/mo), or $9.95 monthly. 2 Macs: $63.95/yr. 5 Macs: $127.95/yr.
- One-time purchase: $119.95 for 1 Mac. It covers the current major version only, with no future major upgrades.
- Also on Setapp and the App Store. Free version and 7-day trial. Basic and Plus tiers since July 2025.

## Sources
- https://cleanmymac.com/
- https://macpaw.com/cleanmymac/whats-new
- https://cleanmymac.com/blog/cleanmymac-vs-cleanmymac-x
- https://macpaw.com/store/cleanmymac
- https://macpaw.com/support/cleanmymac/knowledgebase/purchase-options
- https://macpaw.com/news/macpaw-introduces-cloud-cleanup
- https://macpaw.com/news/introducing-smart-insights
- https://macpaw.com/news/cleanmypc-sunset
- https://setapp.com/apps/cleanmymac

## CleanMyMac to Windows mapping (PC Cleanup & Organizer v2)
| CleanMyMac | Windows equivalent | Status |
|---|---|---|
| Smart Care | Dashboard tab: one read-only "Smart Scan" across all modules, health score | BUILT |
| My Activity / recommendations | Dashboard health summary plus Recommendations (local rules; AI provider stubbed, OFF) | BUILT |
| Cleanup (junk, caches, Trash) | Cleanup tab: TEMP, Edge/Chrome caches, thumbnail cache, Recycle Bin | existing |
| Space Lens | Scan & disk map | existing |
| My Clutter: large/old/duplicates/downloads | Scan tabs: largest, duplicates, old downloads | existing |
| My Clutter: similar images | Not built. Pure-Python image decoding is too slow and heavy without Pillow | SKIPPED |
| Applications: uninstaller and leftovers | Apps tab: registry programs + Store apps, own uninstaller, leftover scan, .reg backup and restore | BUILT |
| Applications: orphaned leftovers | Apps tab: AppData/ProgramData folders with no matching program (review-only) | BUILT |
| Applications: updater | Apps tab: `winget upgrade` list, and an upgrade per app behind a confirm | BUILT |
| Applications: old installers | Organize "Installers" group, old downloads | existing |
| Protection: malware scan | Protection tab: Defender status and Quick Scan (when Defender is active), Security Center AV list | BUILT |
| Protection: adware/privacy | Protection tab: browser extensions and permissions, homepage/search overrides, unsigned startup items, AppData/Temp tasks, hosts file, proxy | BUILT |
| Privacy (browsing traces) | Protection tab: history and cookie DB sizes (read-only, no deletion) | BUILT (read-only) |
| Performance: login/background items | Startup tab: Run/RunOnce, Startup folders, StartupApproved, logon tasks, services, and enable/disable via StartupApproved | BUILT |
| Performance: maintenance tasks | Windows Update status, pending reboot, disk health | BUILT (read-only) |
| CleanMyMac Menu (live monitor) | Monitor tab: CPU per core, RAM, disk I/O, network, GPU and VRAM and temp, battery, processes, sparklines | BUILT |
| Purgeable space | (Windows: Storage Sense / Disk Cleanup, needs admin) | not built |
| Cloud Cleanup | OneDrive cloud-only files are already shown and never downloaded | partial (existing) |
| Email Cleanup / Browser Care / Screen clean | Out of scope for a local disk tool | SKIPPED |
