<#
  PC Cleanup & Organizer installer (no admin needed). Run it with Install-PCCleanup.cmd (double-click).
  Installs to %LOCALAPPDATA%\PCCleanup:  app\ = code, data\ = settings, logs, undo history and registry backups.
  The app uses only the Python standard library, so the only thing it may need is Python 3.10+; if that's missing
  it offers to install the official python.org Python (per-user) first. Running it again is safe.

  Test / sandbox example (touches nothing real):
    Install-PCCleanup.cmd -InstallRoot "%TEMP%\PCCTest" -DesktopDir "%TEMP%\PCCTest\desk" -StartMenuDir "%TEMP%\PCCTest\start"
      -ShortcutName "PC Cleanup TEST" -NoHotkey -NoLaunch -Quiet [-ForcePythonInstall -PythonDir "%TEMP%\PCCTest\py"]
#>
param(
  [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "PCCleanup"),
  [string]$ShortcutName = "PC Cleanup & Organizer",
  [string]$DesktopDir = [Environment]::GetFolderPath("Desktop"),
  [string]$StartMenuDir = (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"),
  [string]$Hotkey = "Ctrl+Alt+C",
  [switch]$NoHotkey,
  [switch]$NoLaunch,
  [switch]$Quiet,
  [switch]$InstallPython,
  [switch]$ForcePythonInstall,
  [string]$PythonDir = ""
)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $Here "SetupCommon.ps1")
Initialize-Net
$PkgRoot = Split-Path -Parent $Here
$Src = Join-Path $PkgRoot "app"
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$AppDir = Join-Path $InstallRoot "app"
$DataDir = Join-Path $InstallRoot "data"
$T0 = Get-Date
function Finish($code) {
  $secs = [int]((Get-Date) - $T0).TotalSeconds
  Say ("  (took {0} min {1} s)" -f [math]::Floor($secs / 60), ($secs % 60))
  if (-not $Quiet) { Write-Host ""; Read-Host "Press Enter to close" | Out-Null }
  exit $code
}

Say ""
Say "  PC Cleanup & Organizer setup" Cyan
Say "  ----------------------------"
if (-not (Test-Path -LiteralPath (Join-Path $Src "cleanup.pyw"))) {
  Say "  Can't find the app files next to this installer." Red
  Say "  Right-click the downloaded zip, choose 'Extract All...', then run Install-PCCleanup.cmd from the extracted folder."
  Finish 1
}
$Version = "?"
$m = Select-String -LiteralPath (Join-Path $Src "cleanup.pyw") -Pattern '^VERSION = "([^"]+)"' | Select-Object -First 1
if ($m) { $Version = $m.Matches[0].Groups[1].Value }
Say "  Version $Version  ->  $InstallRoot"
if (-not (Assert-FreeSpace $InstallRoot 50 "PC Cleanup & Organizer")) { Finish 1 }

$py = Resolve-Python -Min ([version]"3.10") -Force:$ForcePythonInstall -SandboxDir $PythonDir -AutoYes:($InstallPython -or $ForcePythonInstall) -Quiet:$Quiet -AppName "PC Cleanup & Organizer"
if (-not $py) { Say "  PC Cleanup & Organizer needs Python. Nothing was installed." Yellow; Finish 2 }
$PyW = Join-Path (Split-Path $py.Path) "pythonw.exe"
if (-not (Test-Path -LiteralPath $PyW)) { $PyW = $py.Path }

Stop-AppProcesses $InstallRoot
New-Item -ItemType Directory -Force -Path $AppDir, $DataDir | Out-Null
Copy-Item -Path (Join-Path $Src "*") -Destination $AppDir -Recurse -Force
foreach ($f in @("Uninstall-PCCleanup.ps1", "SetupCommon.ps1")) { Copy-Item -LiteralPath (Join-Path $Here $f) -Destination (Join-Path $InstallRoot $f) -Force }
Get-ChildItem -LiteralPath $AppDir -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
$info = [ordered]@{ data_dir = "..\data"; version = $Version; installed = (Get-Date -Format s); python = $PyW }
Write-Utf8NoBom (Join-Path $AppDir "installed.json") ($info | ConvertTo-Json)
Say "  App copied to $AppDir; settings and logs live in $DataDir" Green
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { Say "  Note: winget (App Installer) isn't on this PC, so the app-update list is off. Get 'App Installer' from the Microsoft Store to turn it on." Yellow }

$Ico = Join-Path $AppDir "cleanup.ico"
$appArgs = '"' + (Join-Path $AppDir "cleanup.pyw") + '"'
New-Item -ItemType Directory -Force -Path $DesktopDir, $StartMenuDir | Out-Null
function Get-LinkPath($dir, $name) {
  $p = Join-Path $dir "$name.lnk"
  if (Test-Path -LiteralPath $p) {
    try { $l = (New-Object -ComObject WScript.Shell).CreateShortcut($p); if (($l.Arguments + $l.TargetPath) -notlike "*$InstallRoot*") { $p = Join-Path $dir "$name (installed).lnk" } } catch { }
  }
  return $p
}
$desk = Get-LinkPath $DesktopDir $ShortcutName
$start = Get-LinkPath $StartMenuDir $ShortcutName
$hot = $null
if (-not $NoHotkey) {
  $taken = Find-HotkeyClash $Hotkey (Get-ShortcutDirs $DesktopDir $StartMenuDir) @($desk, $start)
  if ($taken) { Say "  Note: '$(Split-Path $taken -Leaf)' already uses $Hotkey, so the new shortcut has no hotkey." Yellow } else { $hot = $Hotkey }
}
New-AppShortcut $desk $PyW $appArgs $AppDir $Ico $hot "PC Cleanup & Organizer"
New-AppShortcut $start $PyW $appArgs $AppDir $Ico $null "PC Cleanup & Organizer"
$unArgs = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $InstallRoot "Uninstall-PCCleanup.ps1") + '" -InstallRoot "' + $InstallRoot + '" -ShortcutName "' + $ShortcutName + '" -DesktopDir "' + $DesktopDir + '" -StartMenuDir "' + $StartMenuDir + '"'
New-AppShortcut (Join-Path $StartMenuDir "Uninstall $ShortcutName.lnk") "powershell.exe" $unArgs $InstallRoot $Ico $null "Uninstall PC Cleanup & Organizer"
$hotMsg = ""; if ($hot) { $hotMsg = " (hotkey $hot)" }
Say ("  Shortcuts: Desktop + Start menu" + $hotMsg) Green

if (-not $NoLaunch) { Start-Process -FilePath $PyW -ArgumentList $appArgs -WorkingDirectory $AppDir; Say "  Opening PC Cleanup & Organizer." Cyan }
"installed $Version $(Get-Date -Format s) python=$($py.Path)" | Add-Content -LiteralPath (Join-Path $DataDir "install.log")
Say ""
Say "  Done!" Green
Finish 0
