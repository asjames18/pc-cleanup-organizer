@echo off
setlocal
rem PC Cleanup and Organizer uninstaller. Your data is kept unless you choose to delete it.
if exist "%LOCALAPPDATA%\PCCleanup\Uninstall-PCCleanup.ps1" if "%~1"=="" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\PCCleanup\Uninstall-PCCleanup.ps1"
  exit /b %errorlevel%
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\Uninstall-PCCleanup.ps1" %*
exit /b %errorlevel%
