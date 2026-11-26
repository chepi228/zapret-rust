@echo off
setlocal
rem Native menu handles elevation and update recovery.
cd /d "%~dp0"
if not exist "%~dp0bin\zapret-rust.exe" (
    if exist "%~dp0bin\zapret-rust-recovery.exe" (
        "%~dp0bin\zapret-rust-recovery.exe" --root "%~dp0." %*
        exit /b
    )
    echo Native executable is missing. Build it with dev\native-build.ps1.
    exit /b 1
)
"%~dp0bin\zapret-rust.exe" --root "%~dp0." %*
exit /b %errorlevel%
