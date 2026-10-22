@echo off
chcp 65001 >nul
rem One-click public launch for policy_gap (middle-step history fill game).
rem Starts the local proxy server in --public mode and opens a Cloudflare quick tunnel,
rem prints the share link and copies it to the clipboard.
rem Close this window to kill the public URL.
rem
rem Keep all Chinese out of this file: cmd.exe parses .bat with the OEM codepage,
rem so UTF-8 comments get mis-parsed as commands. All Chinese output comes from Node.
cd /d "%~dp0.."
where node >nul 2>nul
if errorlevel 1 (
  echo [X] node not found on PATH. Install Node.js first, then double-click again.
  echo     The server itself is plain Node, no packages needed.
  pause
  exit /b 1
)
node "deploy\public-launch.mjs"
echo.
pause
