@echo off
rem Miasma — Easy mode launcher (default for non-technical users)
rem
rem This launches the Miasma desktop app in Easy mode.
rem To switch to Technical mode, use "Miasma Technical.cmd" or
rem go to Settings inside the app.
start "" "%~dp0miasma-desktop.exe" --mode easy
