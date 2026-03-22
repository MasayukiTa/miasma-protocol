# Miasma Desktop — Troubleshooting Guide

## App does not start

**Symptom**: Double-clicking the shortcut or exe does nothing, or a brief flash appears.

**Try**:
1. Right-click `miasma-desktop.exe` → Properties → check "Unblock" if present → OK
2. Check if antivirus quarantined the exe (restore it from quarantine)
3. Run from a command prompt to see error output: `miasma-desktop.exe --mode technical`
4. Ensure the Visual C++ 2015-2022 Redistributable (x64) is installed

## Backend does not connect

**Symptom**: App shows "Not running" or "Stopped" and clicking Start does not help.

**Try**:
1. Check if `miasma.exe` exists next to `miasma-desktop.exe` (or is on PATH)
2. Check if antivirus is blocking `miasma.exe`
3. Look at the daemon log: open `%LOCALAPPDATA%\miasma\data\daemon.log.*`
4. Try starting manually: open a command prompt, run `miasma daemon`
5. If a stale lock exists, delete `%LOCALAPPDATA%\miasma\data\daemon.port` and restart

## No peers found

**Symptom**: App shows "Connected" but peer count stays at 0.

**This is normal** for the first few minutes after launch. The DHT needs time to discover peers.

**If peers remain at 0 after 5+ minutes**:
1. Check your network connection
2. Corporate firewalls or proxies may block P2P traffic — check Settings for proxy configuration
3. If behind a restrictive network (GlobalProtect, Zscaler), see the proxy section in the Technical docs

## Save or retrieve not working

**Symptom**: Save hangs or shows an error; Retrieve says content not found.

**For save issues**:
- Ensure the daemon is running (green indicator or "Connected" status)
- Check available storage quota in the Status tab

**For retrieve issues**:
- Verify the MID is correct (starts with `miasma:`)
- Content must exist on at least one reachable peer
- If no peers are connected, the content cannot be retrieved

## Language or mode confusion

**To change language**: Settings → Language → select from dropdown → takes effect immediately

**To change mode**: Settings → Interface Mode → select Technical or Easy → takes effect immediately

Both settings persist across restarts.

## Magnet link or torrent file not opening

**Symptom**: Clicking a magnet link does not open Miasma.

**For installed (MSI) users**:
1. Open Windows Settings → Default apps
2. Search for "magnet" or find Miasma in the app list
3. Set Miasma as the handler for magnet links

**For .torrent files**:
1. Right-click a `.torrent` file → Open with → Choose another app
2. Select Miasma from the list
3. Optionally check "Always use this app"

**For portable (ZIP) users**:
- Drag the `.torrent` file onto `miasma-desktop.exe`
- Or run: `miasma-desktop.exe "magnet:?xt=..."`

## Install or upgrade issues

**Fresh install fails**:
- Ensure you have admin rights
- Check that no previous Miasma processes are running (Task Manager)
- The MSI requires the Visual C++ Redistributable — install it first

**Upgrade preserves old behavior**:
- Mode and language preferences are stored in `%LOCALAPPDATA%\miasma\data\desktop-prefs.toml`
- This file survives upgrades and uninstalls
- If preferences seem wrong after upgrade, delete `desktop-prefs.toml` to reset to defaults

**Uninstall leaves data**:
- This is intentional — your encrypted content is preserved in `%LOCALAPPDATA%\miasma\data\`
- To fully remove all data, delete that directory after uninstalling

## Getting support

1. Open the Status tab
2. Click **Save Report** to save diagnostics to a file
3. Attach the file when reporting issues
4. Include: what you did, what you expected, what happened instead
5. Desktop logs are in `%LOCALAPPDATA%\miasma\data\desktop.log.*`
6. Daemon logs are in `%LOCALAPPDATA%\miasma\data\daemon.log.*`
