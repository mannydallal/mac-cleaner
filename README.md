# Mac Cleaner

A CleanMyMac-style desktop app that cleans junk files on Mac and Windows (including Parallels).

## Download

See the [Releases](../../releases) page for the latest installer:
- **Mac**: Download the `.dmg` → open it → drag Mac Cleaner to Applications
- **Windows** (Parallels): Download the `.exe` → run the installer

> **First time on Mac:** Right-click the app → Open (bypasses the security warning for unsigned apps)

## What it cleans

### Mac
- User App Caches (`~/Library/Caches`)
- System Logs (`~/Library/Logs`)
- Temp Files (`/private/tmp`)
- Trash (`~/.Trash`)
- Chrome, Safari, Firefox caches
- Xcode Derived Data
- Parallels VM cache

### Windows
- User Temp Files (`%TEMP%`)
- Windows Temp (`C:\Windows\Temp`)
- Chrome and Edge caches
- IE / Edge web cache
- Recent files list

## Build from source

```bash
npm install
npm run package:mac    # builds Mac .dmg
npm run package:win    # builds Windows .exe (requires Windows or Wine)
```

## Note on app icons

Place a 512×512 PNG named `icon.png` in the `build/` folder before building.
electron-builder will generate `icon.icns` (Mac) and `icon.ico` (Windows) automatically.
