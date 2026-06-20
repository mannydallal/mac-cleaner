import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export type ScanResult = {
  id: string;
  name: string;
  category: string;
  path: string;
  sizeMb: number;
  fileCount: number;
  safe: boolean;
};

function expandPath(p: string): string {
  if (p.startsWith("~")) return path.join(os.homedir(), p.slice(1));
  if (process.platform === "win32") {
    return p.replace(/%([^%]+)%/g, (_, key) => process.env[key] ?? "");
  }
  return p;
}

function getFolderSize(dirPath: string): { sizeMb: number; fileCount: number } {
  let totalBytes = 0;
  let fileCount = 0;
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      try {
        if (entry.isSymbolicLink()) continue;
        if (entry.isFile()) {
          totalBytes += fs.statSync(fullPath).size;
          fileCount++;
        } else if (entry.isDirectory()) {
          const sub = getFolderSize(fullPath);
          totalBytes += sub.sizeMb * 1024 * 1024;
          fileCount += sub.fileCount;
        }
      } catch {
        // skip inaccessible files
      }
    }
  } catch {
    // skip inaccessible directories
  }
  return { sizeMb: totalBytes / (1024 * 1024), fileCount };
}

type ScanTarget = {
  id: string;
  name: string;
  category: string;
  rawPath: string;
  safe: boolean;
  platforms: ("darwin" | "win32" | "linux")[];
};

const SCAN_TARGETS: ScanTarget[] = [
  // ── Mac: System Junk ─────────────────────────────────────────
  {
    id: "mac-user-cache",
    name: "User App Caches",
    category: "System Junk",
    rawPath: "~/Library/Caches",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-system-cache",
    name: "System Caches",
    category: "System Junk",
    rawPath: "/Library/Caches",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-logs",
    name: "User Log Files",
    category: "System Junk",
    rawPath: "~/Library/Logs",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-system-logs",
    name: "System Log Files",
    category: "System Junk",
    rawPath: "/Library/Logs",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-tmp",
    name: "Temp Files",
    category: "System Junk",
    rawPath: "/private/tmp",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-trash",
    name: "Trash",
    category: "System Junk",
    rawPath: "~/.Trash",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-crash-reports",
    name: "Crash Reports",
    category: "System Junk",
    rawPath: "~/Library/Application Support/CrashReporter",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-diagnostics",
    name: "Diagnostic Reports",
    category: "System Junk",
    rawPath: "~/Library/Logs/DiagnosticReports",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-sleep-image",
    name: "Sleep Image",
    category: "System Junk",
    rawPath: "/private/var/vm",
    safe: false,
    platforms: ["darwin"],
  },
  // ── Mac: Browser Junk ────────────────────────────────────────
  {
    id: "mac-chrome-cache",
    name: "Chrome Cache",
    category: "Browser Junk",
    rawPath: "~/Library/Application Support/Google/Chrome/Default/Cache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-chrome-code-cache",
    name: "Chrome Code Cache",
    category: "Browser Junk",
    rawPath: "~/Library/Application Support/Google/Chrome/Default/Code Cache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-chrome-gpu-cache",
    name: "Chrome GPU Cache",
    category: "Browser Junk",
    rawPath: "~/Library/Application Support/Google/Chrome/Default/GPUCache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-safari-cache",
    name: "Safari Cache",
    category: "Browser Junk",
    rawPath: "~/Library/Caches/com.apple.Safari",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-safari-webkit-cache",
    name: "Safari WebKit Cache",
    category: "Browser Junk",
    rawPath: "~/Library/WebKit/com.apple.Safari",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-firefox-cache",
    name: "Firefox Cache",
    category: "Browser Junk",
    rawPath: "~/Library/Application Support/Firefox/Profiles",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-brave-cache",
    name: "Brave Cache",
    category: "Browser Junk",
    rawPath: "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-edge-cache",
    name: "Edge Cache",
    category: "Browser Junk",
    rawPath: "~/Library/Application Support/Microsoft Edge/Default/Cache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-opera-cache",
    name: "Opera Cache",
    category: "Browser Junk",
    rawPath: "~/Library/Application Support/com.operasoftware.Opera/Default/Cache",
    safe: true,
    platforms: ["darwin"],
  },
  // ── Mac: App Caches ──────────────────────────────────────────
  {
    id: "mac-slack-cache",
    name: "Slack Cache",
    category: "System Junk",
    rawPath: "~/Library/Application Support/Slack/Cache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-slack-gpucache",
    name: "Slack GPU Cache",
    category: "System Junk",
    rawPath: "~/Library/Application Support/Slack/GPUCache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-discord-cache",
    name: "Discord Cache",
    category: "System Junk",
    rawPath: "~/Library/Application Support/discord/Cache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-teams-cache",
    name: "Microsoft Teams Cache",
    category: "System Junk",
    rawPath: "~/Library/Application Support/Microsoft/Teams/Cache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-spotify-cache",
    name: "Spotify Cache",
    category: "System Junk",
    rawPath: "~/Library/Application Support/Spotify/PersistentCache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-zoom-cache",
    name: "Zoom Cache",
    category: "System Junk",
    rawPath: "~/Library/Application Support/zoom.us",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-dropbox-cache",
    name: "Dropbox Cache",
    category: "System Junk",
    rawPath: "~/.dropbox/cache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-figma-cache",
    name: "Figma Cache",
    category: "System Junk",
    rawPath: "~/Library/Application Support/Figma/cache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-vscode-cache",
    name: "VS Code Cache",
    category: "System Junk",
    rawPath: "~/Library/Application Support/Code/Cache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-vscode-gpucache",
    name: "VS Code GPU Cache",
    category: "System Junk",
    rawPath: "~/Library/Application Support/Code/GPUCache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-jetbrains-cache",
    name: "JetBrains Caches",
    category: "Developer Junk",
    rawPath: "~/Library/Caches/JetBrains",
    safe: true,
    platforms: ["darwin"],
  },
  // ── Mac: Mail ────────────────────────────────────────────────
  {
    id: "mac-mail-downloads",
    name: "Mail Downloads",
    category: "System Junk",
    rawPath: "~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-mail-attachments",
    name: "Mail Attachments",
    category: "System Junk",
    rawPath: "~/Library/Mail Downloads",
    safe: true,
    platforms: ["darwin"],
  },
  // ── Mac: iOS / Xcode / Developer ─────────────────────────────
  {
    id: "mac-ios-backups",
    name: "iOS Device Backups",
    category: "Large Files",
    rawPath: "~/Library/Application Support/MobileSync/Backup",
    safe: false,
    platforms: ["darwin"],
  },
  {
    id: "mac-ios-device-support",
    name: "iOS Device Support Symbols",
    category: "Developer Junk",
    rawPath: "~/Library/Developer/Xcode/iOS DeviceSupport",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-watchos-device-support",
    name: "watchOS Device Support Symbols",
    category: "Developer Junk",
    rawPath: "~/Library/Developer/Xcode/watchOS DeviceSupport",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-tvos-device-support",
    name: "tvOS Device Support Symbols",
    category: "Developer Junk",
    rawPath: "~/Library/Developer/Xcode/tvOS DeviceSupport",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-xcode",
    name: "Xcode Derived Data",
    category: "Developer Junk",
    rawPath: "~/Library/Developer/Xcode/DerivedData",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-xcode-archives",
    name: "Xcode Archives",
    category: "Developer Junk",
    rawPath: "~/Library/Developer/Xcode/Archives",
    safe: false,
    platforms: ["darwin"],
  },
  {
    id: "mac-xcode-previews",
    name: "Xcode Canvas Previews",
    category: "Developer Junk",
    rawPath: "~/Library/Developer/Xcode/UserData/Previews",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-simulator-devices",
    name: "iOS Simulator Data",
    category: "Developer Junk",
    rawPath: "~/Library/Developer/CoreSimulator/Devices",
    safe: false,
    platforms: ["darwin"],
  },
  {
    id: "mac-simulator-cache",
    name: "Simulator Caches",
    category: "Developer Junk",
    rawPath: "~/Library/Developer/CoreSimulator/Caches",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-simulator-runtimes",
    name: "Old Simulator Runtimes",
    category: "Developer Junk",
    rawPath: "~/Library/Developer/CoreSimulator/Volumes",
    safe: false,
    platforms: ["darwin"],
  },
  {
    id: "mac-npm-cache",
    name: "npm Cache",
    category: "Developer Junk",
    rawPath: "~/.npm/_cacache",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-yarn-cache",
    name: "Yarn Cache",
    category: "Developer Junk",
    rawPath: "~/Library/Caches/Yarn",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-pip-cache",
    name: "pip Cache",
    category: "Developer Junk",
    rawPath: "~/Library/Caches/pip",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-gradle-cache",
    name: "Gradle Cache",
    category: "Developer Junk",
    rawPath: "~/.gradle/caches",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-maven-cache",
    name: "Maven Cache",
    category: "Developer Junk",
    rawPath: "~/.m2/repository",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-cocoapods-cache",
    name: "CocoaPods Cache",
    category: "Developer Junk",
    rawPath: "~/Library/Caches/CocoaPods",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-homebrew-cache",
    name: "Homebrew Cache",
    category: "Developer Junk",
    rawPath: "~/Library/Caches/Homebrew",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-cargo-cache",
    name: "Rust / Cargo Cache",
    category: "Developer Junk",
    rawPath: "~/.cargo/registry",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-docker-cache",
    name: "Docker Desktop Cache",
    category: "Developer Junk",
    rawPath: "~/Library/Containers/com.docker.docker/Data",
    safe: false,
    platforms: ["darwin"],
  },
  // ── Mac: Privacy ─────────────────────────────────────────────
  {
    id: "mac-recent-servers",
    name: "Recent Server Connections",
    category: "Privacy",
    rawPath: "~/Library/Application Support/com.apple.sharedfilelist",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-quicklook-cache",
    name: "QuickLook Preview Cache",
    category: "Privacy",
    rawPath: "~/Library/Application Support/Quick Look",
    safe: true,
    platforms: ["darwin"],
  },
  // ── Mac: Parallels ───────────────────────────────────────────
  {
    id: "mac-parallels",
    name: "Parallels VMs & Snapshots",
    category: "Parallels",
    rawPath: "~/Parallels",
    safe: false,
    platforms: ["darwin"],
  },
  {
    id: "mac-parallels-cache",
    name: "Parallels Cache",
    category: "Parallels",
    rawPath: "~/Library/Caches/com.parallels.desktop",
    safe: true,
    platforms: ["darwin"],
  },
  // ── Windows ──────────────────────────────────────────────────
  {
    id: "win-temp",
    name: "User Temp Files",
    category: "System Junk",
    rawPath: "%TEMP%",
    safe: true,
    platforms: ["win32"],
  },
  {
    id: "win-local-temp",
    name: "Local App Temp",
    category: "System Junk",
    rawPath: "%LOCALAPPDATA%\\Temp",
    safe: true,
    platforms: ["win32"],
  },
  {
    id: "win-windows-temp",
    name: "Windows Temp",
    category: "System Junk",
    rawPath: "C:\\Windows\\Temp",
    safe: true,
    platforms: ["win32"],
  },
  {
    id: "win-prefetch",
    name: "Prefetch Files",
    category: "System Junk",
    rawPath: "C:\\Windows\\Prefetch",
    safe: true,
    platforms: ["win32"],
  },
  {
    id: "win-chrome-cache",
    name: "Chrome Cache",
    category: "Browser Junk",
    rawPath: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cache",
    safe: true,
    platforms: ["win32"],
  },
  {
    id: "win-edge-cache",
    name: "Edge Cache",
    category: "Browser Junk",
    rawPath: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cache",
    safe: true,
    platforms: ["win32"],
  },
  {
    id: "win-recycle",
    name: "Recycle Bin",
    category: "System Junk",
    rawPath: "C:\\$Recycle.Bin",
    safe: false,
    platforms: ["win32"],
  },
  {
    id: "win-recent",
    name: "Recent Files List",
    category: "Privacy",
    rawPath: "%APPDATA%\\Microsoft\\Windows\\Recent",
    safe: true,
    platforms: ["win32"],
  },
  {
    id: "win-inet-cache",
    name: "IE / Edge Web Cache",
    category: "Browser Junk",
    rawPath: "%LOCALAPPDATA%\\Microsoft\\Windows\\INetCache",
    safe: true,
    platforms: ["win32"],
  },
  {
    id: "win-thumbnails",
    name: "Thumbnail Cache",
    category: "System Junk",
    rawPath: "%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer",
    safe: true,
    platforms: ["win32"],
  },
];

export function scanSystem(): ScanResult[] {
  const platform = process.platform as "darwin" | "win32" | "linux";
  const results: ScanResult[] = [];

  for (const target of SCAN_TARGETS) {
    if (!target.platforms.includes(platform)) continue;
    const expanded = expandPath(target.rawPath);
    if (!fs.existsSync(expanded)) continue;
    const { sizeMb, fileCount } = getFolderSize(expanded);
    if (sizeMb < 0.001) continue;
    results.push({
      id: target.id,
      name: target.name,
      category: target.category,
      path: expanded,
      sizeMb,
      fileCount,
      safe: target.safe,
    });
  }

  return results.sort((a, b) => b.sizeMb - a.sizeMb);
}

// ── App scanner ───────────────────────────────────────────────────────────────

export type AppInfo = {
  name: string;
  appPath: string;
  bundleId: string;
  sizeMb: number;
  associatedPaths: string[];
  associatedSizeMb: number;
};

function getAppBundleId(appPath: string): string {
  try {
    const plistPath = path.join(appPath, "Contents", "Info.plist");
    const content = fs.readFileSync(plistPath, "utf-8");
    const match = content.match(/<key>CFBundleIdentifier<\/key>\s*<string>([^<]+)<\/string>/);
    return match?.[1] ?? "";
  } catch {
    return "";
  }
}

function findAssociatedPaths(cleanName: string, bundleId: string): string[] {
  const home = os.homedir();
  const found: string[] = [];

  const candidates: string[] = [
    path.join(home, "Library", "Application Support", cleanName),
    path.join(home, "Library", "Logs", cleanName),
    path.join(home, "Library", "Saved Application State", `${bundleId}.savedState`),
  ];

  if (bundleId) {
    candidates.push(
      path.join(home, "Library", "Caches", bundleId),
      path.join(home, "Library", "Containers", bundleId),
      path.join(home, "Library", "Application Support", bundleId),
    );
  }

  // Scan Preferences for matching plists
  const prefsDir = path.join(home, "Library", "Preferences");
  try {
    const prefs = fs.readdirSync(prefsDir).filter(
      (f) => (bundleId && f.startsWith(bundleId)) || f.toLowerCase().startsWith(cleanName.toLowerCase())
    );
    prefs.forEach((f) => candidates.push(path.join(prefsDir, f)));
  } catch { /* skip */ }

  for (const p of candidates) {
    try {
      if (fs.existsSync(p) && !found.includes(p)) found.push(p);
    } catch { /* skip */ }
  }

  return found;
}

export function scanApps(): AppInfo[] {
  const results: AppInfo[] = [];

  if (process.platform === "darwin") {
    const appsDir = "/Applications";
    try {
      const entries = fs.readdirSync(appsDir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.name.endsWith(".app")) continue;
        const appPath = path.join(appsDir, entry.name);
        const cleanName = entry.name.replace(/\.app$/, "");
        const bundleId = getAppBundleId(appPath);
        const { sizeMb } = getFolderSize(appPath);
        const associatedPaths = findAssociatedPaths(cleanName, bundleId);
        const associatedSizeMb = associatedPaths.reduce((sum, p) => {
          try { return sum + getFolderSize(p).sizeMb; } catch { return sum; }
        }, 0);
        results.push({ name: cleanName, appPath, bundleId, sizeMb, associatedPaths, associatedSizeMb });
      }
    } catch { /* skip */ }
  } else if (process.platform === "win32") {
    const dirs = [
      "C:\\Program Files",
      "C:\\Program Files (x86)",
      path.join(os.homedir(), "AppData", "Local", "Programs"),
    ];
    for (const dir of dirs) {
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          if (!entry.isDirectory()) continue;
          const appPath = path.join(dir, entry.name);
          const { sizeMb } = getFolderSize(appPath);
          results.push({ name: entry.name, appPath, bundleId: "", sizeMb, associatedPaths: [], associatedSizeMb: 0 });
        }
      } catch { /* skip */ }
    }
  }

  return results.sort((a, b) => (b.sizeMb + b.associatedSizeMb) - (a.sizeMb + a.associatedSizeMb));
}

export function getSizeOf(p: string): number {
  try { return getFolderSize(p).sizeMb; } catch { return 0; }
}

// ── Disk health ───────────────────────────────────────────────────────────────

export type DiskHealth = {
  smartStatus: string;
  volumeName: string;
  fileSystem: string;
  totalGb: number;
  freeGb: number;
  brokenSymlinks: string[];
};

function findBrokenSymlinks(dir: string, maxDepth = 3, maxFound = 100): string[] {
  const found: string[] = [];
  const scan = (d: string, depth: number) => {
    if (depth > maxDepth || found.length >= maxFound) return;
    try {
      const entries = fs.readdirSync(d, { withFileTypes: true });
      for (const e of entries) {
        if (found.length >= maxFound) break;
        const full = path.join(d, e.name);
        try {
          if (e.isSymbolicLink()) {
            const target = fs.readlinkSync(full);
            const resolved = path.resolve(d, target);
            if (!fs.existsSync(resolved)) found.push(full);
          } else if (e.isDirectory() && !e.isSymbolicLink() && depth < maxDepth) {
            scan(full, depth + 1);
          }
        } catch { /* skip inaccessible */ }
      }
    } catch { /* skip */ }
  };
  scan(dir, 0);
  return found;
}

export function getDiskHealth(): DiskHealth {
  let smartStatus = "Unknown";
  let volumeName = "";
  let fileSystem = "";
  let totalGb = 0;
  let freeGb = 0;
  const { execSync } = require("child_process") as typeof import("child_process");

  if (process.platform === "darwin") {
    // ── Mac: diskutil ──────────────────────────────────────────
    try {
      const out = execSync("diskutil info /", { encoding: "utf-8", timeout: 8000 }) as string;
      const smart  = out.match(/S\.M\.A\.R\.T\. Status:\s*(.+)/);
      const vol    = out.match(/Volume Name:\s*(.+)/);
      const fsLine = out.match(/Type \(Bundle\):\s*(.+)/);
      if (smart)  smartStatus = smart[1].trim();
      if (vol)    volumeName  = vol[1].trim();
      if (fsLine) fileSystem  = fsLine[1].trim();
    } catch { /* skip */ }

    try {
      const df = (execSync("df -k /", { encoding: "utf-8" }) as string).split("\n")[1].trim().split(/\s+/);
      totalGb = (parseInt(df[1]) * 1024) / 1e9;
      freeGb  = (parseInt(df[3]) * 1024) / 1e9;
    } catch { /* skip */ }

  } else if (process.platform === "win32") {
    // ── Windows: wmic ──────────────────────────────────────────
    // SMART status
    try {
      const out = execSync("wmic diskdrive get status /value", { encoding: "utf-8", timeout: 10000 }) as string;
      const match = out.match(/Status=(\w+)/i);
      smartStatus = match ? (match[1] === "OK" ? "Verified" : match[1]) : "Unknown";
    } catch { /* skip */ }

    // Volume info for C:
    try {
      const out = execSync(
        'wmic logicaldisk where DeviceID="C:" get Size,FreeSpace,FileSystem,VolumeName /value',
        { encoding: "utf-8", timeout: 10000 }
      ) as string;
      const fsMatch   = out.match(/FileSystem=(\w+)/i);
      const freeMatch = out.match(/FreeSpace=(\d+)/i);
      const sizeMatch = out.match(/Size=(\d+)/i);
      const nameMatch = out.match(/VolumeName=([^\r\n]+)/i);
      if (fsMatch)   fileSystem = fsMatch[1];
      volumeName  = nameMatch?.[1]?.trim() || "Local Disk (C:)";
      if (sizeMatch) totalGb = parseInt(sizeMatch[1]) / 1e9;
      if (freeMatch) freeGb  = parseInt(freeMatch[1]) / 1e9;
    } catch { /* skip */ }
  }

  // ── Broken symlinks (cross-platform) ───────────────────────
  const home = os.homedir();
  const symlinkDirs = process.platform === "darwin"
    ? [
        path.join(home, "Library", "Application Support"),
        "/usr/local/bin",
        "/usr/local/lib",
        "/opt/homebrew/bin",
      ]
    : [
        path.join(home, "AppData", "Roaming"),
        path.join(home, "AppData", "Local"),
        "C:\\Program Files",
        "C:\\Program Files (x86)",
      ];

  const brokenSymlinks: string[] = [];
  for (const d of symlinkDirs) {
    if (fs.existsSync(d)) brokenSymlinks.push(...findBrokenSymlinks(d, 2, 100 - brokenSymlinks.length));
    if (brokenSymlinks.length >= 100) break;
  }

  return { smartStatus, volumeName: volumeName || "System Drive", fileSystem: fileSystem || "Unknown", totalGb, freeGb, brokenSymlinks };
}

export function verifyDiskVolume(): string {
  const { execSync } = require("child_process") as typeof import("child_process");

  if (process.platform === "darwin") {
    try {
      return execSync("diskutil verifyVolume /", { encoding: "utf-8", timeout: 120000 }) as string;
    } catch (e: unknown) {
      const err = e as { stdout?: string; message?: string };
      return err.stdout ?? err.message ?? String(e);
    }

  } else if (process.platform === "win32") {
    // chkdsk C: with no flags = read-only check, no admin required
    try {
      return execSync("chkdsk C:", { encoding: "utf-8", timeout: 120000 }) as string;
    } catch (e: unknown) {
      // chkdsk exits non-zero when it finds issues but still prints the report
      const err = e as { stdout?: string; stderr?: string; message?: string };
      return err.stdout || err.stderr || err.message || String(e);
    }
  }

  return "Disk verification is not supported on this platform.";
}

// ── Virus / Malware Scanner ───────────────────────────────────────────────────

export interface ThreatItem {
  path: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
}

export interface VirusScanResult {
  status: "clean" | "threats_found" | "error";
  threats: ThreatItem[];
  scannedCount: number;
  scanDuration: number;
  error?: string;
}

const MAC_THREAT_PATTERNS: { pattern: RegExp; name: string; severity: ThreatItem["severity"]; desc: string }[] = [
  { pattern: /genieo/i,        name: "Genieo",           severity: "high",     desc: "Browser hijacker that redirects searches" },
  { pattern: /vsearch/i,       name: "VSearch",          severity: "high",     desc: "Search hijacker" },
  { pattern: /pirrit/i,        name: "Pirrit",           severity: "high",     desc: "Adware injecting ads into browsers" },
  { pattern: /shlayer/i,       name: "Shlayer",          severity: "critical", desc: "Malware dropper — installs other malware" },
  { pattern: /silver.sparrow/i,name: "Silver Sparrow",   severity: "critical", desc: "Malware targeting Apple Silicon" },
  { pattern: /adload/i,        name: "Adload",           severity: "high",     desc: "Adware loader" },
  { pattern: /bundlore/i,      name: "Bundlore",         severity: "high",     desc: "Adware bundler" },
  { pattern: /crossrider/i,    name: "CrossRider",       severity: "medium",   desc: "Browser extension adware" },
  { pattern: /dnsping/i,       name: "DNSPing",          severity: "high",     desc: "DNS hijacker" },
  { pattern: /installcore/i,   name: "InstallCore",      severity: "medium",   desc: "Bundled adware installer" },
  { pattern: /searchmine/i,    name: "SearchMine",       severity: "high",     desc: "Browser hijacker" },
  { pattern: /weknow/i,        name: "Weknow",           severity: "high",     desc: "Browser hijacker" },
  { pattern: /tapufind/i,      name: "TapuFind",         severity: "high",     desc: "Browser hijacker" },
  { pattern: /spigot/i,        name: "Spigot",           severity: "medium",   desc: "Browser redirect adware" },
  { pattern: /babylon/i,       name: "Babylon",          severity: "high",     desc: "Browser hijacker" },
  { pattern: /conduit/i,       name: "Conduit",          severity: "high",     desc: "Browser hijacker" },
  { pattern: /macmediaplayer/i,name: "MacMediaPlayer",   severity: "medium",   desc: "Potentially unwanted program" },
  { pattern: /mplayerx/i,      name: "MPlayerX",         severity: "medium",   desc: "Potentially unwanted program" },
  { pattern: /OperatorMac/i,   name: "OperatorMac",      severity: "high",     desc: "Adware" },
  { pattern: /zango/i,         name: "Zango",            severity: "high",     desc: "Adware" },
];

const WIN_THREAT_PATTERNS: { pattern: RegExp; name: string; severity: ThreatItem["severity"]; desc: string }[] = [
  { pattern: /conduit/i,       name: "Conduit",          severity: "high",     desc: "Browser hijacker" },
  { pattern: /babylon/i,       name: "Babylon",          severity: "high",     desc: "Browser hijacker" },
  { pattern: /sweetpacks/i,    name: "SweetPacks",       severity: "high",     desc: "Adware" },
  { pattern: /iminent/i,       name: "Iminent",          severity: "high",     desc: "Adware" },
  { pattern: /spigot/i,        name: "Spigot",           severity: "medium",   desc: "Browser redirect" },
  { pattern: /ask\.toolbar/i,  name: "Ask Toolbar",      severity: "medium",   desc: "Unwanted browser toolbar" },
  { pattern: /mywebsearch/i,   name: "MyWebSearch",      severity: "high",     desc: "Browser hijacker" },
  { pattern: /facemoods/i,     name: "Facemoods",        severity: "medium",   desc: "Adware" },
  { pattern: /dealply/i,       name: "DealPly",          severity: "medium",   desc: "Adware" },
  { pattern: /wajam/i,         name: "Wajam",            severity: "high",     desc: "Adware / privacy threat" },
  { pattern: /crossrider/i,    name: "CrossRider",       severity: "medium",   desc: "Browser extension adware" },
  { pattern: /installcore/i,   name: "InstallCore",      severity: "medium",   desc: "Bundled adware installer" },
];

function scanDirForThreats(
  dir: string,
  patterns: { pattern: RegExp; name: string; severity: ThreatItem["severity"]; desc: string }[],
  depth = 1,
  maxFiles = 500,
): { threats: ThreatItem[]; scanned: number } {
  const threats: ThreatItem[] = [];
  let scanned = 0;
  function walk(d: string, level: number) {
    if (level > depth || scanned >= maxFiles) return;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (scanned >= maxFiles) break;
      const full = path.join(d, e.name);
      scanned++;
      for (const t of patterns) {
        if (t.pattern.test(e.name) || t.pattern.test(full)) {
          threats.push({ path: full, name: t.name, severity: t.severity, description: t.desc });
          break;
        }
      }
      if (e.isDirectory() && level < depth) walk(full, level + 1);
    }
  }
  walk(dir, 0);
  return { threats, scanned };
}

export function virusScan(): VirusScanResult {
  const start = Date.now();
  const { execSync } = require("child_process") as typeof import("child_process");

  try {
    if (process.platform === "darwin") {
      // ── Mac: deep multi-pass scan ─────────────────────────────
      const home = os.homedir();
      const allThreats: ThreatItem[] = [];
      let totalScanned = 0;

      // Pass 1: persistence locations (deep)
      const persistDirs = [
        { dir: path.join(home, "Library", "LaunchAgents"),          depth: 3 },
        { dir: "/Library/LaunchAgents",                              depth: 3 },
        { dir: "/Library/LaunchDaemons",                             depth: 3 },
        { dir: "/System/Library/LaunchDaemons",                      depth: 2 },
        { dir: path.join(home, "Library", "StartupItems"),           depth: 2 },
        { dir: "/Library/StartupItems",                              depth: 2 },
      ];
      for (const { dir, depth } of persistDirs) {
        if (!fs.existsSync(dir)) continue;
        const { threats, scanned } = scanDirForThreats(dir, MAC_THREAT_PATTERNS, depth, 2000);
        allThreats.push(...threats);
        totalScanned += scanned;
      }

      // Pass 2: Applications + user dirs (broad)
      const broadDirs = [
        { dir: "/Applications",                                       depth: 2 },
        { dir: path.join(home, "Applications"),                      depth: 2 },
        { dir: path.join(home, "Library", "Application Support"),    depth: 3 },
        { dir: path.join(home, "Library", "Internet Plug-Ins"),      depth: 2 },
        { dir: "/Library/Internet Plug-Ins",                         depth: 2 },
        { dir: path.join(home, "Library", "Extensions"),             depth: 2 },
        { dir: "/Library/Extensions",                                 depth: 2 },
        { dir: path.join(home, "Downloads"),                         depth: 2 },
        { dir: path.join(home, "Desktop"),                           depth: 2 },
        { dir: path.join(home, "Library", "Preferences"),            depth: 1 },
        { dir: "/Library/Preferences",                               depth: 1 },
        { dir: "/private/tmp",                                        depth: 2 },
        { dir: "/tmp",                                                depth: 2 },
      ];
      for (const { dir, depth } of broadDirs) {
        if (!fs.existsSync(dir)) continue;
        const { threats, scanned } = scanDirForThreats(dir, MAC_THREAT_PATTERNS, depth, 2000);
        allThreats.push(...threats);
        totalScanned += scanned;
      }

      // Pass 3: mdfind bundle ID sweep (covers all mounted volumes)
      const knownBundles = [
        "com.genieo", "com.vsearch", "com.pirrit", "com.babylon", "com.conduit",
        "com.searchmine", "com.weknow", "com.adload", "com.bundlore", "com.shlayer",
        "com.installcore", "com.crossrider", "com.tapufind", "com.dnsping",
      ];
      for (const bundleId of knownBundles) {
        try {
          const found = execSync(
            `mdfind "kMDItemCFBundleIdentifier == '*${bundleId}*'"`,
            { encoding: "utf-8", timeout: 8000 }
          ) as string;
          for (const line of found.split("\n").filter(Boolean)) {
            if (!allThreats.some(t => t.path === line)) {
              const match = MAC_THREAT_PATTERNS.find(p => p.pattern.test(bundleId));
              if (match) allThreats.push({ path: line, name: match.name, severity: match.severity, description: match.desc });
            }
          }
        } catch { /* skip */ }
      }

      // Pass 4: find unsigned / suspicious executables in common drop paths
      const dropPaths = [
        path.join(home, "Downloads"),
        path.join(home, "Desktop"),
        "/tmp",
        "/private/tmp",
      ];
      for (const dp of dropPaths) {
        if (!fs.existsSync(dp)) continue;
        try {
          // find executables that lack a valid Apple code signature
          const out = execSync(
            `find "${dp}" -maxdepth 3 -type f \\( -name "*.pkg" -o -name "*.dmg" -o -name "*.app" -o -perm +111 \\) 2>/dev/null | head -200`,
            { encoding: "utf-8", timeout: 15000 }
          ) as string;
          for (const fp of out.split("\n").filter(Boolean)) {
            totalScanned++;
            // check code signature
            try {
              execSync(`codesign --verify --strict "${fp}" 2>&1`, { timeout: 3000, stdio: "pipe" });
            } catch {
              // no valid signature — check if it matches any threat pattern by name
              const base = path.basename(fp);
              for (const t of MAC_THREAT_PATTERNS) {
                if (t.pattern.test(base) || t.pattern.test(fp)) {
                  if (!allThreats.some(x => x.path === fp)) {
                    allThreats.push({ path: fp, name: t.name, severity: t.severity, description: t.desc });
                  }
                  break;
                }
              }
            }
          }
        } catch { /* skip */ }
      }

      // Pass 5: check login items via osascript
      try {
        const items = execSync(
          `osascript -e 'tell application "System Events" to get the path of every login item'`,
          { encoding: "utf-8", timeout: 8000 }
        ) as string;
        for (const item of items.split(", ").map(s => s.trim()).filter(Boolean)) {
          totalScanned++;
          for (const t of MAC_THREAT_PATTERNS) {
            if (t.pattern.test(item)) {
              if (!allThreats.some(x => x.path === item)) {
                allThreats.push({ path: item, name: t.name, severity: t.severity, description: `Login item: ${t.desc}` });
              }
              break;
            }
          }
        }
      } catch { /* skip */ }

      return {
        status: allThreats.length > 0 ? "threats_found" : "clean",
        threats: allThreats,
        scannedCount: totalScanned,
        scanDuration: Date.now() - start,
      };

    } else if (process.platform === "win32") {
      // ── Windows: Windows Defender full scan + deep pattern sweep ──
      const allThreats: ThreatItem[] = [];
      let totalScanned = 0;

      // 1. Run Windows Defender full scan (ScanType 2)
      try {
        const defenderPath = "C:\\Program Files\\Windows Defender\\MpCmdRun.exe";
        if (fs.existsSync(defenderPath)) {
          execSync(`"${defenderPath}" -Scan -ScanType 2`, { timeout: 300000 });
        }
      } catch { /* exits non-zero when threats found — ok */ }

      // 2. Pull all Defender detections via PowerShell
      try {
        const out = execSync(
          `powershell -NoProfile -Command "Get-MpThreatDetection | Select-Object -Property ThreatName,Resources,SeverityID | ConvertTo-Json -Depth 3"`,
          { encoding: "utf-8", timeout: 20000 }
        ) as string;
        if (out && out.trim()) {
          const parsed = JSON.parse(out.startsWith("[") ? out : `[${out}]`) as Array<{
            ThreatName?: string; Resources?: string | string[]; SeverityID?: number;
          }>;
          for (const t of parsed) {
            const resources = Array.isArray(t.Resources) ? t.Resources : [t.Resources ?? ""];
            for (const res of resources) {
              const sev: ThreatItem["severity"] = (t.SeverityID ?? 0) >= 5 ? "critical" : (t.SeverityID ?? 0) >= 4 ? "high" : (t.SeverityID ?? 0) >= 2 ? "medium" : "low";
              if (!allThreats.some(x => x.path === res)) {
                allThreats.push({ path: res, name: t.ThreatName ?? "Unknown threat", severity: sev, description: "Detected by Windows Defender" });
              }
            }
          }
        }
      } catch { /* no detections or PS unavailable */ }

      // 3. Deep pattern scan across all user + system dirs
      const home = os.homedir();
      const winDirs = [
        { dir: path.join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), depth: 2 },
        { dir: path.join(home, "AppData", "Roaming"),   depth: 4 },
        { dir: path.join(home, "AppData", "Local"),     depth: 4 },
        { dir: path.join(home, "AppData", "LocalLow"),  depth: 3 },
        { dir: path.join(home, "Downloads"),            depth: 3 },
        { dir: path.join(home, "Desktop"),              depth: 2 },
        { dir: "C:\\ProgramData",                       depth: 3 },
        { dir: "C:\\Program Files",                     depth: 3 },
        { dir: "C:\\Program Files (x86)",               depth: 3 },
        { dir: "C:\\Windows\\Temp",                     depth: 2 },
        { dir: path.join(home, "AppData", "Local", "Temp"), depth: 3 },
      ];
      for (const { dir, depth } of winDirs) {
        if (!fs.existsSync(dir)) continue;
        const { threats, scanned } = scanDirForThreats(dir, WIN_THREAT_PATTERNS, depth, 3000);
        for (const t of threats) {
          if (!allThreats.some(x => x.path === t.path)) allThreats.push(t);
        }
        totalScanned += scanned;
      }

      // 4. Check run registry keys via PowerShell
      try {
        const regOut = execSync(
          `powershell -NoProfile -Command "Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' | ConvertTo-Json -Depth 2"`,
          { encoding: "utf-8", timeout: 10000 }
        ) as string;
        if (regOut && regOut.trim()) {
          const regMap = JSON.parse(regOut) as Record<string, string>;
          for (const [key, val] of Object.entries(regMap)) {
            if (typeof val !== "string" || key.startsWith("PS")) continue;
            totalScanned++;
            for (const t of WIN_THREAT_PATTERNS) {
              if (t.pattern.test(key) || t.pattern.test(val)) {
                if (!allThreats.some(x => x.path === val)) {
                  allThreats.push({ path: val, name: t.name, severity: t.severity, description: `Registry startup entry: ${t.desc}` });
                }
                break;
              }
            }
          }
        }
      } catch { /* skip */ }

      return {
        status: allThreats.length > 0 ? "threats_found" : "clean",
        threats: allThreats,
        scannedCount: totalScanned,
        scanDuration: Date.now() - start,
      };
    }

    return { status: "clean", threats: [], scannedCount: 0, scanDuration: Date.now() - start };

  } catch (e: unknown) {
    return {
      status: "error",
      threats: [],
      scannedCount: 0,
      scanDuration: Date.now() - start,
      error: String(e),
    };
  }
}

export function cleanPaths(
  ids: string[],
  scanResults: ScanResult[]
): { freedMb: number; errors: string[] } {
  const errors: string[] = [];
  let freedMb = 0;

  const toClean = scanResults.filter((r) => ids.includes(r.id));

  for (const item of toClean) {
    try {
      if (!fs.existsSync(item.path)) continue;
      const stat = fs.statSync(item.path);
      if (stat.isDirectory()) {
        const entries = fs.readdirSync(item.path);
        for (const entry of entries) {
          const fullPath = path.join(item.path, entry);
          try {
            fs.rmSync(fullPath, { recursive: true, force: true });
          } catch (e) {
            errors.push(`Could not delete ${fullPath}: ${String(e)}`);
          }
        }
      } else {
        fs.rmSync(item.path, { force: true });
      }
      freedMb += item.sizeMb;
    } catch (e) {
      errors.push(`Could not clean ${item.name}: ${String(e)}`);
    }
  }

  return { freedMb, errors };
}
