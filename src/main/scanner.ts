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
  // ── Mac ──────────────────────────────────────────────────────
  {
    id: "mac-user-cache",
    name: "User App Caches",
    category: "System Junk",
    rawPath: "~/Library/Caches",
    safe: true,
    platforms: ["darwin"],
  },
  {
    id: "mac-logs",
    name: "System Logs",
    category: "System Junk",
    rawPath: "~/Library/Logs",
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
    id: "mac-safari-cache",
    name: "Safari Cache",
    category: "Browser Junk",
    rawPath: "~/Library/Caches/com.apple.Safari",
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
    id: "mac-ios-backups",
    name: "iOS Device Backups",
    category: "Large Files",
    rawPath: "~/Library/Application Support/MobileSync/Backup",
    safe: false,
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
