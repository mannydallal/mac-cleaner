import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as crypto from "crypto";
import { promisify } from "util";
import { exec, spawn } from "child_process";
const execAsync = promisify(exec);

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

async function getFolderSize(dirPath: string): Promise<{ sizeMb: number; fileCount: number }> {
  let totalBytes = 0;
  let fileCount = 0;
  try {
    const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      try {
        if (entry.isSymbolicLink()) continue;
        if (entry.isFile()) {
          const stat = await fs.promises.stat(fullPath);
          totalBytes += stat.size;
          fileCount++;
        } else if (entry.isDirectory()) {
          const sub = await getFolderSize(fullPath);
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
    id: "mac-parallels-public",
    name: "Parallels VMs (Public/Share)",
    category: "Parallels",
    rawPath: "~/Public/Share/Parallels",
    safe: false,
    platforms: ["darwin"],
  },
  {
    id: "mac-parallels-docs",
    name: "Parallels VMs (Documents)",
    category: "Parallels",
    rawPath: "~/Documents/Parallels",
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
  {
    id: "win-firefox-cache",
    name: "Firefox Cache",
    category: "Browser Junk",
    rawPath: "%APPDATA%\\Mozilla\\Firefox\\Profiles",
    safe: true,
    platforms: ["win32"],
  },
  {
    id: "win-update-cache",
    name: "Windows Update Cache",
    category: "System Junk",
    rawPath: "C:\\Windows\\SoftwareDistribution\\Download",
    safe: true,
    platforms: ["win32"],
  },
  {
    id: "win-error-reports",
    name: "Windows Error Reports",
    category: "System Junk",
    rawPath: "%LOCALAPPDATA%\\Microsoft\\Windows\\WER",
    safe: true,
    platforms: ["win32"],
  },
  {
    id: "win-delivery-opt",
    name: "Delivery Optimization Cache",
    category: "System Junk",
    rawPath: "C:\\Windows\\SoftwareDistribution\\DeliveryOptimization",
    safe: true,
    platforms: ["win32"],
  },
  {
    id: "win-crash-dumps",
    name: "Crash Dumps",
    category: "System Junk",
    rawPath: "%LOCALAPPDATA%\\CrashDumps",
    safe: true,
    platforms: ["win32"],
  },
];

export function checkFullDiskAccess(): boolean {
  try {
    const cachesPath = path.join(os.homedir(), "Library", "Caches");
    const entries = fs.readdirSync(cachesPath);
    return entries.length > 0;
  } catch {
    return false;
  }
}

// ── External drive junk patterns ──────────────────────────────────────────────

const EXTERNAL_JUNK_PATTERNS: { name: string; relPath: string; safe: boolean }[] = [
  { name: "Spotlight Index",     relPath: ".Spotlight-V100",    safe: true  },
  { name: "File System Events",  relPath: ".fseventsd",         safe: true  },
  { name: "Drive Trash",         relPath: ".Trashes",           safe: true  },
  { name: "Temporary Items",     relPath: ".TemporaryItems",    safe: true  },
  { name: "Volume Cache",        relPath: ".vol",               safe: true  },
];

export type ExternalVolume = {
  name: string;
  path: string;
  totalGb: number;
  freeGb: number;
};

export type MountedVolumesResult = {
  volumes: ExternalVolume[];
  error?: string;
};

export async function listMountedVolumes(): Promise<MountedVolumesResult> {
  const results: ExternalVolume[] = [];

  if (process.platform === "darwin") {
    try {
      const volumes = await fs.promises.readdir("/Volumes", { withFileTypes: true });
      for (const vol of volumes) {
        const volPath = path.join("/Volumes", vol.name);
        try {
          const resolved = fs.realpathSync(volPath);
          if (resolved === "/") continue;
        } catch { continue; }
        try {
          const { stdout } = await execAsync(`df -k "${volPath}" 2>/dev/null | tail -1`);
          const parts = stdout.trim().split(/\s+/);
          const totalKb = parseInt(parts[1] ?? "0", 10);
          const freeKb  = parseInt(parts[3] ?? "0", 10);
          results.push({ name: vol.name, path: volPath, totalGb: totalKb / 1024 / 1024, freeGb: freeKb / 1024 / 1024 });
        } catch {
          results.push({ name: vol.name, path: volPath, totalGb: 0, freeGb: 0 });
        }
      }
    } catch { /* /Volumes not accessible */ }
    return { volumes: results };
  } else if (process.platform === "win32") {
    try {
      // wmic logicaldisk: DriveType 2=Removable, 3=Fixed (skip C:)
      const { stdout } = await execAsync("wmic logicaldisk get DeviceID,DriveType,Size,FreeSpace /format:csv");
      for (const line of stdout.split("\n")) {
        const cols = line.trim().split(",");
        if (cols.length < 5) continue;
        const [, deviceId, driveType, freeSpace, size] = cols;
        const dt = parseInt(driveType ?? "", 10);
        if (!deviceId || isNaN(dt)) continue;
        // Include removable (2) and fixed non-C: drives (3)
        if (dt !== 2 && !(dt === 3 && deviceId.toUpperCase() !== "C:")) continue;
        const totalGb = parseInt(size ?? "0", 10) / 1024 / 1024 / 1024;
        const freeGb  = parseInt(freeSpace ?? "0", 10) / 1024 / 1024 / 1024;
        results.push({ name: deviceId, path: deviceId + "\\", totalGb, freeGb });
      }
      return { volumes: results };
    } catch {
      return {
        volumes: [],
        error: "Could not detect drives — wmic may be restricted by Group Policy. Try running as administrator.",
      };
    }
  }
  return { volumes: results };
}

const WINDOWS_EXTERNAL_JUNK: { name: string; relPath: string; safe: boolean }[] = [
  { name: "Recycle Bin",            relPath: "$RECYCLE.BIN",            safe: false },
  { name: "System Volume Info",     relPath: "System Volume Information", safe: true },
  { name: "Spotlight Index",        relPath: ".Spotlight-V100",          safe: true },
  { name: "Temporary Items",        relPath: "FOUND.000",                safe: true },
];

export async function scanExternalDrives(): Promise<ScanResult[]> {
  const results: ScanResult[] = [];

  if (process.platform === "win32") {
    const { volumes } = await listMountedVolumes();
    for (const vol of volumes) {
      for (const pattern of WINDOWS_EXTERNAL_JUNK) {
        const junkPath = path.join(vol.path, pattern.relPath);
        if (!fs.existsSync(junkPath)) continue;
        const { sizeMb, fileCount } = await getFolderSize(junkPath);
        if (sizeMb < 0.001) continue;
        results.push({
          id: `ext-${vol.name}-${pattern.relPath}`,
          name: `${pattern.name} (${vol.name})`,
          category: "External Drives",
          path: junkPath,
          sizeMb,
          fileCount,
          safe: pattern.safe,
        });
      }
    }
    return results.sort((a, b) => b.sizeMb - a.sizeMb);
  }

  if (process.platform !== "darwin") return [];

  try {
    const volumes = await fs.promises.readdir("/Volumes", { withFileTypes: true });
    for (const vol of volumes) {
      const volPath = path.join("/Volumes", vol.name);
      try {
        // Skip the root volume (symlink → /)
        const resolved = fs.realpathSync(volPath);
        if (resolved === "/") continue;
      } catch { continue; }

      for (const pattern of EXTERNAL_JUNK_PATTERNS) {
        const junkPath = path.join(volPath, pattern.relPath);
        if (!fs.existsSync(junkPath)) continue;
        const { sizeMb, fileCount } = await getFolderSize(junkPath);
        if (sizeMb < 0.001) continue;
        results.push({
          id: `ext-${vol.name}-${pattern.relPath}`,
          name: `${pattern.name} (${vol.name})`,
          category: "External Drives",
          path: junkPath,
          sizeMb,
          fileCount,
          safe: pattern.safe,
        });
      }
    }
  } catch { /* /Volumes not accessible */ }

  return results.sort((a, b) => b.sizeMb - a.sizeMb);
}

export async function scanSystem(
  onProgress?: (scanned: number, total: number, currentName: string) => void
): Promise<ScanResult[]> {
  const platform = process.platform as "darwin" | "win32" | "linux";
  const results: ScanResult[] = [];

  const targets = SCAN_TARGETS.filter((t) => t.platforms.includes(platform));
  const total = targets.length;

  for (let i = 0; i < targets.length; i++) {
    const target = targets[i];
    onProgress?.(i, total, target.name);
    const expanded = expandPath(target.rawPath);
    if (!fs.existsSync(expanded)) continue;
    const { sizeMb, fileCount } = await getFolderSize(expanded);
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
  onProgress?.(total, total, "External drives");

  // Include external drive junk in the full scan
  results.push(...await scanExternalDrives());

  return results.sort((a, b) => b.sizeMb - a.sizeMb);
}

// ── Parallels info ────────────────────────────────────────────────────────────

export type ParallelsInfo = {
  installed: boolean;
  version: string;
  vms: { name: string; sizeMb: number }[];
  totalVmSizeMb: number;
};

export async function getParallelsInfo(): Promise<ParallelsInfo> {
  const home = os.homedir();
  const appPath = "/Applications/Parallels Desktop.app/Contents/Info.plist";
  let version = "";

  if (fs.existsSync(appPath)) {
    try {
      const plist = await fs.promises.readFile(appPath, "utf-8");
      const short = plist.match(/<key>CFBundleShortVersionString<\/key>\s*<string>([^<]+)<\/string>/);
      const bundle = plist.match(/<key>CFBundleVersion<\/key>\s*<string>([^<]+)<\/string>/);
      if (short) version = short[1].trim();
      else if (bundle) version = bundle[1].trim();
    } catch { /* skip */ }
  }

  const vmsDirs = [
    path.join(home, "Parallels"),
    path.join(home, "Public", "Share", "Parallels"),
    path.join(home, "Documents", "Parallels"),
  ];
  const vms: { name: string; sizeMb: number }[] = [];
  const seenNames = new Set<string>();

  for (const vmsDir of vmsDirs) {
    if (!fs.existsSync(vmsDir)) continue;
    try {
      const entries = await fs.promises.readdir(vmsDir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.name.endsWith(".pvm")) continue;
        if (seenNames.has(entry.name)) continue;
        seenNames.add(entry.name);
        const vmPath = path.join(vmsDir, entry.name);
        const { sizeMb } = await getFolderSize(vmPath);
        vms.push({ name: entry.name.replace(/\.pvm$/, ""), sizeMb });
      }
    } catch { /* skip */ }
  }

  vms.sort((a, b) => b.sizeMb - a.sizeMb);
  const totalVmSizeMb = vms.reduce((s, v) => s + v.sizeMb, 0);
  const installed = !!version || vms.length > 0;

  return { installed, version, vms, totalVmSizeMb };
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

async function getAppBundleId(appPath: string): Promise<string> {
  try {
    const plistPath = path.join(appPath, "Contents", "Info.plist");
    const content = await fs.promises.readFile(plistPath, "utf-8");
    const match = content.match(/<key>CFBundleIdentifier<\/key>\s*<string>([^<]+)<\/string>/);
    return match?.[1] ?? "";
  } catch {
    return "";
  }
}

async function findAssociatedPaths(cleanName: string, bundleId: string): Promise<string[]> {
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
    const prefs = (await fs.promises.readdir(prefsDir)).filter(
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

async function getDuSizeMb(targetPath: string): Promise<number> {
  try {
    const { stdout } = await execAsync(`du -sk "${targetPath}" 2>/dev/null`);
    const kb = parseInt(stdout.trim().split(/\s+/)[0] ?? "0", 10);
    return isNaN(kb) ? 0 : kb / 1024;
  } catch {
    return 0;
  }
}

async function getWinDirSizeMb(targetPath: string): Promise<number> {
  try {
    const { stdout } = await execAsync(
      `powershell -NoProfile -Command "(Get-ChildItem -Path '${targetPath}' -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum"`,
    );
    const bytes = parseInt(stdout.trim(), 10);
    return isNaN(bytes) ? 0 : bytes / (1024 * 1024);
  } catch {
    return 0;
  }
}

export async function scanApps(
  onProgress?: (scanned: number, total: number, currentName: string) => void,
): Promise<AppInfo[]> {
  const results: AppInfo[] = [];

  if (process.platform === "darwin") {
    // Collect .app entries from both /Applications and ~/Applications
    const appsDirs = ["/Applications", path.join(os.homedir(), "Applications")];
    const allEntries: { name: string; appPath: string }[] = [];
    for (const appsDir of appsDirs) {
      try {
        const entries = (await fs.promises.readdir(appsDir, { withFileTypes: true }))
          .filter(e => e.name.endsWith(".app"));
        for (const e of entries) {
          allEntries.push({ name: e.name, appPath: path.join(appsDir, e.name) });
        }
      } catch { /* dir doesn't exist or inaccessible */ }
    }

    const total = allEntries.length;
    let scanned = 0;
    for (const { name, appPath } of allEntries) {
      const cleanName = name.replace(/\.app$/, "");
      onProgress?.(scanned, total, cleanName);
      const bundleId = await getAppBundleId(appPath);
      // Use du -sk — 50-100x faster than recursive JS walk for large app bundles
      const sizeMb = await getDuSizeMb(appPath);
      const associatedPaths = await findAssociatedPaths(cleanName, bundleId);
      let associatedSizeMb = 0;
      for (const p of associatedPaths) {
        associatedSizeMb += await getDuSizeMb(p);
      }
      results.push({ name: cleanName, appPath, bundleId, sizeMb, associatedPaths, associatedSizeMb });
      scanned++;
      onProgress?.(scanned, total, cleanName);
    }
  } else if (process.platform === "win32") {
    const dirs = [
      "C:\\Program Files",
      "C:\\Program Files (x86)",
      path.join(os.homedir(), "AppData", "Local", "Programs"),
    ];
    const allEntries: { name: string; appPath: string }[] = [];
    for (const dir of dirs) {
      try {
        const entries = await fs.promises.readdir(dir, { withFileTypes: true });
        for (const entry of entries) {
          if (!entry.isDirectory()) continue;
          allEntries.push({ name: entry.name, appPath: path.join(dir, entry.name) });
        }
      } catch { /* skip */ }
    }
    const total = allEntries.length;
    let scanned = 0;
    for (const { name, appPath } of allEntries) {
      onProgress?.(scanned, total, name);
      const sizeMb = await getWinDirSizeMb(appPath);
      results.push({ name, appPath, bundleId: "", sizeMb, associatedPaths: [], associatedSizeMb: 0 });
      scanned++;
      onProgress?.(scanned, total, name);
    }
  }

  return results.sort((a, b) => (b.sizeMb + b.associatedSizeMb) - (a.sizeMb + a.associatedSizeMb));
}

export async function getSizeOf(p: string): Promise<number> {
  try { return (await getFolderSize(p)).sizeMb; } catch { return 0; }
}

// ── Disk health ───────────────────────────────────────────────────────────────

export type DiskHealth = {
  smartStatus: string;
  volumeName: string;
  fileSystem: string;
  totalGb: number;
  freeGb: number;
  brokenSymlinks: string[];
  error?: string;
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

export async function getDiskHealth(): Promise<DiskHealth> {
  let smartStatus = "Unknown";
  let volumeName = "";
  let fileSystem = "";
  let totalGb = 0;
  let freeGb = 0;

  if (process.platform === "darwin") {
    // ── Mac: diskutil ──────────────────────────────────────────
    try {
      const { stdout } = await execAsync("diskutil info /", { timeout: 8000 });
      const smart  = stdout.match(/S\.M\.A\.R\.T\. Status:\s*(.+)/);
      const vol    = stdout.match(/Volume Name:\s*(.+)/);
      const fsLine = stdout.match(/Type \(Bundle\):\s*(.+)/);
      if (smart)  smartStatus = smart[1].trim();
      if (vol)    volumeName  = vol[1].trim();
      if (fsLine) fileSystem  = fsLine[1].trim();
    } catch { /* skip */ }

    try {
      const { stdout } = await execAsync("df -k /");
      const df = stdout.split("\n")[1].trim().split(/\s+/);
      totalGb = (parseInt(df[1]) * 1024) / 1e9;
      freeGb  = (parseInt(df[3]) * 1024) / 1e9;
    } catch { /* skip */ }

  } else if (process.platform === "win32") {
    // ── Windows: wmic ──────────────────────────────────────────
    let wmicSmartFailed = false;
    let wmicVolumeFailed = false;

    // SMART status
    try {
      const { stdout } = await execAsync("wmic diskdrive get status /value", { timeout: 10000 });
      const match = stdout.match(/Status=(\w+)/i);
      smartStatus = match ? (match[1] === "OK" ? "Verified" : match[1]) : "Unknown";
    } catch {
      wmicSmartFailed = true;
    }

    // Volume info for C:
    try {
      const { stdout } = await execAsync(
        'wmic logicaldisk where DeviceID="C:" get Size,FreeSpace,FileSystem,VolumeName /value',
        { timeout: 10000 }
      );
      const fsMatch   = stdout.match(/FileSystem=(\w+)/i);
      const freeMatch = stdout.match(/FreeSpace=(\d+)/i);
      const sizeMatch = stdout.match(/Size=(\d+)/i);
      const nameMatch = stdout.match(/VolumeName=([^\r\n]+)/i);
      if (fsMatch)   fileSystem = fsMatch[1];
      volumeName  = nameMatch?.[1]?.trim() || "Local Disk (C:)";
      if (sizeMatch) totalGb = parseInt(sizeMatch[1]) / 1e9;
      if (freeMatch) freeGb  = parseInt(freeMatch[1]) / 1e9;
      if (!sizeMatch && !freeMatch) wmicVolumeFailed = true;
    } catch {
      wmicVolumeFailed = true;
    }

    if (wmicSmartFailed && wmicVolumeFailed) {
      return {
        smartStatus: "Unknown",
        volumeName: "Local Disk (C:)",
        fileSystem: "Unknown",
        totalGb: 0,
        freeGb: 0,
        brokenSymlinks: [],
        error: "Could not read disk info — wmic may be restricted by Group Policy. Try running as administrator.",
      };
    }
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

export function verifyDiskVolume(onProgress?: (line: string) => void): Promise<string> {
  return new Promise((resolve) => {
    let cmd: string;
    let args: string[];

    if (process.platform === "darwin") {
      cmd = "diskutil";
      args = ["verifyVolume", "/"];
    } else if (process.platform === "win32") {
      // chkdsk C: with no flags = read-only check, no admin required
      cmd = "chkdsk";
      args = ["C:"];
    } else {
      resolve("Disk verification is not supported on this platform.");
      return;
    }

    const child = spawn(cmd, args);
    const chunks: string[] = [];

    const handleData = (data: Buffer) => {
      const text = data.toString();
      chunks.push(text);
      if (onProgress) {
        for (const line of text.split(/\r?\n/).filter(Boolean)) {
          onProgress(line);
        }
      }
    };

    child.stdout.on("data", handleData);
    child.stderr.on("data", handleData);

    const timer = setTimeout(() => {
      child.kill();
      resolve(chunks.join("") || "Disk verification timed out.");
    }, 120000);

    child.on("close", () => {
      clearTimeout(timer);
      resolve(chunks.join(""));
    });

    child.on("error", (err) => {
      clearTimeout(timer);
      resolve(err.message);
    });
  });
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

async function scanDirForThreats(
  dir: string,
  patterns: { pattern: RegExp; name: string; severity: ThreatItem["severity"]; desc: string }[],
  depth = 1,
  maxFiles = 500,
): Promise<{ threats: ThreatItem[]; scanned: number }> {
  const threats: ThreatItem[] = [];
  let scanned = 0;
  async function walk(d: string, level: number) {
    if (level > depth || scanned >= maxFiles) return;
    let entries: fs.Dirent[];
    try { entries = await fs.promises.readdir(d, { withFileTypes: true }); } catch { return; }
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
      if (e.isDirectory() && level < depth) await walk(full, level + 1);
    }
  }
  await walk(dir, 0);
  return { threats, scanned };
}

export async function virusScan(
  onProgress?: (msg: string, scanned: number) => void
): Promise<VirusScanResult> {
  const start = Date.now();

  try {
    if (process.platform === "darwin") {
      // ── Mac: deep multi-pass scan ─────────────────────────────
      const home = os.homedir();
      const allThreats: ThreatItem[] = [];
      let totalScanned = 0;

      // Pass 1: persistence locations (deep)
      onProgress?.("Checking launch agents and startup items…", totalScanned);
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
        const { threats, scanned } = await scanDirForThreats(dir, MAC_THREAT_PATTERNS, depth, 2000);
        allThreats.push(...threats);
        totalScanned += scanned;
      }

      // Pass 2: Applications + user dirs (broad)
      onProgress?.("Scanning applications and user directories…", totalScanned);
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
        const { threats, scanned } = await scanDirForThreats(dir, MAC_THREAT_PATTERNS, depth, 2000);
        allThreats.push(...threats);
        totalScanned += scanned;
        onProgress?.(`Scanning ${path.basename(dir)}…`, totalScanned);
      }

      // Pass 3: mdfind bundle ID sweep (covers all mounted volumes)
      onProgress?.("Running bundle ID sweep across all volumes…", totalScanned);
      const knownBundles = [
        "com.genieo", "com.vsearch", "com.pirrit", "com.babylon", "com.conduit",
        "com.searchmine", "com.weknow", "com.adload", "com.bundlore", "com.shlayer",
        "com.installcore", "com.crossrider", "com.tapufind", "com.dnsping",
      ];
      for (const bundleId of knownBundles) {
        try {
          const { stdout } = await execAsync(
            `mdfind "kMDItemCFBundleIdentifier == '*${bundleId}*'"`,
            { timeout: 8000 }
          );
          for (const line of stdout.split("\n").filter(Boolean)) {
            totalScanned++;
            if (!allThreats.some(t => t.path === line)) {
              const match = MAC_THREAT_PATTERNS.find(p => p.pattern.test(bundleId));
              if (match) allThreats.push({ path: line, name: match.name, severity: match.severity, description: match.desc });
            }
          }
        } catch { /* skip */ }
      }

      // Pass 4: find unsigned / suspicious executables in common drop paths
      onProgress?.("Checking for unsigned executables in Downloads and Desktop…", totalScanned);
      const dropPaths = [
        path.join(home, "Downloads"),
        path.join(home, "Desktop"),
        "/tmp",
        "/private/tmp",
      ];
      for (const dp of dropPaths) {
        if (!fs.existsSync(dp)) continue;
        try {
          const { stdout: out } = await execAsync(
            `find "${dp}" -maxdepth 3 -type f \\( -name "*.pkg" -o -name "*.dmg" -o -name "*.app" -o -perm +111 \\) 2>/dev/null | head -200`,
            { timeout: 15000 }
          );
          for (const fp of out.split("\n").filter(Boolean)) {
            totalScanned++;
            try {
              await execAsync(`codesign --verify --strict "${fp}" 2>&1`, { timeout: 3000 });
            } catch {
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
            if (totalScanned % 50 === 0) onProgress?.(`Checking executables… (${totalScanned} scanned)`, totalScanned);
          }
        } catch { /* skip */ }
      }

      // Pass 5: check login items via osascript
      onProgress?.("Checking login items…", totalScanned);
      try {
        const { stdout: items } = await execAsync(
          `osascript -e 'tell application "System Events" to get the path of every login item'`,
          { timeout: 8000 }
        );
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

      // 1. Run Windows Defender full scan (ScanType 2) — spawn so stdout streams as progress
      onProgress?.("Starting Windows Defender scan…", totalScanned);
      try {
        const defenderPath = "C:\\Program Files\\Windows Defender\\MpCmdRun.exe";
        if (fs.existsSync(defenderPath)) {
          await new Promise<void>((resolve) => {
            const child = spawn(defenderPath, ["-Scan", "-ScanType", "2"]);
            const handleData = (data: Buffer) => {
              const line = data.toString().trim();
              if (line) {
                totalScanned++;
                onProgress?.(line, totalScanned);
              }
            };
            child.stdout.on("data", handleData);
            child.stderr.on("data", handleData);
            const timer = setTimeout(() => { child.kill(); resolve(); }, 300000);
            child.on("close", () => { clearTimeout(timer); resolve(); });
            child.on("error", () => { clearTimeout(timer); resolve(); });
          });
        }
      } catch { /* exits non-zero when threats found — ok */ }

      // 2. Pull all Defender detections via PowerShell
      onProgress?.("Reading Windows Defender threat history…", totalScanned);
      try {
        const { stdout: out } = await execAsync(
          `powershell -NoProfile -Command "Get-MpThreatDetection | Select-Object -Property ThreatName,Resources,SeverityID | ConvertTo-Json -Depth 3"`,
          { timeout: 20000 }
        );
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
      onProgress?.("Scanning user and system directories for known threats…", totalScanned);
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
        onProgress?.(`Scanning ${dir}…`, totalScanned);
        const { threats, scanned } = await scanDirForThreats(dir, WIN_THREAT_PATTERNS, depth, 3000);
        for (const t of threats) {
          if (!allThreats.some(x => x.path === t.path)) allThreats.push(t);
        }
        totalScanned += scanned;
        onProgress?.(`Scanned ${dir}`, totalScanned);
      }

      // 4. Check run registry keys via PowerShell
      onProgress?.("Checking Windows startup registry entries…", totalScanned);
      try {
        const { stdout: regOut } = await execAsync(
          `powershell -NoProfile -Command "Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' | ConvertTo-Json -Depth 2"`,
          { timeout: 10000 }
        );
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

// ── Duplicate Finder ──────────────────────────────────────────────────────────

export type DuplicateFile = {
  path: string;
  name: string;
  sizeMb: number;
  modifiedAt: string;
};

export type DuplicateGroup = {
  hash: string;
  sizeMb: number;
  files: DuplicateFile[];
};

export type DuplicateScanResult = {
  groups: DuplicateGroup[];
  totalWasteMb: number;
  scannedCount: number;
};

async function hashFile(filePath: string): Promise<string | null> {
  try {
    const buf = await fs.promises.readFile(filePath);
    return crypto.createHash("sha256").update(buf).digest("hex");
  } catch {
    return null;
  }
}

async function walkDir(dir: string, maxDepth: number, depth = 0): Promise<string[]> {
  if (depth > maxDepth) return [];
  const results: string[] = [];
  try {
    const entries = await fs.promises.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith(".")) continue;
      const fullPath = path.join(dir, entry.name);
      try {
        if (entry.isSymbolicLink()) continue;
        if (entry.isFile()) {
          results.push(fullPath);
        } else if (entry.isDirectory()) {
          results.push(...await walkDir(fullPath, maxDepth, depth + 1));
        }
      } catch { /* skip */ }
    }
  } catch { /* skip */ }
  return results;
}

export async function findDuplicates(
  onProgress?: (scanned: number, total: number, phase: "walk" | "hash") => void
): Promise<DuplicateScanResult> {
  const home = os.homedir();
  const scanDirs = [
    path.join(home, "Desktop"),
    path.join(home, "Documents"),
    path.join(home, "Downloads"),
    path.join(home, "Pictures"),
    path.join(home, "Music"),
    path.join(home, "Movies"),
  ];

  const allFiles: string[] = [];
  for (const dir of scanDirs) {
    if (fs.existsSync(dir)) allFiles.push(...await walkDir(dir, 5));
  }

  // Pre-filter: group by file size (no hashing needed for unique sizes)
  const bySize = new Map<number, string[]>();
  for (let i = 0; i < allFiles.length; i++) {
    const filePath = allFiles[i];
    try {
      const stat = await fs.promises.stat(filePath);
      if (stat.size < 1024) continue; // skip files < 1 KB
      const group = bySize.get(stat.size) ?? [];
      group.push(filePath);
      bySize.set(stat.size, group);
    } catch { /* skip */ }
    if (onProgress && i % 200 === 0) onProgress(i, allFiles.length, "walk");
  }
  onProgress?.(allFiles.length, allFiles.length, "walk");

  // Collect candidates that need hashing
  const candidates: string[] = [];
  for (const [, files] of bySize.entries()) {
    if (files.length >= 2) candidates.push(...files);
  }

  // Hash only files that share a size with at least one other file
  const byHash = new Map<string, string[]>();
  for (let i = 0; i < candidates.length; i++) {
    const filePath = candidates[i];
    const hash = await hashFile(filePath);
    if (!hash) continue;
    const group = byHash.get(hash) ?? [];
    group.push(filePath);
    byHash.set(hash, group);
    if (onProgress && i % 50 === 0) onProgress(i, candidates.length, "hash");
  }
  onProgress?.(candidates.length, candidates.length, "hash");

  const groups: DuplicateGroup[] = [];
  let totalWasteMb = 0;

  for (const [hash, files] of byHash.entries()) {
    if (files.length < 2) continue;
    const fileInfos: DuplicateFile[] = await Promise.all(files.map(async filePath => {
      try {
        const stat = await fs.promises.stat(filePath);
        return {
          path: filePath,
          name: path.basename(filePath),
          sizeMb: stat.size / (1024 * 1024),
          modifiedAt: stat.mtime.toISOString(),
        };
      } catch {
        return { path: filePath, name: path.basename(filePath), sizeMb: 0, modifiedAt: "" };
      }
    }));
    // Newest first
    fileInfos.sort((a, b) => new Date(b.modifiedAt).getTime() - new Date(a.modifiedAt).getTime());
    const sizeMb = fileInfos[0]?.sizeMb ?? 0;
    totalWasteMb += sizeMb * (fileInfos.length - 1);
    groups.push({ hash, sizeMb, files: fileInfos });
  }

  // Biggest waste first
  groups.sort((a, b) => (b.sizeMb * (b.files.length - 1)) - (a.sizeMb * (a.files.length - 1)));

  return { groups, totalWasteMb, scannedCount: allFiles.length };
}

export function deleteDuplicateFiles(paths: string[]): { freedMb: number; errors: string[] } {
  const errors: string[] = [];
  let freedMb = 0;
  for (const filePath of paths) {
    try {
      if (!fs.existsSync(filePath)) continue;
      const stat = fs.statSync(filePath);
      freedMb += stat.size / (1024 * 1024);
      fs.unlinkSync(filePath);
    } catch (e) {
      errors.push(`Could not delete ${path.basename(filePath)}: ${String(e)}`);
    }
  }
  return { freedMb, errors };
}
