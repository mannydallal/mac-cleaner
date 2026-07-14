import { app, BrowserWindow, ipcMain, shell } from "electron";
import * as path from "path";
import * as os from "os";
import * as fs from "fs";
import { promisify } from "util";
import { exec } from "child_process";
import { scanSystem, cleanPaths, scanApps, scanAppsV2, getSizeOf, getDiskHealth, verifyDiskVolume, virusScan, checkFullDiskAccess, getParallelsInfo, listMountedVolumes, findDuplicates, deleteDuplicateFiles, scanUsbDrive, runSystemRepairs, ScanResult, AppInfo, AppInfoV2 } from "./scanner";

const execAsync = promisify(exec);

let scanCache: ScanResult[] = [];
let appCache: AppInfo[] = [];

// ── App-list disk cache ───────────────────────────────────────────────────────

type AppCacheFile = {
  timestamp: number;
  apps: AppInfo[];
};

function getAppCachePath(): string {
  return path.join(app.getPath("userData"), "app-cache.json");
}

function readAppCacheFile(): AppCacheFile | null {
  try {
    const raw = fs.readFileSync(getAppCachePath(), "utf-8");
    return JSON.parse(raw) as AppCacheFile;
  } catch {
    return null;
  }
}

function writeAppCacheFile(apps: AppInfo[]): void {
  try {
    const data: AppCacheFile = { timestamp: Date.now(), apps };
    fs.writeFileSync(getAppCachePath(), JSON.stringify(data), "utf-8");
  } catch {
    // ignore write errors silently
  }
}

function createWindow(): void {
  const win = new BrowserWindow({
    width: 1100,
    height: 720,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: "#EAF6EC",
    titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "default",
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  if (process.env["ELECTRON_RENDERER_URL"]) {
    win.loadURL(process.env["ELECTRON_RENDERER_URL"]);
  } else {
    win.loadFile(path.join(__dirname, "../renderer/index.html"));
  }
}

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

// ── IPC handlers ─────────────────────────────────────────────────────────────

ipcMain.handle("check-permission", async () => {
  return checkFullDiskAccess();
});

ipcMain.handle("list-external-volumes", async () => {
  const result = await listMountedVolumes();
  return result;
});

ipcMain.handle("get-parallels-info", async () => {
  return await getParallelsInfo();
});

ipcMain.handle("scan", async (event) => {
  scanCache = await scanSystem((scanned, total, currentName, found) => {
    event.sender.send("scan-progress", scanned, total, currentName, found);
  });
  return scanCache;
});

ipcMain.handle("clean", async (_event, ids: string[]) => {
  const result = cleanPaths(ids, scanCache);
  scanCache = await scanSystem();
  return result;
});

ipcMain.handle("get-stats", async () => {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();

  let idle = 0;
  let total = 0;
  for (const cpu of cpus) {
    idle += cpu.times.idle;
    total += Object.values(cpu.times).reduce((a, b) => a + b, 0);
  }
  const cpuPercent = Math.round((1 - idle / total) * 100);

  let diskUsedGb = 0;
  let diskTotalGb = 0;
  let diskError: string | undefined;
  try {
    if (process.platform === "win32") {
      const { stdout } = await execAsync("wmic logicaldisk get size,freespace,caption /format:csv");
      let found = false;
      for (const line of stdout.trim().split("\n")) {
        const parts = line.split(",");
        if (parts.length >= 4 && parts[1] === "C:") {
          const free = parseFloat(parts[2]);
          const size = parseFloat(parts[3]);
          if (!isNaN(free) && !isNaN(size) && size > 0) {
            diskTotalGb = size / 1e9;
            diskUsedGb = (size - free) / 1e9;
            found = true;
          }
        }
      }
      if (!found) {
        diskError = "Could not read disk info — try running as administrator";
      }
    } else {
      const { stdout } = await execAsync("df -k /");
      const out = stdout.split("\n")[1].trim().split(/\s+/);
      diskTotalGb = (parseInt(out[1]) * 1024) / 1e9;
      diskUsedGb = (parseInt(out[2]) * 1024) / 1e9;
    }
  } catch (err) {
    diskError = process.platform === "win32"
      ? "Could not read disk info — wmic may be restricted by Group Policy. Try running as administrator."
      : `Could not read disk info: ${String(err)}`;
  }

  return {
    platform: process.platform,
    cpuPercent,
    ramUsedGb: (totalMem - freeMem) / 1e9,
    ramTotalGb: totalMem / 1e9,
    diskUsedGb,
    diskTotalGb,
    diskError,
  };
});

ipcMain.handle("open-path", async (_event, p: string) => {
  if (fs.existsSync(p)) shell.showItemInFolder(p);
});

ipcMain.handle("get-cached-apps", async () => {
  return readAppCacheFile();
});

ipcMain.handle("scan-apps", async (event) => {
  appCache = await scanApps((scanned, total, currentName) => {
    event.sender.send("scan-apps-progress", scanned, total, currentName);
  });
  writeAppCacheFile(appCache);
  return appCache;
});

ipcMain.handle("disk-health", async (event) => {
  return await getDiskHealth((line) => {
    event.sender.send("disk-health-progress", line);
  });
});

ipcMain.handle("verify-disk", async (event) => {
  return await verifyDiskVolume((line) => {
    event.sender.send("verify-disk-progress", line);
  });
});

ipcMain.handle("fix-symlinks", async (_event, paths: string[]) => {
  const errors: string[] = [];
  let fixed = 0;
  for (const p of paths) {
    try {
      if (fs.existsSync(p) || fs.lstatSync(p).isSymbolicLink()) {
        fs.unlinkSync(p);
        fixed++;
      }
    } catch (e) {
      errors.push(`${path.basename(p)}: ${String(e)}`);
    }
  }
  return { fixed, errors };
});

ipcMain.handle("virus-scan", async (event) => {
  return await virusScan((msg, scanned) => {
    event.sender.send("virus-scan-progress", msg, scanned);
  });
});

ipcMain.handle("quarantine-threat", async (_event, threatPath: string) => {
  try {
    if (!fs.existsSync(threatPath) && !fs.lstatSync(threatPath).isSymbolicLink()) {
      return { ok: false, error: "File not found" };
    }
    await shell.trashItem(threatPath);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

ipcMain.handle("scan-duplicates", async (event) => {
  return await findDuplicates((scanned, total, phase) => {
    event.sender.send("scan-duplicates-progress", scanned, total, phase);
  });
});

ipcMain.handle("delete-duplicates", async (_event, paths: string[]) => {
  return deleteDuplicateFiles(paths);
});

ipcMain.handle("uninstall-app", async (_event, appPath: string, associatedPaths: string[]) => {
  const errors: string[] = [];
  let freedMb = 0;
  for (const p of [appPath, ...associatedPaths]) {
    try {
      if (!fs.existsSync(p)) continue;
      freedMb += await getSizeOf(p);
      await shell.trashItem(p);
    } catch (e) {
      errors.push(`Could not trash ${path.basename(p)}: ${String(e)}`);
    }
  }
  if (errors.length === 0) {
    const source = appCache.length > 0 ? appCache : (readAppCacheFile()?.apps ?? []);
    appCache = source.filter((a) => a.appPath !== appPath);
    writeAppCacheFile(appCache);
  }
  return { freedMb, errors };
});

ipcMain.handle("scan-apps-v2", async (event) => {
  return await scanAppsV2((scanned, total, currentName) => {
    event.sender.send("scan-apps-v2-progress", scanned, total, currentName);
  });
});

ipcMain.handle("uninstall-app-v2", async (_event, appInfo: AppInfoV2) => {
  if (process.platform === "win32") {
    const { uninstallString, quietUninstallString, isMsi, msiGuid, name } = appInfo;
    try {
      let cmd = "";
      if (isMsi && msiGuid) {
        cmd = `msiexec /x "${msiGuid}" /passive /norestart`;
      } else if (quietUninstallString) {
        cmd = quietUninstallString;
      } else if (uninstallString) {
        cmd = uninstallString;
        if (!/\/S\b|\/silent|\/quiet/i.test(cmd)) {
          if (/uninst|uninstall/i.test(cmd)) cmd += " /S";
        }
      } else {
        return { freedMb: 0, errors: [`No uninstaller found for ${name}`], method: "none" };
      }
      await execAsync(cmd, { timeout: 120000 });
      return { freedMb: appInfo.sizeMb, errors: [], method: "uninstaller" };
    } catch (e) {
      return { freedMb: 0, errors: [String(e)], method: "uninstaller" };
    }
  }

  if (process.platform === "linux") {
    const cmd = appInfo.quietUninstallString || appInfo.uninstallString;
    if (!cmd) {
      return { freedMb: 0, errors: [`No uninstall command found for ${appInfo.name}`], method: "none" };
    }
    try {
      await execAsync(cmd, { timeout: 120000 });
      return { freedMb: appInfo.sizeMb, errors: [], method: "linux-package-manager" };
    } catch (e) {
      return { freedMb: 0, errors: [String(e)], method: "linux-package-manager" };
    }
  }

  // Mac — always move to Trash (fully reversible)
  const errors: string[] = [];
  let freedMb = 0;
  for (const p of [appInfo.appPath, ...appInfo.associatedPaths]) {
    try {
      if (!fs.existsSync(p)) continue;
      freedMb += await getSizeOf(p);
      await shell.trashItem(p);
    } catch (e) {
      errors.push(`Could not move ${path.basename(p)} to Trash: ${String(e)}`);
    }
  }
  if (errors.length === 0) {
    const source = appCache.length > 0 ? appCache : (readAppCacheFile()?.apps ?? []);
    appCache = source.filter((a) => a.appPath !== appInfo.appPath);
    writeAppCacheFile(appCache);
  }
  return { freedMb, errors, method: "trash" };
});

ipcMain.handle("scan-usb-drive", async (_event, volPath: string) => {
  return await scanUsbDrive(volPath);
});

ipcMain.handle("run-system-repairs", async (event) => {
  return await runSystemRepairs((step) => {
    event.sender.send("repair-step", step);
  });
});

ipcMain.handle("clean-usb-junk", async (_event, paths: string[]) => {
  const errors: string[] = [];
  let freedMb = 0;
  for (const p of paths) {
    try {
      if (!fs.existsSync(p)) continue;
      freedMb += await getSizeOf(p);
      await shell.trashItem(p);
    } catch (e) {
      errors.push(`${path.basename(p)}: ${String(e)}`);
    }
  }
  return { freedMb, errors };
});
