import { app, BrowserWindow, ipcMain, shell } from "electron";
import * as path from "path";
import * as os from "os";
import * as fs from "fs";
import { scanSystem, cleanPaths, scanApps, getSizeOf, getDiskHealth, verifyDiskVolume, virusScan, checkFullDiskAccess, ScanResult, AppInfo } from "./scanner";

let scanCache: ScanResult[] = [];
let appCache: AppInfo[] = [];

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

ipcMain.handle("scan", async () => {
  scanCache = scanSystem();
  return scanCache;
});

ipcMain.handle("clean", async (_event, ids: string[]) => {
  const result = cleanPaths(ids, scanCache);
  // refresh cache after cleaning
  scanCache = scanSystem();
  return result;
});

ipcMain.handle("get-stats", async () => {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();

  // simple cpu idle estimate
  let idle = 0;
  let total = 0;
  for (const cpu of cpus) {
    idle += cpu.times.idle;
    total += Object.values(cpu.times).reduce((a, b) => a + b, 0);
  }
  const cpuPercent = Math.round((1 - idle / total) * 100);

  // disk usage via df on mac/linux, wmic on windows
  let diskUsedGb = 0;
  let diskTotalGb = 0;
  try {
    if (process.platform === "win32") {
      const { execSync } = await import("child_process");
      const out = execSync('wmic logicaldisk get size,freespace,caption /format:csv')
        .toString()
        .trim()
        .split("\n");
      for (const line of out) {
        const parts = line.split(",");
        if (parts.length >= 4 && parts[1] === "C:") {
          const free = parseFloat(parts[2]);
          const size = parseFloat(parts[3]);
          if (!isNaN(free) && !isNaN(size) && size > 0) {
            diskTotalGb = size / 1e9;
            diskUsedGb = (size - free) / 1e9;
          }
        }
      }
    } else {
      const { execSync } = await import("child_process");
      const out = execSync("df -k /").toString().split("\n")[1].trim().split(/\s+/);
      diskTotalGb = (parseInt(out[1]) * 1024) / 1e9;
      diskUsedGb = (parseInt(out[2]) * 1024) / 1e9;
    }
  } catch {
    // fallback
    diskTotalGb = 500;
    diskUsedGb = 250;
  }

  return {
    platform: process.platform,
    cpuPercent,
    ramUsedGb: (totalMem - freeMem) / 1e9,
    ramTotalGb: totalMem / 1e9,
    diskUsedGb,
    diskTotalGb,
  };
});

ipcMain.handle("open-path", async (_event, p: string) => {
  if (fs.existsSync(p)) shell.showItemInFolder(p);
});

ipcMain.handle("scan-apps", async () => {
  appCache = scanApps();
  return appCache;
});

ipcMain.handle("disk-health", async () => {
  return getDiskHealth();
});

ipcMain.handle("verify-disk", async () => {
  return verifyDiskVolume();
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

ipcMain.handle("virus-scan", async () => {
  return virusScan();
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

ipcMain.handle("uninstall-app", async (_event, appPath: string, associatedPaths: string[]) => {
  const errors: string[] = [];
  let freedMb = 0;
  for (const p of [appPath, ...associatedPaths]) {
    try {
      if (!fs.existsSync(p)) continue;
      freedMb += getSizeOf(p);
      await shell.trashItem(p);
    } catch (e) {
      errors.push(`Could not trash ${path.basename(p)}: ${String(e)}`);
    }
  }
  return { freedMb, errors };
});
