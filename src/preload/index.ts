import { contextBridge, ipcRenderer } from "electron";

export type ScanResult = {
  id: string;
  name: string;
  category: string;
  path: string;
  sizeMb: number;
  fileCount: number;
  safe: boolean;
};

export type SystemStats = {
  platform: string;
  cpuPercent: number;
  ramUsedGb: number;
  ramTotalGb: number;
  diskUsedGb: number;
  diskTotalGb: number;
};

export type CleanResult = {
  freedMb: number;
  errors: string[];
};

export type AppInfo = {
  name: string;
  appPath: string;
  bundleId: string;
  sizeMb: number;
  associatedPaths: string[];
  associatedSizeMb: number;
};

export type DiskHealth = {
  smartStatus: string;
  volumeName: string;
  fileSystem: string;
  totalGb: number;
  freeGb: number;
  brokenSymlinks: string[];
};

contextBridge.exposeInMainWorld("cleaner", {
  platform: process.platform,
  scan: (): Promise<ScanResult[]> => ipcRenderer.invoke("scan"),
  clean: (ids: string[]): Promise<CleanResult> => ipcRenderer.invoke("clean", ids),
  getStats: (): Promise<SystemStats> => ipcRenderer.invoke("get-stats"),
  openPath: (path: string): Promise<void> => ipcRenderer.invoke("open-path", path),
  scanApps: (): Promise<AppInfo[]> => ipcRenderer.invoke("scan-apps"),
  uninstallApp: (appPath: string, associatedPaths: string[]): Promise<CleanResult> =>
    ipcRenderer.invoke("uninstall-app", appPath, associatedPaths),
  diskHealth: (): Promise<DiskHealth> => ipcRenderer.invoke("disk-health"),
  verifyDisk: (): Promise<string> => ipcRenderer.invoke("verify-disk"),
  fixSymlinks: (paths: string[]): Promise<{ fixed: number; errors: string[] }> =>
    ipcRenderer.invoke("fix-symlinks", paths),
});
