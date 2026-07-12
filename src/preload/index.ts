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

export type ThreatItem = {
  path: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
};

export type VirusScanResult = {
  status: "clean" | "threats_found" | "error";
  threats: ThreatItem[];
  scannedCount: number;
  scanDuration: number;
  error?: string;
};

export type ExternalVolume = {
  name: string;
  path: string;
  totalGb: number;
  freeGb: number;
};

export type UsbDriveFolder = { name: string; path: string; sizeMb: number };
export type UsbDriveJunk   = { name: string; path: string; sizeMb: number; safe: boolean };
export type UsbDriveScanResult = {
  topFolders: UsbDriveFolder[];
  junkItems: UsbDriveJunk[];
  totalJunkMb: number;
};

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

export type AppInfoV2 = {
  name: string;
  appPath: string;
  bundleId: string;
  version: string;
  publisher: string;
  sizeMb: number;
  associatedPaths: string[];
  associatedSizeMb: number;
  uninstallString: string;
  quietUninstallString: string;
  isMsi: boolean;
  msiGuid: string;
  isSystemApp: boolean;
};

contextBridge.exposeInMainWorld("cleaner", {
  platform: process.platform,
  checkPermission: (): Promise<boolean> => ipcRenderer.invoke("check-permission"),
  getParallelsInfo: (): Promise<{ installed: boolean; version: string; vms: { name: string; sizeMb: number }[]; totalVmSizeMb: number }> =>
    ipcRenderer.invoke("get-parallels-info"),
  scan: (): Promise<ScanResult[]> => ipcRenderer.invoke("scan"),
  clean: (ids: string[]): Promise<CleanResult> => ipcRenderer.invoke("clean", ids),
  getStats: (): Promise<SystemStats> => ipcRenderer.invoke("get-stats"),
  openPath: (path: string): Promise<void> => ipcRenderer.invoke("open-path", path),
  getCachedApps: (): Promise<{ timestamp: number; apps: AppInfo[] } | null> =>
    ipcRenderer.invoke("get-cached-apps"),
  scanApps: (): Promise<AppInfo[]> => ipcRenderer.invoke("scan-apps"),
  uninstallApp: (appPath: string, associatedPaths: string[]): Promise<CleanResult> =>
    ipcRenderer.invoke("uninstall-app", appPath, associatedPaths),
  diskHealth: (): Promise<DiskHealth> => ipcRenderer.invoke("disk-health"),
  verifyDisk: (): Promise<string> => ipcRenderer.invoke("verify-disk"),
  fixSymlinks: (paths: string[]): Promise<{ fixed: number; errors: string[] }> =>
    ipcRenderer.invoke("fix-symlinks", paths),
  virusScan: (): Promise<VirusScanResult> => ipcRenderer.invoke("virus-scan"),
  quarantineThreat: (threatPath: string): Promise<{ ok: boolean; error?: string }> =>
    ipcRenderer.invoke("quarantine-threat", threatPath),
  listExternalVolumes: (): Promise<{ volumes: ExternalVolume[]; error?: string }> => ipcRenderer.invoke("list-external-volumes"),
  scanUsbDrive: (volPath: string): Promise<UsbDriveScanResult> => ipcRenderer.invoke("scan-usb-drive", volPath),
  cleanUsbJunk: (paths: string[]): Promise<{ freedMb: number; errors: string[] }> => ipcRenderer.invoke("clean-usb-junk", paths),
  scanDuplicates: (): Promise<DuplicateScanResult> => ipcRenderer.invoke("scan-duplicates"),
  deleteDuplicates: (paths: string[]): Promise<{ freedMb: number; errors: string[] }> =>
    ipcRenderer.invoke("delete-duplicates", paths),

  // ── Progress event listeners ────────────────────────────────────────────────
  onScanProgress: (cb: (scanned: number, total: number, currentName: string, found: number) => void) => {
    const handler = (_e: Electron.IpcRendererEvent, scanned: number, total: number, currentName: string, found: number) =>
      cb(scanned, total, currentName, found);
    ipcRenderer.on("scan-progress", handler);
    return () => ipcRenderer.off("scan-progress", handler);
  },
  onDiskHealthProgress: (cb: (line: string) => void) => {
    const handler = (_e: Electron.IpcRendererEvent, line: string) => cb(line);
    ipcRenderer.on("disk-health-progress", handler);
    return () => ipcRenderer.off("disk-health-progress", handler);
  },
  onVerifyDiskProgress: (cb: (line: string) => void) => {
    const handler = (_e: Electron.IpcRendererEvent, line: string) => cb(line);
    ipcRenderer.on("verify-disk-progress", handler);
    return () => ipcRenderer.off("verify-disk-progress", handler);
  },
  onVirusScanProgress: (cb: (msg: string, scanned: number) => void) => {
    const handler = (_e: Electron.IpcRendererEvent, msg: string, scanned: number) => cb(msg, scanned);
    ipcRenderer.on("virus-scan-progress", handler);
    return () => ipcRenderer.off("virus-scan-progress", handler);
  },
  onScanDuplicatesProgress: (cb: (scanned: number, total: number, phase: "walk" | "hash") => void) => {
    const handler = (_e: Electron.IpcRendererEvent, scanned: number, total: number, phase: "walk" | "hash") =>
      cb(scanned, total, phase);
    ipcRenderer.on("scan-duplicates-progress", handler);
    return () => ipcRenderer.off("scan-duplicates-progress", handler);
  },
  onScanAppsProgress: (cb: (scanned: number, total: number, currentName: string) => void) => {
    const handler = (_e: Electron.IpcRendererEvent, scanned: number, total: number, currentName: string) =>
      cb(scanned, total, currentName);
    ipcRenderer.on("scan-apps-progress", handler);
    return () => ipcRenderer.off("scan-apps-progress", handler);
  },

  // ── Uninstaller v2 ──────────────────────────────────────────────────────────
  scanAppsV2: (): Promise<AppInfoV2[]> => ipcRenderer.invoke("scan-apps-v2"),
  uninstallAppV2: (appInfo: AppInfoV2): Promise<{ freedMb: number; errors: string[]; method: string }> =>
    ipcRenderer.invoke("uninstall-app-v2", appInfo),
  onScanAppsV2Progress: (cb: (scanned: number, total: number, currentName: string) => void) => {
    const handler = (_e: Electron.IpcRendererEvent, scanned: number, total: number, currentName: string) =>
      cb(scanned, total, currentName);
    ipcRenderer.on("scan-apps-v2-progress", handler);
    return () => ipcRenderer.off("scan-apps-v2-progress", handler);
  },
});
