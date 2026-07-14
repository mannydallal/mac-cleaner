import { useState, useEffect, useCallback } from "react";

// ── Types ─────────────────────────────────────────────────────────────────────

type ScanResult = {
  id: string;
  name: string;
  category: string;
  path: string;
  sizeMb: number;
  fileCount: number;
  safe: boolean;
};

type SystemStats = {
  platform: string;
  cpuPercent: number;
  ramUsedGb: number;
  ramTotalGb: number;
  diskUsedGb: number;
  diskTotalGb: number;
  diskError?: string;
};

type AppInfo = {
  name: string;
  appPath: string;
  bundleId: string;
  sizeMb: number;
  associatedPaths: string[];
  associatedSizeMb: number;
};

type AppInfoV2 = {
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

type DiskHealth = {
  smartStatus: string;
  volumeName: string;
  fileSystem: string;
  totalGb: number;
  freeGb: number;
  brokenSymlinks: string[];
  error?: string;
};

type ThreatItem = {
  path: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
};

type VirusScanResult = {
  status: "clean" | "threats_found" | "error";
  threats: ThreatItem[];
  scannedCount: number;
  scanDuration: number;
  error?: string;
};

type ExternalVolume = {
  name: string;
  path: string;
  totalGb: number;
  freeGb: number;
};

type UsbDriveFolder = { name: string; path: string; sizeMb: number };
type UsbDriveJunk   = { name: string; path: string; sizeMb: number; safe: boolean };
type UsbDriveScanResult = {
  topFolders: UsbDriveFolder[];
  junkItems: UsbDriveJunk[];
  totalJunkMb: number;
};

declare global {
  interface Window {
    cleaner: {
      platform: string;
      checkPermission: () => Promise<boolean>;
      getParallelsInfo: () => Promise<{ installed: boolean; version: string; vms: { name: string; sizeMb: number }[]; totalVmSizeMb: number }>;
      scan: () => Promise<ScanResult[]>;
      clean: (ids: string[]) => Promise<{ freedMb: number; errors: string[] }>;
      getStats: () => Promise<SystemStats>;
      openPath: (path: string) => Promise<void>;
      getCachedApps: () => Promise<{ timestamp: number; apps: AppInfo[] } | null>;
      scanApps: () => Promise<AppInfo[]>;
      uninstallApp: (appPath: string, associatedPaths: string[]) => Promise<{ freedMb: number; errors: string[] }>;
      diskHealth: () => Promise<DiskHealth>;
      verifyDisk: () => Promise<string>;
      fixSymlinks: (paths: string[]) => Promise<{ fixed: number; errors: string[] }>;
      virusScan: () => Promise<VirusScanResult>;
      quarantineThreat: (threatPath: string) => Promise<{ ok: boolean; error?: string }>;
      listExternalVolumes: () => Promise<{ volumes: ExternalVolume[]; error?: string }>;
      scanUsbDrive: (volPath: string) => Promise<UsbDriveScanResult>;
      cleanUsbJunk: (paths: string[]) => Promise<{ freedMb: number; errors: string[] }>;
      scanDuplicates: () => Promise<DuplicateScanResult>;
      deleteDuplicates: (paths: string[]) => Promise<{ freedMb: number; errors: string[] }>;
      onScanProgress: (cb: (scanned: number, total: number, currentName: string, found: number) => void) => () => void;
      onDiskHealthProgress?: (cb: (line: string) => void) => () => void;
      onVirusScanProgress: (cb: (msg: string, scanned: number) => void) => () => void;
      onScanDuplicatesProgress: (cb: (scanned: number, total: number, phase: "walk" | "hash") => void) => () => void;
      onScanAppsProgress: (cb: (scanned: number, total: number, currentName: string) => void) => () => void;
      scanAppsV2: () => Promise<AppInfoV2[]>;
      uninstallAppV2: (appInfo: AppInfoV2) => Promise<{ freedMb: number; errors: string[]; method: string }>;
      onScanAppsV2Progress: (cb: (scanned: number, total: number, currentName: string) => void) => () => void;
      runSystemRepairs: () => Promise<{ steps: RepairStep[]; fixedCount: number; errorCount: number }>;
      onRepairStep?: (cb: (step: RepairStep) => void) => () => void;
    };
  }
}

type RepairStep = {
  id: string;
  label: string;
  status: "pending" | "running" | "ok" | "warn" | "error" | "skipped";
  detail: string;
};

type DuplicateFile = {
  path: string;
  name: string;
  sizeMb: number;
  modifiedAt: string;
};

type DuplicateGroup = {
  hash: string;
  sizeMb: number;
  files: DuplicateFile[];
};

type DuplicateScanResult = {
  groups: DuplicateGroup[];
  totalWasteMb: number;
  scannedCount: number;
};

// ── Constants ─────────────────────────────────────────────────────────────────

const S = {
  bg: "#EAF6EC",
  bgGrad: "linear-gradient(145deg, #D8F0DC 0%, #EAF6EC 55%, #E0F5E4 100%)",
  sidebar: "rgba(210,238,215,0.98)",
  card: "rgba(255,255,255,0.88)",
  card2: "rgba(240,252,242,0.92)",
  border: "rgba(40,160,70,0.15)",
  text: "#142018",
  muted: "#4A7055",
  green: "#1A8C38",
  orange: "#C06800",
  blue: "#0060CC",
  red: "#C42020",
  purple: "#7030B0",
  teal: "#0078A0",
};

type Tab = "scan-all" | "smart" | "junk" | "privacy" | "parallels" | "external" | "uninstaller" | "uninstaller-v3" | "repair" | "virus" | "duplicates";

const NAV: { id: Tab; label: string; emoji: string; color: string }[] = [
  { id: "scan-all",       label: "Scan All",          emoji: "⚡", color: "#7030B0" },
  { id: "smart",          label: "Smart Scan",        emoji: "🔍", color: S.green  },
  { id: "junk",           label: "System Junk",       emoji: "🗑", color: S.orange },
  { id: "privacy",        label: "Privacy",           emoji: "🔒", color: S.blue   },
  { id: "duplicates",     label: "Duplicates",        emoji: "👯", color: "#C06800" },
  { id: "parallels",      label: "Parallels",         emoji: "💻", color: S.purple },
  { id: "external",       label: "External Drives",   emoji: "💾", color: S.teal   },
  { id: "uninstaller",    label: "Uninstaller",       emoji: "🗂", color: S.red    },
  { id: "uninstaller-v3", label: "System Cleaner V3", emoji: "🧹", color: "#1E6B3C" },
  { id: "repair",         label: "Disk Health",       emoji: "🔧", color: "#0078A0"},
  { id: "virus",          label: "Virus Scan",        emoji: "🛡", color: "#C42020" },
];

function fmtMb(mb: number): string {
  if (mb >= 1024) return (mb / 1024).toFixed(1) + " GB";
  if (mb >= 1) return mb.toFixed(0) + " MB";
  return (mb * 1024).toFixed(0) + " KB";
}

function fmtGb(gb: number): string {
  return gb.toFixed(1) + " GB";
}

function fmtAge(timestamp: number): string {
  const secs = Math.floor((Date.now() - timestamp) / 1000);
  if (secs < 60) return "just now";
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} hour${hours !== 1 ? "s" : ""} ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days !== 1 ? "s" : ""} ago`;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SidebarItem({
  item,
  active,
  onClick,
}: {
  item: (typeof NAV)[0];
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "9px 14px",
        borderRadius: 9,
        border: "none",
        background: active ? "rgba(255,255,255,0.09)" : "transparent",
        color: active ? S.text : S.muted,
        cursor: "pointer",
        width: "100%",
        textAlign: "left",
        fontSize: 14,
        fontWeight: active ? 600 : 400,
        transition: "all 0.15s",
      }}
    >
      <span
        style={{
          width: 28,
          height: 28,
          borderRadius: 7,
          background: active ? item.color + "33" : "rgba(255,255,255,0.06)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 14,
          flexShrink: 0,
        }}
      >
        {item.emoji}
      </span>
      {item.label}
    </button>
  );
}

function StatRing({
  percent,
  label,
  color,
  sub,
}: {
  percent: number;
  label: string;
  color: string;
  sub: string;
}) {
  const r = 38;
  const circ = 2 * Math.PI * r;
  const pct = Math.min(Math.max(percent, 0), 100);
  const dash = (pct / 100) * circ;
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
      <svg width={96} height={96} viewBox="0 0 96 96">
        <circle cx={48} cy={48} r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={7} />
        <circle
          cx={48} cy={48} r={r} fill="none" stroke={color} strokeWidth={7}
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circ}`}
          strokeDashoffset={circ / 4}
          style={{ transition: "stroke-dasharray 0.6s ease" }}
        />
        <text x={48} y={52} textAnchor="middle" fill={S.text} fontSize={16} fontWeight={700} fontFamily="-apple-system,sans-serif">
          {pct}%
        </text>
      </svg>
      <div style={{ textAlign: "center" }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: S.text }}>{label}</div>
        <div style={{ fontSize: 11, color: S.muted }}>{sub}</div>
      </div>
    </div>
  );
}

function CategoryGroup({
  category,
  items,
  selected,
  onToggle,
  onReveal,
}: {
  category: string;
  items: ScanResult[];
  selected: Set<string>;
  onToggle: (id: string) => void;
  onReveal: (path: string) => void;
}) {
  const total = items.reduce((s, i) => s + i.sizeMb, 0);
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6, padding: "0 2px" }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: S.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>{category}</span>
        <span style={{ fontSize: 11, color: S.muted }}>{fmtMb(total)}</span>
      </div>
      <div style={{ background: S.card, borderRadius: 12, overflow: "hidden" }}>
        {items.map((item, idx) => (
          <div
            key={item.id}
            style={{
              display: "flex", alignItems: "center", gap: 12, padding: "12px 16px",
              borderBottom: idx < items.length - 1 ? `1px solid ${S.border}` : "none",
              cursor: "pointer",
            }}
            onClick={() => onToggle(item.id)}
          >
            <div style={{
              width: 18, height: 18, borderRadius: 5,
              border: `2px solid ${selected.has(item.id) ? S.green : "rgba(255,255,255,0.25)"}`,
              background: selected.has(item.id) ? S.green : "transparent",
              flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center",
              transition: "all 0.15s",
            }}>
              {selected.has(item.id) && (
                <svg width={10} height={8} viewBox="0 0 10 8" fill="none">
                  <path d="M1 4l3 3 5-6" stroke="#fff" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              )}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 14, color: S.text, fontWeight: 500 }}>{item.name}</div>
              <div style={{ fontSize: 12, color: S.muted, marginTop: 2 }}>{item.fileCount.toLocaleString()} files</div>
            </div>
            <div style={{ textAlign: "right", flexShrink: 0 }}>
              <div style={{ fontSize: 14, fontWeight: 600, color: item.sizeMb > 100 ? S.orange : S.text }}>{fmtMb(item.sizeMb)}</div>
              {!item.safe && <div style={{ fontSize: 10, color: S.orange, marginTop: 2 }}>Review first</div>}
            </div>
            <button
              onClick={(e) => { e.stopPropagation(); onReveal(item.path); }}
              style={{ background: "rgba(255,255,255,0.06)", border: "none", borderRadius: 6, color: S.muted, fontSize: 11, padding: "4px 8px", cursor: "pointer", flexShrink: 0 }}
            >
              Show
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function AppRow({
  app,
  onUninstall,
  onReveal,
  uninstalling,
}: {
  app: AppInfo;
  onUninstall: (app: AppInfo) => void;
  onReveal: (path: string) => void;
  uninstalling: boolean;
}) {
  const total = app.sizeMb + app.associatedSizeMb;
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 12, padding: "13px 16px",
      borderBottom: `1px solid ${S.border}`,
    }}>
      <div style={{
        width: 36, height: 36, borderRadius: 9, background: "rgba(255,255,255,0.06)",
        display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, flexShrink: 0,
      }}>
        🗂
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 14, color: S.text, fontWeight: 600 }}>{app.name}</div>
        <div style={{ fontSize: 12, color: S.muted, marginTop: 2 }}>
          App: {fmtMb(app.sizeMb)}
          {app.associatedSizeMb > 0.5 && (
            <span style={{ color: S.orange }}> + {fmtMb(app.associatedSizeMb)} leftovers</span>
          )}
        </div>
      </div>
      <div style={{ textAlign: "right", flexShrink: 0 }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: total > 500 ? S.orange : S.text }}>{fmtMb(total)}</div>
      </div>
      <button
        onClick={() => onReveal(app.appPath)}
        style={{ background: "rgba(255,255,255,0.06)", border: "none", borderRadius: 6, color: S.muted, fontSize: 11, padding: "4px 8px", cursor: "pointer", flexShrink: 0 }}
      >
        Show
      </button>
      <button
        onClick={() => onUninstall(app)}
        disabled={uninstalling}
        style={{
          background: S.red + "22", border: `1px solid ${S.red}44`, borderRadius: 7,
          color: S.red, fontSize: 12, fontWeight: 600, padding: "5px 12px",
          cursor: uninstalling ? "not-allowed" : "pointer", flexShrink: 0,
          opacity: uninstalling ? 0.5 : 1,
        }}
      >
        Uninstall
      </button>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────

export default function App() {
  const [tab, setTab] = useState<Tab>("smart");
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [scanning, setScanning] = useState(false);
  const [cleaning, setCleaning] = useState(false);
  const [freedMb, setFreedMb] = useState(0);
  const [toast, setToast] = useState<string | null>(null);
  const [scanDone, setScanDone] = useState(false);
  const [needsPermission, setNeedsPermission] = useState(false);
  const [parallelsInfo, setParallelsInfo] = useState<{ installed: boolean; version: string; vms: { name: string; sizeMb: number }[]; totalVmSizeMb: number } | null>(null);

  // Uninstaller state
  const [appList, setAppList] = useState<AppInfo[]>([]);
  const [loadingApps, setLoadingApps] = useState(false);
  const [appsDone, setAppsDone] = useState(false);
  const [appsCachedAt, setAppsCachedAt] = useState<number | null>(null);
  const [bgRefreshing, setBgRefreshing] = useState(false);
  const [uninstallingApp, setUninstallingApp] = useState<string | null>(null);
  const [confirmApp, setConfirmApp] = useState<AppInfo | null>(null);

  // System Cleaner V3 (cross-platform uninstaller) state
  const [appListV2, setAppListV2] = useState<AppInfoV2[]>([]);
  const [loadingAppsV2, setLoadingAppsV2] = useState(false);
  const [appsDoneV2, setAppsDoneV2] = useState(false);
  const [appsProgressV2, setAppsProgressV2] = useState<{ scanned: number; total: number; currentName: string } | null>(null);
  const [uninstallingAppV2, setUninstallingAppV2] = useState<string | null>(null);
  const [confirmAppV2, setConfirmAppV2] = useState<AppInfoV2 | null>(null);
  const [v3Search, setV3Search] = useState("");

  // Scan All state
  const [scanningAll, setScanningAll] = useState(false);
  const [scanAllDone, setScanAllDone] = useState(false);
  const [scanAllError, setScanAllError] = useState<string | null>(null);
  const [fixingAll, setFixingAll] = useState(false);
  const [scanAllRowStatus, setScanAllRowStatus] = useState<{ junk: "pending" | "ok" | "error"; virus: "pending" | "ok" | "error"; disk: "pending" | "ok" | "error" }>({ junk: "pending", virus: "pending", disk: "pending" });
  const [scanAllVirusPass, setScanAllVirusPass] = useState<string | null>(null);
  const [scanAllJunkProgress, setScanAllJunkProgress] = useState<{ scanned: number; total: number; name: string; found: number } | null>(null);
  const [scanAllDiskProgress, setScanAllDiskProgress] = useState<string | null>(null);

  // Virus scan state
  const [virusResult, setVirusResult] = useState<VirusScanResult | null>(null);
  const [loadingVirus, setLoadingVirus] = useState(false);
  const [quarantining, setQuarantining] = useState<string | null>(null);

  // Disk health state
  const [diskHealth, setDiskHealth] = useState<DiskHealth | null>(null);
  const [loadingHealth, setLoadingHealth] = useState(false);
  const [verifyOutput, setVerifyOutput] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [fixingSymlinks, setFixingSymlinks] = useState(false);
  const [lastCleanedAt, setLastCleanedAt] = useState<number | null>(() => {
    const s = localStorage.getItem("macCleaner_lastCleanedAt");
    return s ? parseInt(s) : null;
  });
  const saveLastCleaned = () => {
    const now = Date.now();
    setLastCleanedAt(now);
    localStorage.setItem("macCleaner_lastCleanedAt", String(now));
  };
  const [repairing, setRepairing] = useState(false);
  const [repairSteps, setRepairSteps] = useState<{ id: string; label: string; status: "pending"|"running"|"ok"|"warn"|"error"|"skipped"; detail: string }[]>([]);
  const [repairDone, setRepairDone] = useState(false);
  const [repairSummary, setRepairSummary] = useState<{ fixedCount: number; errorCount: number } | null>(null);

  // External drives state
  const [externalVolumes, setExternalVolumes] = useState<ExternalVolume[]>([]);
  const [externalVolumesError, setExternalVolumesError] = useState<string | null>(null);
  const [usbScanResults, setUsbScanResults] = useState<Record<string, UsbDriveScanResult>>({});
  const [scanningUsb, setScanningUsb] = useState<Set<string>>(new Set());
  const [cleaningUsb, setCleaningUsb] = useState<Set<string>>(new Set());

  // Stats error state
  const [statsError, setStatsError] = useState<string | null>(null);

  // Duplicates state
  const [dupResult, setDupResult] = useState<DuplicateScanResult | null>(null);
  const [loadingDups, setLoadingDups] = useState(false);
  const [dupsDone, setDupsDone] = useState(false);
  const [dupSelected, setDupSelected] = useState<Set<string>>(new Set());
  const [deletingDups, setDeletingDups] = useState(false);

  // Progress state
  const [scanProgress, setScanProgress] = useState<{ scanned: number; total: number; currentName: string } | null>(null);
  const [virusProgress, setVirusProgress] = useState<{ msg: string; scanned: number } | null>(null);
  const [dupProgress, setDupProgress] = useState<{ scanned: number; total: number; phase: "walk" | "hash" } | null>(null);
  const [appsProgress, setAppsProgress] = useState<{ scanned: number; total: number; currentName: string } | null>(null);

  const platform = window.cleaner?.platform ?? "darwin";
  const isMac = platform === "darwin";

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3500);
  };

  useEffect(() => {
    if (!window.cleaner) return;
    window.cleaner.getStats().then(s => { setStats(s); setStatsError(null); }).catch((e) => {
      setStatsError(String(e?.message ?? "Could not load system stats"));
    });
    const iv = setInterval(() => {
      window.cleaner.getStats().then(s => { setStats(s); setStatsError(null); }).catch(() => {});
    }, 5000);
    return () => clearInterval(iv);
  }, []);

  useEffect(() => {
    if (tab !== "parallels" || !window.cleaner) return;
    window.cleaner.getParallelsInfo().then(setParallelsInfo).catch(() => {});
  }, [tab]);

  useEffect(() => {
    if (tab !== "external" || !window.cleaner) return;
    window.cleaner.listExternalVolumes().then(({ volumes, error }) => {
      setExternalVolumes(volumes);
      setExternalVolumesError(error ?? null);
    }).catch(() => {});
  }, [tab]);

  useEffect(() => {
    if (tab !== "uninstaller" || !window.cleaner) return;
    if (appsDone || loadingApps) return;
    window.cleaner.getCachedApps?.().then((cached) => {
      if (cached && cached.apps.length > 0) {
        setAppList(cached.apps);
        setAppsDone(true);
        setAppsCachedAt(cached.timestamp);
        const ONE_DAY_MS = 24 * 60 * 60 * 1000;
        if (Date.now() - cached.timestamp > ONE_DAY_MS) {
          setBgRefreshing(true);
          window.cleaner.scanApps().then((freshApps) => {
            setAppList(freshApps);
            setAppsCachedAt(Date.now());
          }).catch(() => {}).finally(() => {
            setBgRefreshing(false);
          });
        }
      }
    }).catch(() => {});
  }, [tab]);

  useEffect(() => {
    if (!scanningAll || !window.cleaner) return;
    setScanAllVirusPass(null);
    setScanAllJunkProgress(null);
    setScanAllDiskProgress(null);
    const unsubVirus = window.cleaner.onVirusScanProgress((msg) => {
      setScanAllVirusPass(msg);
    });
    const unsubJunk = window.cleaner.onScanProgress?.((scanned, total, currentName, found) => {
      setScanAllJunkProgress({ scanned, total, name: currentName, found });
    });
    const unsubDisk = window.cleaner.onDiskHealthProgress?.((line) => {
      setScanAllDiskProgress(line);
    });
    return () => {
      unsubVirus();
      unsubJunk?.();
      unsubDisk?.();
    };
  }, [scanningAll]);

  const handleScan = useCallback(async () => {
    if (!window.cleaner) return;
    setScanning(true);
    setScanDone(false);
    setScanProgress(null);
    setSelected(new Set());
    const unsub = window.cleaner.onScanProgress?.((scanned, total, currentName, _found) => {
      setScanProgress({ scanned, total, currentName });
    });
    try {
      const results = await window.cleaner.scan();
      setScanResults(results);
      setSelected(new Set(results.filter((r) => r.safe).map((r) => r.id)));
      setScanDone(true);
      if (results.length === 0 && window.cleaner.platform === "darwin") {
        const hasAccess = await window.cleaner.checkPermission().catch(() => true);
        setNeedsPermission(!hasAccess);
      } else {
        setNeedsPermission(false);
      }
    } finally {
      unsub?.();
      setScanProgress(null);
      setScanning(false);
    }
  }, []);

  const handleClean = useCallback(async () => {
    if (!window.cleaner || selected.size === 0) return;
    setCleaning(true);
    try {
      const result = await window.cleaner.clean(Array.from(selected));
      setFreedMb((prev) => prev + result.freedMb);
      saveLastCleaned();
      const fresh = await window.cleaner.scan();
      setScanResults(fresh);
      setSelected(new Set());
      setScanDone(false);
      showToast(`Freed ${fmtMb(result.freedMb)}${result.errors.length > 0 ? " (some items skipped)" : ""}`);
    } finally {
      setCleaning(false);
    }
  }, [selected]);

  const handleScanAll = useCallback(async () => {
    if (!window.cleaner) return;
    setScanningAll(true);
    setScanAllDone(false);
    setScanAllError(null);
    setScanAllRowStatus({ junk: "pending", virus: "pending", disk: "pending" });
    setVirusResult(null);
    setDiskHealth(null);
    setScanResults([]);
    setSelected(new Set());
    try {
      const junkPromise = window.cleaner.scan().then((res) => {
        setScanResults(res);
        setSelected(new Set(res.filter((r) => r.safe).map((r) => r.id)));
        setScanDone(true);
        setScanAllRowStatus((prev) => ({ ...prev, junk: "ok" }));
        return res;
      }, (err) => {
        setScanAllRowStatus((prev) => ({ ...prev, junk: "error" }));
        throw err;
      });

      const virusPromise = window.cleaner.virusScan().then((res) => {
        setVirusResult(res);
        setScanAllRowStatus((prev) => ({ ...prev, virus: "ok" }));
        return res;
      }, (err) => {
        setScanAllRowStatus((prev) => ({ ...prev, virus: "error" }));
        throw err;
      });

      const diskPromise = window.cleaner.diskHealth().then((res) => {
        setDiskHealth(res);
        setScanAllRowStatus((prev) => ({ ...prev, disk: "ok" }));
        return res;
      }, (err) => {
        setScanAllRowStatus((prev) => ({ ...prev, disk: "error" }));
        throw err;
      });

      const [junkSettled, virusSettled, diskSettled] = await Promise.allSettled([
        junkPromise,
        virusPromise,
        diskPromise,
      ]);

      const failed: string[] = [];
      if (junkSettled.status === "rejected") failed.push("junk file scan");
      if (virusSettled.status === "rejected") failed.push("virus scan");
      if (diskSettled.status === "rejected") failed.push("disk health check");
      if (failed.length > 0) {
        setScanAllError(`One or more scans could not complete: ${failed.join(", ")}. Partial results are shown below.`);
      }

      setScanAllDone(true);
    } finally {
      setScanningAll(false);
    }
  }, []);

  const handleFixAll = useCallback(async () => {
    if (!window.cleaner) return;
    setFixingAll(true);
    try {
      // 1. Clean junk — skipped if junk scan failed (selected will be empty)
      if (selected.size > 0) {
        const r = await window.cleaner.clean(Array.from(selected));
        setFreedMb((prev) => prev + r.freedMb);
        saveLastCleaned();
        const fresh = await window.cleaner.scan();
        setScanResults(fresh);
        setSelected(new Set());
      }
      // 2. Fix broken symlinks — skipped if disk health scan failed (diskHealth is null)
      if (diskHealth && diskHealth.brokenSymlinks.length > 0) {
        await window.cleaner.fixSymlinks(diskHealth.brokenSymlinks);
        const freshDisk = await window.cleaner.diskHealth();
        setDiskHealth(freshDisk);
      }
      // 3. Quarantine all threats — skipped if virus scan failed (virusResult is null)
      if (virusResult && virusResult.threats.length > 0) {
        for (const t of virusResult.threats) {
          await window.cleaner.quarantineThreat(t.path);
        }
        setVirusResult((prev) => prev ? { ...prev, threats: [], status: "clean" } : null);
      }
      showToast("✓ All issues fixed");
    } finally {
      setFixingAll(false);
    }
  }, [selected, diskHealth, virusResult]);

  const handleVirusScan = useCallback(async () => {
    if (!window.cleaner) return;
    setLoadingVirus(true);
    setVirusResult(null);
    setVirusProgress(null);
    const unsub = window.cleaner.onVirusScanProgress?.((msg, scanned) => {
      setVirusProgress({ msg, scanned });
    });
    try {
      const result = await window.cleaner.virusScan();
      setVirusResult(result);
    } finally {
      unsub?.();
      setVirusProgress(null);
      setLoadingVirus(false);
    }
  }, []);

  const handleScanDuplicates = useCallback(async () => {
    if (!window.cleaner) return;
    setLoadingDups(true);
    setDupResult(null);
    setDupsDone(false);
    setDupSelected(new Set());
    setDupProgress(null);
    const unsub = window.cleaner.onScanDuplicatesProgress?.((scanned, total, phase) => {
      setDupProgress({ scanned, total, phase });
    });
    try {
      const result = await window.cleaner.scanDuplicates();
      setDupResult(result);
      setDupsDone(true);
    } finally {
      unsub?.();
      setDupProgress(null);
      setLoadingDups(false);
    }
  }, []);

  const handleDeleteDuplicates = useCallback(async () => {
    if (!window.cleaner || dupSelected.size === 0) return;
    setDeletingDups(true);
    try {
      const paths = Array.from(dupSelected);
      const result = await window.cleaner.deleteDuplicates(paths);
      showToast(`🗑 Freed ${fmtMb(result.freedMb)} — deleted ${paths.length} duplicate${paths.length > 1 ? "s" : ""}`);
      setDupResult(prev => {
        if (!prev) return prev;
        const groups = prev.groups
          .map(g => ({ ...g, files: g.files.filter(f => !dupSelected.has(f.path)) }))
          .filter(g => g.files.length >= 2);
        const totalWasteMb = groups.reduce((s, g) => s + g.sizeMb * (g.files.length - 1), 0);
        return { ...prev, groups, totalWasteMb };
      });
      setDupSelected(new Set());
    } finally {
      setDeletingDups(false);
    }
  }, [dupSelected]);

  const handleQuarantine = useCallback(async (threat: ThreatItem) => {
    if (!window.cleaner) return;
    setQuarantining(threat.path);
    try {
      const result = await window.cleaner.quarantineThreat(threat.path);
      if (result.ok) {
        showToast(`Moved "${threat.name}" to Trash`);
        setVirusResult((prev) => prev ? { ...prev, threats: prev.threats.filter(t => t.path !== threat.path), status: prev.threats.length === 1 ? "clean" : "threats_found" } : null);
      } else {
        showToast(`⚠ Could not quarantine: ${result.error}`);
      }
    } finally {
      setQuarantining(null);
    }
  }, []);

  const handleDiskHealth = useCallback(async () => {
    if (!window.cleaner) return;
    setLoadingHealth(true);
    setVerifyOutput(null);
    try {
      const result = await window.cleaner.diskHealth();
      setDiskHealth(result);
    } finally {
      setLoadingHealth(false);
    }
  }, []);

  const handleVerifyDisk = useCallback(async () => {
    if (!window.cleaner) return;
    setVerifying(true);
    setVerifyOutput(null);
    try {
      const out = await window.cleaner.verifyDisk();
      setVerifyOutput(out);
    } finally {
      setVerifying(false);
    }
  }, []);

  const handleRunRepairs = useCallback(async () => {
    if (!window.cleaner) return;
    setRepairing(true);
    setRepairDone(false);
    setRepairSteps([]);
    setRepairSummary(null);
    const unsub = window.cleaner.onRepairStep?.((step) => {
      setRepairSteps((prev) => {
        const idx = prev.findIndex((s) => s.id === step.id);
        if (idx >= 0) {
          const next = [...prev];
          next[idx] = step;
          return next;
        }
        return [...prev, step];
      });
    });
    try {
      const report = await window.cleaner.runSystemRepairs();
      setRepairSummary({ fixedCount: report.fixedCount, errorCount: report.errorCount });
      setRepairDone(true);
    } finally {
      unsub?.();
      setRepairing(false);
    }
  }, []);

  const handleFixSymlinks = useCallback(async (paths: string[]) => {
    if (!window.cleaner) return;
    setFixingSymlinks(true);
    try {
      const result = await window.cleaner.fixSymlinks(paths);
      if (result.errors.length > 0) {
        showToast(`⚠ Fixed ${result.fixed}, failed on ${result.errors.length}`);
      } else {
        showToast(`Fixed ${result.fixed} broken symlink${result.fixed !== 1 ? "s" : ""}`);
      }
      // Re-scan to refresh list
      const fresh = await window.cleaner.diskHealth();
      setDiskHealth(fresh);
    } finally {
      setFixingSymlinks(false);
    }
  }, []);

  const handleScanApps = useCallback(async () => {
    if (!window.cleaner) return;
    setLoadingApps(true);
    setAppsDone(false);
    setAppsProgress(null);
    const unsub = window.cleaner.onScanAppsProgress?.((scanned, total, currentName) => {
      setAppsProgress({ scanned, total, currentName });
    });
    try {
      const apps = await window.cleaner.scanApps();
      setAppList(apps);
      setAppsDone(true);
      setAppsCachedAt(Date.now());
    } finally {
      unsub?.();
      setAppsProgress(null);
      setLoadingApps(false);
    }
  }, []);

  const handleUninstall = useCallback(async (app: AppInfo) => {
    if (!window.cleaner) return;
    setConfirmApp(null);
    setUninstallingApp(app.appPath);
    try {
      const result = await window.cleaner.uninstallApp(app.appPath, app.associatedPaths);
      if (result.errors.length > 0) {
        showToast(`⚠ Could not remove ${app.name}: ${result.errors[0]}`);
      } else {
        setFreedMb((prev) => prev + result.freedMb);
        setAppList((prev) => prev.filter((a) => a.appPath !== app.appPath));
        showToast(`Moved ${app.name} to Trash — empty Trash to free ${fmtMb(result.freedMb)}`);
      }
    } finally {
      setUninstallingApp(null);
    }
  }, []);

  const handleScanAppsV2 = useCallback(async () => {
    if (!window.cleaner) return;
    setLoadingAppsV2(true);
    setAppsDoneV2(false);
    setAppsProgressV2(null);
    const unsub = window.cleaner.onScanAppsV2Progress?.((scanned, total, currentName) => {
      setAppsProgressV2({ scanned, total, currentName });
    });
    try {
      const apps = await window.cleaner.scanAppsV2();
      setAppListV2(apps);
      setAppsDoneV2(true);
    } finally {
      unsub?.();
      setAppsProgressV2(null);
      setLoadingAppsV2(false);
    }
  }, []);

  const handleUninstallV2 = useCallback(async (app: AppInfoV2) => {
    if (!window.cleaner) return;
    setConfirmAppV2(null);
    setUninstallingAppV2(app.appPath);
    try {
      const result = await window.cleaner.uninstallAppV2(app);
      if (result.errors.length > 0) {
        showToast(`⚠ ${app.name}: ${result.errors[0]}`);
      } else {
        setFreedMb((prev) => prev + result.freedMb);
        setAppListV2((prev) => prev.filter((a) => a.appPath !== app.appPath));
        const methodMsg = result.method === "trash"
          ? `Moved to Trash — empty Trash to free ${fmtMb(result.freedMb)}`
          : `Uninstalled via official uninstaller`;
        showToast(`✓ ${app.name} removed — ${methodMsg}`);
      }
    } finally {
      setUninstallingAppV2(null);
    }
  }, []);

  const handleScanUsb = useCallback(async (volPath: string) => {
    if (!window.cleaner) return;
    setScanningUsb(prev => new Set(prev).add(volPath));
    try {
      const result = await window.cleaner.scanUsbDrive(volPath);
      setUsbScanResults(prev => ({ ...prev, [volPath]: result }));
    } finally {
      setScanningUsb(prev => { const s = new Set(prev); s.delete(volPath); return s; });
    }
  }, []);

  const handleCleanUsbJunk = useCallback(async (volPath: string, junkPaths: string[]) => {
    if (!window.cleaner) return;
    setCleaningUsb(prev => new Set(prev).add(volPath));
    try {
      const result = await window.cleaner.cleanUsbJunk(junkPaths);
      setFreedMb(prev => prev + result.freedMb);
      if (result.errors.length > 0) {
        showToast(`⚠ Some items could not be moved: ${result.errors[0]}`);
      } else {
        showToast(`Freed ${fmtMb(result.freedMb)} from drive junk — empty Trash to reclaim space`);
      }
      // Re-scan the drive to refresh the view
      const fresh = await window.cleaner.scanUsbDrive(volPath);
      setUsbScanResults(prev => ({ ...prev, [volPath]: fresh }));
    } finally {
      setCleaningUsb(prev => { const s = new Set(prev); s.delete(volPath); return s; });
    }
  }, []);

  const toggleItem = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const revealPath = (path: string) => window.cleaner?.openPath(path);

  const filteredResults = scanResults.filter((r) => {
    if (tab === "smart") return true;
    if (tab === "junk") return r.category === "System Junk" || r.category === "Browser Junk" || r.category === "Developer Junk";
    if (tab === "privacy") return r.category === "Privacy";
    if (tab === "parallels") return r.category === "Parallels";
    if (tab === "external") return r.category === "External Drives";
    return true;
  });

  const categories = Array.from(new Set(filteredResults.map((r) => r.category)));
  const selectedMb = scanResults.filter((r) => selected.has(r.id)).reduce((s, r) => s + r.sizeMb, 0);
  const totalFoundMb = filteredResults.reduce((s, r) => s + r.sizeMb, 0);

  const diskPct = stats && stats.diskTotalGb > 0 ? Math.round((stats.diskUsedGb / stats.diskTotalGb) * 100) : 0;
  const ramPct = stats ? Math.round((stats.ramUsedGb / stats.ramTotalGb) * 100) : 0;

  // ── Health score (0–100) ──────────────────────────────────────────────────
  const junkMbForScore = scanDone ? scanResults.reduce((s, r) => s + r.sizeMb, 0) : 0;
  const healthScore = (() => {
    let s = 100;
    // Disk penalty
    if (diskPct > 95) s -= 25;
    else if (diskPct > 90) s -= 20;
    else if (diskPct > 80) s -= 10;
    else if (diskPct > 70) s -= 5;
    // RAM penalty
    if (ramPct > 95) s -= 15;
    else if (ramPct > 85) s -= 8;
    else if (ramPct > 75) s -= 3;
    // CPU penalty
    if (stats && stats.cpuPercent > 85) s -= 5;
    else if (stats && stats.cpuPercent > 70) s -= 2;
    // Junk penalty (only after a scan — cleared back to 0 once user cleans)
    if (scanDone) {
      if (junkMbForScore > 1000) s -= 20;
      else if (junkMbForScore > 500) s -= 15;
      else if (junkMbForScore > 100) s -= 10;
      else if (junkMbForScore > 0) s -= 5;
    }
    return Math.max(0, Math.min(100, s));
  })();
  const healthLabel = healthScore === 100 ? "Perfect ✨" : healthScore >= 90 ? "Excellent" : healthScore >= 75 ? "Good" : healthScore >= 55 ? "Fair" : "Needs Attention";
  const healthColor = healthScore >= 90 ? S.green : healthScore >= 70 ? S.orange : S.red;
  // Overdue if never cleaned or cleaned > 30 days ago
  const cleanOverdue = lastCleanedAt === null || (Date.now() - lastCleanedAt) > 30 * 86_400_000;
  // ─────────────────────────────────────────────────────────────────────────

  const isUninstallerTab = tab === "uninstaller";
  const isRepairTab      = tab === "repair";
  const isExternalTab    = tab === "external";

  return (
    <div style={{ display: "flex", height: "100vh", background: S.bgGrad, overflow: "hidden", position: "relative" }}>
      <style>{`@keyframes fadeInName { from { opacity: 0; } to { opacity: 1; } }`}</style>

      {/* Toast */}
      {toast && (
        <div style={{
          position: "fixed", top: 20, left: "50%", transform: "translateX(-50%)",
          background: toast.startsWith("⚠") ? S.orange : S.green,
          color: "#fff", padding: "10px 20px", borderRadius: 10,
          fontSize: 13, fontWeight: 600, zIndex: 9999, boxShadow: "0 4px 20px rgba(0,0,0,0.5)",
          maxWidth: 420, textAlign: "center",
        }}>
          {toast.startsWith("⚠") ? toast : `✓ ${toast}`}
        </div>
      )}

      {/* Confirm uninstall dialog */}
      {confirmApp && (
        <div style={{
          position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", zIndex: 9998,
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <div style={{ background: S.card, borderRadius: 16, padding: 28, width: 380, boxShadow: "0 20px 60px rgba(0,0,0,0.5)" }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: S.text, marginBottom: 6 }}>
              Move {confirmApp.name} to Trash?
            </div>
            <div style={{ fontSize: 13, color: S.muted, marginBottom: 12 }}>
              The following will be moved to Trash. Empty your Trash afterwards to free the space.
            </div>
            <div style={{ fontSize: 13, color: S.text, background: S.card2, borderRadius: 8, padding: "10px 14px", marginBottom: 16 }}>
              <div>• {confirmApp.name}.app ({fmtMb(confirmApp.sizeMb)})</div>
              {confirmApp.associatedPaths.map((p, i) => (
                <div key={i} style={{ color: S.muted, marginTop: 4, fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>• {p}</div>
              ))}
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <button
                onClick={() => setConfirmApp(null)}
                style={{ flex: 1, padding: "10px", borderRadius: 9, border: "none", background: "rgba(255,255,255,0.08)", color: S.text, fontSize: 14, cursor: "pointer" }}
              >
                Cancel
              </button>
              <button
                onClick={() => handleUninstall(confirmApp)}
                style={{ flex: 1, padding: "10px", borderRadius: 9, border: "none", background: S.red, color: "#fff", fontSize: 14, fontWeight: 700, cursor: "pointer" }}
              >
                Move to Trash
              </button>
            </div>
          </div>
        </div>
      )}

      {/* System Cleaner V3 — confirm uninstall dialog */}
      {confirmAppV2 && (
        <div style={{
          position: "fixed", inset: 0, background: "rgba(0,0,0,0.80)", zIndex: 9998,
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <div style={{ background: S.card, borderRadius: 18, padding: 28, width: 460, boxShadow: "0 24px 64px rgba(0,0,0,0.6)" }}>
            <div style={{ fontSize: 19, fontWeight: 700, color: S.text, marginBottom: 8 }}>
              Remove {confirmAppV2.name}?
            </div>

            {/* Safety badge */}
            <div style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              fontSize: 11, fontWeight: 700, padding: "5px 12px",
              borderRadius: 20, marginBottom: 14,
              background: platform === "darwin" ? "#1A8C3820" : platform === "linux" ? "#8B450020" : "#0060CC20",
              color: platform === "darwin" ? S.green : platform === "linux" ? S.orange : S.blue,
              border: `1px solid ${platform === "darwin" ? S.green + "40" : platform === "linux" ? S.orange + "40" : S.blue + "40"}`,
            }}>
              {platform === "darwin"
                ? "🛡 Moves to Trash — fully reversible"
                : platform === "linux"
                  ? confirmAppV2.quietUninstallString
                    ? `🔧 Uses: ${confirmAppV2.quietUninstallString.split(" ")[0]} package manager`
                    : "⚠ No package manager found for this app"
                  : confirmAppV2.isMsi
                    ? "🛡 Uses MSI official uninstaller"
                    : confirmAppV2.quietUninstallString || confirmAppV2.uninstallString
                      ? "🛡 Uses app's official uninstaller"
                      : "⚠ No uninstaller found — removal may be incomplete"}
            </div>

            {(confirmAppV2.version || confirmAppV2.publisher) && (
              <div style={{ fontSize: 12, color: S.muted, marginBottom: 10 }}>
                {confirmAppV2.version && `Version ${confirmAppV2.version}`}
                {confirmAppV2.publisher ? ` · ${confirmAppV2.publisher}` : ""}
              </div>
            )}

            <div style={{ fontSize: 13, color: S.text, background: "rgba(255,255,255,0.04)", borderRadius: 10, padding: "12px 16px", marginBottom: 18, border: `1px solid ${S.border}` }}>
              <div style={{ fontWeight: 600, marginBottom: 8, fontSize: 11, color: S.muted, textTransform: "uppercase", letterSpacing: 0.5 }}>
                What will be removed
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span>• {confirmAppV2.name}{platform === "darwin" ? ".app" : ""}</span>
                <span style={{ color: S.orange, fontWeight: 600, fontSize: 12 }}>{fmtMb(confirmAppV2.sizeMb)}</span>
              </div>
              {confirmAppV2.associatedPaths.map((p, i) => (
                <div key={i} style={{ color: S.muted, marginTop: 6, fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  • {p}
                </div>
              ))}
              {confirmAppV2.associatedPaths.length === 0 && platform === "darwin" && (
                <div style={{ color: S.muted, marginTop: 6, fontSize: 11 }}>No leftover data found</div>
              )}
              {platform === "linux" && confirmAppV2.quietUninstallString && (
                <div style={{ color: S.muted, marginTop: 8, fontSize: 11, fontFamily: "monospace", background: "rgba(0,0,0,0.2)", padding: "4px 8px", borderRadius: 5 }}>
                  $ {confirmAppV2.quietUninstallString}
                </div>
              )}
            </div>

            <div style={{ fontSize: 12, color: S.muted, marginBottom: 16, padding: "8px 12px", background: "rgba(255,165,0,0.06)", borderRadius: 8, border: "1px solid rgba(255,165,0,0.15)" }}>
              ⚠ Only remove apps you recognise. System-critical packages are already locked.
            </div>

            <div style={{ display: "flex", gap: 10 }}>
              <button
                onClick={() => setConfirmAppV2(null)}
                style={{ flex: 1, padding: "11px", borderRadius: 10, border: "none", background: "rgba(255,255,255,0.08)", color: S.text, fontSize: 14, cursor: "pointer", fontWeight: 600 }}
              >
                Cancel
              </button>
              <button
                onClick={() => handleUninstallV2(confirmAppV2)}
                style={{ flex: 1, padding: "11px", borderRadius: 10, border: "none", background: "#1E6B3C", color: "#fff", fontSize: 14, fontWeight: 700, cursor: "pointer" }}
              >
                {platform === "darwin" ? "Move to Trash" : platform === "linux" ? "Uninstall via Package Manager" : "Uninstall"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Sidebar */}
      <div style={{
        width: 220, background: S.sidebar, display: "flex", flexDirection: "column",
        padding: "48px 10px 20px", borderRight: `1px solid ${S.border}`, flexShrink: 0,
      }}>
        <div style={{ paddingLeft: 6, marginBottom: 20 }}>
          <div style={{ fontSize: 18, fontWeight: 800, color: S.text, letterSpacing: -0.3 }}>
            {isMac ? "🍎" : "🪟"} Mac Cleaner
          </div>
          {freedMb > 0 && (
            <div style={{ fontSize: 11, color: S.green, marginTop: 4 }}>{fmtMb(freedMb)} freed this session</div>
          )}
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
          {NAV.map((item) => (
            <SidebarItem key={item.id} item={item} active={tab === item.id} onClick={() => setTab(item.id)} />
          ))}
        </div>

        {stats && (
          <div style={{ marginTop: "auto", display: "flex", flexDirection: "column", gap: 10 }}>
            <div style={{ height: 1, background: S.border, margin: "0 4px" }} />
            <div style={{ padding: "10px 6px" }}>
              {stats.diskError ? (
                <div style={{ marginBottom: 10 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                    <span style={{ fontSize: 11, color: S.muted }}>Disk</span>
                    <span style={{ fontSize: 11, color: S.orange }}>⚠ Unavailable</span>
                  </div>
                  <div style={{ fontSize: 10, color: S.orange, lineHeight: 1.4 }}>{stats.diskError}</div>
                </div>
              ) : (
                <MiniStat label="Disk" used={fmtGb(stats.diskUsedGb)} total={fmtGb(stats.diskTotalGb)} pct={diskPct} color={diskPct > 85 ? S.red : diskPct > 70 ? S.orange : S.green} />
              )}
              <MiniStat label="RAM" used={fmtGb(stats.ramUsedGb)} total={fmtGb(stats.ramTotalGb)} pct={ramPct} color={ramPct > 85 ? S.red : S.blue} />
              <MiniStat label="CPU" used={`${stats.cpuPercent}%`} total="" pct={stats.cpuPercent} color={stats.cpuPercent > 80 ? S.red : S.teal} />
            </div>
          </div>
        )}
      </div>

      {/* Main content */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>

        {/* Header */}
        <div style={{
          padding: "20px 28px 16px", borderBottom: `1px solid ${S.border}`,
          display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0,
        }}>
          <div>
            <div style={{ fontSize: 22, fontWeight: 800, color: S.text }}>
              {NAV.find((n) => n.id === tab)?.emoji} {NAV.find((n) => n.id === tab)?.label}
            </div>
            {isUninstallerTab && appsDone && (
              <div style={{ fontSize: 13, color: S.muted, marginTop: 3 }}>
                {appList.length} apps found · {fmtMb(appList.reduce((s, a) => s + a.sizeMb + a.associatedSizeMb, 0))} total
                {appsCachedAt !== null && (
                  <span style={{ marginLeft: 8, color: S.green, fontStyle: "italic" }}>
                    · Last scanned {fmtAge(appsCachedAt)}
                  </span>
                )}
                {bgRefreshing && (
                  <span style={{ marginLeft: 10, color: S.muted, fontStyle: "italic", opacity: 0.75 }}>
                    · Updating in background…
                  </span>
                )}
              </div>
            )}
            {!isUninstallerTab && scanDone && (
              <div style={{ fontSize: 13, color: S.muted, marginTop: 3 }}>
                Found {fmtMb(totalFoundMb)} across {filteredResults.length} items
              </div>
            )}
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            {tab === "scan-all" ? (
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  onClick={handleScanAll}
                  disabled={scanningAll}
                  style={{
                    padding: "9px 20px", borderRadius: 10, border: "none",
                    background: "#7030B0", color: "#fff", fontSize: 14, fontWeight: 700,
                    cursor: scanningAll ? "not-allowed" : "pointer", opacity: scanningAll ? 0.6 : 1,
                  }}
                >
                  {scanningAll ? "Scanning…" : scanAllDone ? "Re-scan All" : "⚡ Scan All"}
                </button>
                {scanAllDone && (
                  <button
                    onClick={handleFixAll}
                    disabled={fixingAll || !!scanAllError}
                    title={scanAllError ? "Fix All is unavailable because one or more scans failed" : undefined}
                    style={{
                      padding: "9px 20px", borderRadius: 10, border: "none",
                      background: S.green, color: "#fff", fontSize: 14, fontWeight: 700,
                      cursor: (fixingAll || !!scanAllError) ? "not-allowed" : "pointer",
                      opacity: (fixingAll || !!scanAllError) ? 0.4 : 1,
                    }}
                  >
                    {fixingAll ? "Fixing…" : "Fix All Issues"}
                  </button>
                )}
              </div>
            ) : tab === "virus" ? (
              <button
                onClick={handleVirusScan}
                disabled={loadingVirus}
                style={{
                  padding: "9px 20px", borderRadius: 10, border: "none",
                  background: "rgba(255,255,255,0.1)", color: S.text, fontSize: 14, fontWeight: 600,
                  cursor: loadingVirus ? "not-allowed" : "pointer", opacity: loadingVirus ? 0.6 : 1,
                }}
              >
                {loadingVirus ? "Scanning…" : "Run Scan"}
              </button>
            ) : isRepairTab ? (
              <button
                onClick={handleDiskHealth}
                disabled={loadingHealth}
                style={{
                  padding: "9px 20px", borderRadius: 10, border: "none",
                  background: "rgba(255,255,255,0.1)", color: S.text, fontSize: 14, fontWeight: 600,
                  cursor: loadingHealth ? "not-allowed" : "pointer", opacity: loadingHealth ? 0.6 : 1,
                }}
              >
                {loadingHealth ? "Scanning…" : "Scan Disk"}
              </button>
            ) : tab === "duplicates" ? (
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  onClick={handleScanDuplicates}
                  disabled={loadingDups}
                  style={{
                    padding: "9px 20px", borderRadius: 10, border: "none",
                    background: "rgba(255,255,255,0.1)", color: S.text, fontSize: 14, fontWeight: 600,
                    cursor: loadingDups ? "not-allowed" : "pointer", opacity: loadingDups ? 0.6 : 1,
                  }}
                >
                  {loadingDups ? "Scanning…" : "Scan for Duplicates"}
                </button>
                {dupSelected.size > 0 && (
                  <button
                    onClick={handleDeleteDuplicates}
                    disabled={deletingDups}
                    style={{
                      padding: "9px 20px", borderRadius: 10, border: "none",
                      background: "#C42020", color: "#fff", fontSize: 14, fontWeight: 700,
                      cursor: deletingDups ? "not-allowed" : "pointer", opacity: deletingDups ? 0.6 : 1,
                    }}
                  >
                    {deletingDups ? "Deleting…" : `Delete ${dupSelected.size} Selected`}
                  </button>
                )}
              </div>
            ) : tab === "uninstaller-v3" ? (
              <button
                onClick={handleScanAppsV2}
                disabled={loadingAppsV2}
                style={{
                  padding: "9px 20px", borderRadius: 10, border: "none",
                  background: "rgba(255,255,255,0.1)", color: S.text, fontSize: 14, fontWeight: 600,
                  cursor: loadingAppsV2 ? "not-allowed" : "pointer", opacity: loadingAppsV2 ? 0.6 : 1,
                }}
              >
                {loadingAppsV2
                  ? (appsProgressV2 && appsProgressV2.total > 0
                      ? `Scanning ${appsProgressV2.scanned} / ${appsProgressV2.total}…`
                      : "Scanning…")
                  : appsDoneV2 ? "↺ Refresh" : "🧹 Scan Apps"}
              </button>
            ) : isUninstallerTab ? (
              <button
                onClick={handleScanApps}
                disabled={loadingApps}
                style={{
                  padding: "9px 20px", borderRadius: 10, border: "none",
                  background: "rgba(255,255,255,0.1)", color: S.text, fontSize: 14, fontWeight: 600,
                  cursor: loadingApps ? "not-allowed" : "pointer", opacity: loadingApps ? 0.6 : 1,
                }}
              >
                {loadingApps
                  ? (appsProgress && appsProgress.total > 0
                      ? `Scanning ${appsProgress.scanned} / ${appsProgress.total}…`
                      : "Scanning…")
                  : appsDone || appsCachedAt !== null
                    ? "↺ Refresh"
                    : "Scan Apps"}
              </button>
            ) : isExternalTab ? (
              null
            ) : (
              <>
                <button
                  onClick={handleScan}
                  disabled={scanning}
                  style={{
                    padding: "9px 20px", borderRadius: 10, border: "none",
                    background: "rgba(255,255,255,0.1)", color: S.text, fontSize: 14, fontWeight: 600,
                    cursor: scanning ? "not-allowed" : "pointer", opacity: scanning ? 0.6 : 1,
                  }}
                >
                  {scanning ? "Scanning…" : "Scan"}
                </button>
                <button
                  onClick={handleClean}
                  disabled={selected.size === 0 || cleaning}
                  style={{
                    padding: "9px 24px", borderRadius: 10, border: "none",
                    background: selected.size > 0 ? S.green : "rgba(255,255,255,0.06)",
                    color: selected.size > 0 ? "#fff" : S.muted,
                    fontSize: 14, fontWeight: 700,
                    cursor: selected.size > 0 && !cleaning ? "pointer" : "not-allowed",
                    transition: "all 0.2s",
                  }}
                >
                  {cleaning ? "Cleaning…" : selected.size > 0 ? `Clean ${fmtMb(selectedMb)}` : "Clean"}
                </button>
              </>
            )}
          </div>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflow: "auto", padding: "24px 28px" }}>

          {/* ── Uninstaller tab ── */}
          {isUninstallerTab && (
            <>
              {!loadingApps && !appsDone && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                  <div style={{ fontSize: 48 }}>🗂</div>
                  <div style={{ fontSize: 15, color: S.muted, textAlign: "center" }}>
                    Click <strong style={{ color: S.text }}>Scan Apps</strong> to see all installed apps and their leftover files
                  </div>
                </div>
              )}
              {loadingApps && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                  <div style={{ width: 60, height: 60, borderRadius: "50%", border: `4px solid rgba(255,255,255,0.08)`, borderTop: `4px solid ${S.red}`, animation: "spin 0.8s linear infinite" }} />
                  <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8, width: 320 }}>
                    <div style={{ color: S.text, fontSize: 15, fontWeight: 600 }}>
                      {appsProgress && appsProgress.total > 0
                        ? `Scanning ${appsProgress.scanned} / ${appsProgress.total} apps…`
                        : "Scanning Applications…"}
                    </div>
                    {appsProgress && appsProgress.total > 0 && (
                      <div style={{ width: "100%", height: 6, borderRadius: 3, background: "rgba(255,255,255,0.1)", overflow: "hidden" }}>
                        <div style={{
                          height: "100%",
                          borderRadius: 3,
                          background: S.red,
                          width: `${Math.round((appsProgress.scanned / appsProgress.total) * 100)}%`,
                          transition: "width 0.2s ease",
                        }} />
                      </div>
                    )}
                    <div key={appsProgress?.currentName} style={{ color: S.muted, fontSize: 13, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", textAlign: "center", minHeight: 18, animation: appsProgress?.currentName ? "fadeInName 0.15s ease forwards" : "none" }}>
                      {appsProgress?.currentName ? `Checking ${appsProgress.currentName}…` : ""}
                    </div>
                  </div>
                </div>
              )}
              {appsDone && !loadingApps && (
                <div style={{ background: S.card, borderRadius: 14, overflow: "hidden" }}>
                  {appList.map((app) => (
                    <AppRow
                      key={app.appPath}
                      app={app}
                      onUninstall={(a) => setConfirmApp(a)}
                      onReveal={revealPath}
                      uninstalling={uninstallingApp === app.appPath}
                    />
                  ))}
                </div>
              )}
            </>
          )}

          {/* ── System Cleaner V3 tab ── */}
          {tab === "uninstaller-v3" && (
            <>
              {/* Safety banner */}
              {appsDoneV2 && (
                <div style={{
                  display: "flex", alignItems: "center", gap: 10,
                  background: platform === "darwin" ? "#1A8C3815" : platform === "linux" ? "#8B450015" : "#0060CC15",
                  border: `1px solid ${platform === "darwin" ? "#1A8C3833" : platform === "linux" ? "#8B450033" : "#0060CC33"}`,
                  borderRadius: 10, padding: "10px 16px", marginBottom: 16, fontSize: 13,
                }}>
                  <span style={{ fontSize: 18 }}>
                    {platform === "darwin" ? "🛡" : platform === "linux" ? "🐧" : "🔧"}
                  </span>
                  <span style={{ color: platform === "darwin" ? S.green : platform === "linux" ? S.orange : S.blue, fontWeight: 600 }}>
                    {platform === "darwin"
                      ? "All removals move to Trash — reversible anytime. System apps are locked and cannot be removed."
                      : platform === "linux"
                        ? "Uses your system package manager (apt/snap/flatpak). System-critical packages are locked and protected."
                        : "Apps are uninstalled using their own official uninstaller — the same as Add/Remove Programs."}
                  </span>
                </div>
              )}

              {/* Empty state */}
              {!loadingAppsV2 && !appsDoneV2 && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                  <div style={{ fontSize: 52 }}>🧹</div>
                  <div style={{ fontSize: 16, color: S.text, fontWeight: 700 }}>System Cleaner V3</div>
                  <div style={{ fontSize: 13, color: S.muted, textAlign: "center", maxWidth: 400, lineHeight: 1.6 }}>
                    {platform === "darwin"
                      ? "Scans every installed app and its leftover files (caches, preferences, containers). All removals go to Trash — fully reversible."
                      : platform === "linux"
                        ? "Lists all installed packages from dpkg, snap, and flatpak. System-critical packages are locked automatically."
                        : "Reads the Windows registry to find all installed programs — the same list as Add/Remove Programs — plus their official uninstallers."}
                  </div>
                  <button
                    onClick={handleScanAppsV2}
                    style={{
                      padding: "12px 32px", borderRadius: 11, border: "none",
                      background: "#1E6B3C", color: "#fff", fontSize: 15, fontWeight: 700, cursor: "pointer",
                    }}
                  >
                    🧹 Scan All Apps
                  </button>
                </div>
              )}

              {/* Scanning spinner */}
              {loadingAppsV2 && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                  <div style={{ width: 60, height: 60, borderRadius: "50%", border: `4px solid rgba(255,255,255,0.08)`, borderTop: `4px solid #1E6B3C`, animation: "spin 0.8s linear infinite" }} />
                  <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8, width: 340 }}>
                    <div style={{ color: S.text, fontSize: 15, fontWeight: 600 }}>
                      {appsProgressV2 && appsProgressV2.total > 0
                        ? `Scanning ${appsProgressV2.scanned} / ${appsProgressV2.total} apps…`
                        : platform === "darwin" ? "Scanning Applications…" : platform === "linux" ? "Reading package lists…" : "Reading Windows registry…"}
                    </div>
                    {appsProgressV2 && appsProgressV2.total > 0 && (
                      <div style={{ width: "100%", height: 6, borderRadius: 3, background: "rgba(255,255,255,0.1)", overflow: "hidden" }}>
                        <div style={{
                          height: "100%", borderRadius: 3, background: "#1E6B3C",
                          width: `${Math.round((appsProgressV2.scanned / appsProgressV2.total) * 100)}%`,
                          transition: "width 0.15s ease",
                        }} />
                      </div>
                    )}
                    <div key={appsProgressV2?.currentName} style={{ color: S.muted, fontSize: 13, maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", textAlign: "center", minHeight: 18, animation: appsProgressV2?.currentName ? "fadeInName 0.15s ease forwards" : "none" }}>
                      {appsProgressV2?.currentName ? `Checking ${appsProgressV2.currentName}…` : ""}
                    </div>
                  </div>
                </div>
              )}

              {/* Results */}
              {appsDoneV2 && !loadingAppsV2 && (() => {
                const q = v3Search.toLowerCase().trim();
                const filtered = q
                  ? appListV2.filter(a => a.name.toLowerCase().includes(q) || a.publisher.toLowerCase().includes(q))
                  : appListV2;
                const removable = filtered.filter(a => !a.isSystemApp);
                const systemCount = appListV2.filter(a => a.isSystemApp).length;

                return (
                  <>
                    {/* Summary row */}
                    <div style={{
                      background: S.card, borderRadius: 12, padding: "12px 18px",
                      marginBottom: 12, display: "flex", alignItems: "center", gap: 20, flexWrap: "wrap",
                    }}>
                      <div>
                        <span style={{ fontSize: 22, fontWeight: 800, color: S.text }}>{removable.length}</span>
                        <span style={{ fontSize: 12, color: S.muted, marginLeft: 6 }}>removable</span>
                      </div>
                      <div style={{ width: 1, height: 28, background: S.border }} />
                      <div>
                        <span style={{ fontSize: 22, fontWeight: 800, color: S.orange }}>
                          {fmtMb(appListV2.reduce((s, a) => s + a.sizeMb + a.associatedSizeMb, 0))}
                        </span>
                        <span style={{ fontSize: 12, color: S.muted, marginLeft: 6 }}>total installed</span>
                      </div>
                      {systemCount > 0 && (
                        <>
                          <div style={{ width: 1, height: 28, background: S.border }} />
                          <div style={{ fontSize: 12, color: S.muted }}>🔒 {systemCount} system{platform === "linux" ? " packages" : " apps"} protected</div>
                        </>
                      )}
                      {/* Search */}
                      <div style={{ marginLeft: "auto", position: "relative" }}>
                        <input
                          type="text"
                          placeholder="Search apps…"
                          value={v3Search}
                          onChange={e => setV3Search(e.target.value)}
                          style={{
                            background: "rgba(255,255,255,0.06)", border: `1px solid ${S.border}`,
                            borderRadius: 8, color: S.text, fontSize: 13, padding: "6px 30px 6px 10px",
                            outline: "none", width: 180,
                          }}
                        />
                        {v3Search && (
                          <button
                            onClick={() => setV3Search("")}
                            style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: S.muted, cursor: "pointer", fontSize: 14, padding: 0 }}
                          >×</button>
                        )}
                      </div>
                    </div>

                    {/* App list */}
                    <div style={{ background: S.card, borderRadius: 14, overflow: "hidden" }}>
                      {filtered.length === 0 && (
                        <div style={{ padding: 32, textAlign: "center", color: S.muted, fontSize: 13 }}>
                          No apps match "{v3Search}"
                        </div>
                      )}
                      {filtered.map((app) => {
                        const totalMb = app.sizeMb + app.associatedSizeMb;
                        const isUninstalling = uninstallingAppV2 === app.appPath;
                        const maxMb = Math.max(...appListV2.map(a => a.sizeMb + a.associatedSizeMb), 1);
                        const barPct = Math.min(100, Math.round((totalMb / maxMb) * 100));

                        return (
                          <div key={app.appPath} style={{
                            display: "flex", alignItems: "center", gap: 12, padding: "12px 16px",
                            borderBottom: `1px solid ${S.border}`,
                            opacity: app.isSystemApp ? 0.5 : 1,
                            transition: "background 0.15s",
                          }}>
                            {/* Icon */}
                            <div style={{
                              width: 38, height: 38, borderRadius: 10, flexShrink: 0,
                              background: app.isSystemApp ? "rgba(255,255,255,0.04)" : "#1E6B3C18",
                              display: "flex", alignItems: "center", justifyContent: "center", fontSize: 19,
                            }}>
                              {app.isSystemApp ? "🔒" : platform === "linux" ? "📦" : "🧹"}
                            </div>

                            {/* Info */}
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                <span style={{ fontSize: 14, color: S.text, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                  {app.name}
                                </span>
                                {app.isSystemApp && (
                                  <span style={{ fontSize: 9, fontWeight: 800, padding: "2px 6px", borderRadius: 5, background: "rgba(255,255,255,0.07)", color: S.muted, flexShrink: 0 }}>
                                    PROTECTED
                                  </span>
                                )}
                              </div>
                              <div style={{ fontSize: 11, color: S.muted, marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                {[app.version && `v${app.version}`, app.publisher].filter(Boolean).join(" · ") || (platform === "linux" ? "Linux package" : "Third-party app")}
                              </div>
                              {/* Size bar */}
                              {totalMb > 0 && (
                                <div style={{ marginTop: 5, height: 3, borderRadius: 2, background: "rgba(255,255,255,0.06)", overflow: "hidden", width: "100%" }}>
                                  <div style={{
                                    height: "100%", borderRadius: 2,
                                    background: totalMb > 1024 ? S.orange : totalMb > 200 ? "#FFD700" : S.green,
                                    width: `${barPct}%`,
                                    transition: "width 0.3s ease",
                                  }} />
                                </div>
                              )}
                            </div>

                            {/* Size */}
                            <div style={{ textAlign: "right", flexShrink: 0 }}>
                              <div style={{ fontSize: 13, fontWeight: 700, color: totalMb > 1024 ? S.orange : S.text }}>
                                {totalMb > 0 ? fmtMb(totalMb) : "—"}
                              </div>
                              {app.associatedSizeMb > 0.5 && (
                                <div style={{ fontSize: 9, color: S.muted, marginTop: 1 }}>
                                  +{fmtMb(app.associatedSizeMb)} data
                                </div>
                              )}
                            </div>

                            {/* Actions — Show only on Mac (Windows appPath is a registry key, not a file path) */}
                            {!app.isSystemApp && platform === "darwin" && (
                              <button
                                onClick={() => window.cleaner.openPath(app.appPath)}
                                style={{ background: "rgba(255,255,255,0.05)", border: "none", borderRadius: 6, color: S.muted, fontSize: 11, padding: "4px 8px", cursor: "pointer", flexShrink: 0 }}
                              >
                                Show
                              </button>
                            )}
                            <button
                              onClick={() => !app.isSystemApp && setConfirmAppV2(app)}
                              disabled={app.isSystemApp || isUninstalling}
                              style={{
                                background: app.isSystemApp ? "rgba(255,255,255,0.03)" : "#1E6B3C22",
                                border: `1px solid ${app.isSystemApp ? "transparent" : "#1E6B3C55"}`,
                                borderRadius: 8, color: app.isSystemApp ? S.muted : "#1E6B3C",
                                fontSize: 12, fontWeight: 700, padding: "5px 13px",
                                cursor: app.isSystemApp || isUninstalling ? "not-allowed" : "pointer",
                                flexShrink: 0, opacity: isUninstalling ? 0.5 : 1, transition: "all 0.15s",
                              }}
                            >
                              {isUninstalling ? "Removing…" : app.isSystemApp ? "Protected" : "Remove"}
                            </button>
                          </div>
                        );
                      })}
                    </div>
                  </>
                );
              })()}
            </>
          )}

          {/* ── External Drives / USB tab ── */}
          {isExternalTab && (
            <>
              {externalVolumesError && (
                <div style={{ textAlign: "center", padding: 40 }}>
                  <div style={{ fontSize: 48, marginBottom: 12 }}>⚠️</div>
                  <div style={{ fontSize: 16, color: S.orange, fontWeight: 600 }}>{externalVolumesError}</div>
                </div>
              )}
              {!externalVolumesError && externalVolumes.length === 0 && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 12 }}>
                  <div style={{ fontSize: 48 }}>💾</div>
                  <div style={{ fontSize: 16, color: S.text, fontWeight: 600 }}>No external drives found</div>
                  <div style={{ fontSize: 13, color: S.muted }}>Plug in a USB drive, SD card, or external HDD and scan again.</div>
                </div>
              )}
              {externalVolumes.map((vol) => {
                const usedGb = vol.totalGb - vol.freeGb;
                const pct = vol.totalGb > 0 ? Math.round((usedGb / vol.totalGb) * 100) : 0;
                const scanResult = usbScanResults[vol.path];
                const isScanning = scanningUsb.has(vol.path);
                const isCleaning = cleaningUsb.has(vol.path);
                return (
                  <div key={vol.path} style={{ background: S.card, borderRadius: 14, padding: "18px 20px", marginBottom: 16 }}>
                    {/* Drive header */}
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                      <div>
                        <span style={{ fontSize: 16, fontWeight: 700, color: S.text }}>💾 {vol.name}</span>
                        {vol.totalGb > 0 && (
                          <span style={{ fontSize: 12, color: S.muted, marginLeft: 10 }}>
                            {usedGb.toFixed(1)} GB used of {vol.totalGb.toFixed(1)} GB
                          </span>
                        )}
                      </div>
                      <button
                        onClick={() => handleScanUsb(vol.path)}
                        disabled={isScanning || isCleaning}
                        style={{
                          padding: "6px 16px", borderRadius: 8, border: "none",
                          background: S.teal + "22", color: S.teal,
                          fontSize: 13, fontWeight: 600,
                          cursor: isScanning || isCleaning ? "not-allowed" : "pointer",
                          opacity: isScanning || isCleaning ? 0.6 : 1,
                        }}
                      >
                        {isScanning ? "Scanning…" : scanResult ? "Re-scan" : "Scan Drive"}
                      </button>
                    </div>

                    {/* Capacity bar */}
                    {vol.totalGb > 0 && (
                      <div style={{ height: 6, background: "rgba(0,0,0,0.08)", borderRadius: 3, overflow: "hidden", marginBottom: 14 }}>
                        <div style={{ height: "100%", width: `${pct}%`, background: pct > 85 ? S.red : S.teal, borderRadius: 3, transition: "width 0.4s" }} />
                      </div>
                    )}

                    {/* Scanning spinner */}
                    {isScanning && (
                      <div style={{ display: "flex", alignItems: "center", gap: 10, color: S.muted, fontSize: 13, padding: "8px 0" }}>
                        <div style={{ width: 16, height: 16, borderRadius: "50%", border: `2px solid rgba(0,0,0,0.08)`, borderTop: `2px solid ${S.teal}`, animation: "spin 0.8s linear infinite", flexShrink: 0 }} />
                        Scanning drive contents…
                      </div>
                    )}

                    {/* Scan results */}
                    {!isScanning && scanResult && (
                      <>
                        {/* Top folders breakdown */}
                        {scanResult.topFolders.length > 0 && (
                          <div style={{ marginBottom: 14 }}>
                            <div style={{ fontSize: 11, fontWeight: 700, color: S.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 8 }}>
                              What's on this drive
                            </div>
                            {scanResult.topFolders.slice(0, 8).map((folder) => {
                              const folderPct = vol.totalGb > 0 ? Math.min(100, (folder.sizeMb / 1024 / vol.totalGb) * 100) : 0;
                              return (
                                <div key={folder.path} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                                  <div style={{ fontSize: 12, color: S.text, flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                    {folder.name}
                                  </div>
                                  <div style={{ width: 80, height: 4, background: "rgba(0,0,0,0.06)", borderRadius: 2, overflow: "hidden", flexShrink: 0 }}>
                                    <div style={{ height: "100%", width: `${folderPct}%`, background: S.teal, borderRadius: 2 }} />
                                  </div>
                                  <div style={{ fontSize: 12, color: S.muted, width: 58, textAlign: "right", flexShrink: 0 }}>{fmtMb(folder.sizeMb)}</div>
                                  <button
                                    onClick={() => revealPath(folder.path)}
                                    style={{ background: "rgba(0,0,0,0.04)", border: "none", borderRadius: 5, color: S.muted, fontSize: 10, padding: "2px 7px", cursor: "pointer", flexShrink: 0 }}
                                  >
                                    Show
                                  </button>
                                </div>
                              );
                            })}
                          </div>
                        )}

                        {/* Junk items */}
                        {scanResult.junkItems.length > 0 ? (
                          <div style={{ background: S.card2, borderRadius: 10, padding: "12px 14px" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                              <div style={{ fontSize: 12, fontWeight: 700, color: S.orange }}>
                                🗑 {fmtMb(scanResult.totalJunkMb)} of hidden junk found
                              </div>
                              <button
                                onClick={() => handleCleanUsbJunk(vol.path, scanResult.junkItems.map(j => j.path))}
                                disabled={isCleaning}
                                style={{
                                  padding: "5px 14px", borderRadius: 7, border: "none",
                                  background: S.red, color: "#fff",
                                  fontSize: 12, fontWeight: 700,
                                  cursor: isCleaning ? "not-allowed" : "pointer",
                                  opacity: isCleaning ? 0.6 : 1,
                                }}
                              >
                                {isCleaning ? "Cleaning…" : "Clean Junk"}
                              </button>
                            </div>
                            {scanResult.junkItems.map((item) => (
                              <div key={item.path} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "5px 0", borderTop: `1px solid ${S.border}` }}>
                                <span style={{ fontSize: 12, color: S.text }}>{item.name}</span>
                                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                  {!item.safe && <span style={{ fontSize: 10, color: S.orange }}>Review</span>}
                                  <span style={{ fontSize: 12, color: S.muted }}>{fmtMb(item.sizeMb)}</span>
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div style={{ fontSize: 13, color: S.green, fontWeight: 600 }}>✓ No hidden junk found on this drive</div>
                        )}

                        {scanResult.topFolders.length === 0 && scanResult.junkItems.length === 0 && (
                          <div style={{ fontSize: 13, color: S.muted }}>Drive appears empty or contents are not accessible.</div>
                        )}
                      </>
                    )}
                  </div>
                );
              })}
            </>
          )}

          {/* ── Repair / Disk Health tab ── */}
          {isRepairTab && (
            <>
              {!loadingHealth && !diskHealth && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                  <div style={{ fontSize: 48 }}>🔧</div>
                  <div style={{ fontSize: 15, color: S.muted, textAlign: "center" }}>
                    Click <strong style={{ color: S.text }}>Scan Disk</strong> to check your drive health and find broken files
                  </div>
                </div>
              )}
              {loadingHealth && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                  <div style={{ width: 60, height: 60, borderRadius: "50%", border: `4px solid rgba(255,255,255,0.08)`, borderTop: `4px solid ${S.teal}`, animation: "spin 0.8s linear infinite" }} />
                  <div style={{ color: S.muted, fontSize: 15 }}>Checking disk health…</div>
                  <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                </div>
              )}
              {diskHealth && !loadingHealth && (
                <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

                  {/* Error banner (e.g. wmic unavailable on Windows) */}
                  {diskHealth.error && (
                    <div style={{
                      background: S.orange + "18",
                      border: `1px solid ${S.orange}44`,
                      borderRadius: 12,
                      padding: "14px 18px",
                      display: "flex",
                      alignItems: "flex-start",
                      gap: 12,
                    }}>
                      <span style={{ fontSize: 20, flexShrink: 0 }}>⚠️</span>
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 700, color: S.orange, marginBottom: 4 }}>
                          Could not read disk info
                        </div>
                        <div style={{ fontSize: 12, color: S.muted, lineHeight: 1.5 }}>
                          {diskHealth.error}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* SMART status card */}
                  <div style={{ background: S.card, borderRadius: 14, padding: "20px 24px", display: "flex", alignItems: "center", gap: 20 }}>
                    <div style={{
                      width: 52, height: 52, borderRadius: 14, flexShrink: 0,
                      background: diskHealth.smartStatus === "Verified" ? S.green + "22" : S.red + "22",
                      display: "flex", alignItems: "center", justifyContent: "center", fontSize: 26,
                    }}>
                      {diskHealth.smartStatus === "Verified" ? "✅" : diskHealth.smartStatus === "Unknown" ? "❓" : "⚠️"}
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 16, fontWeight: 700, color: S.text }}>{diskHealth.volumeName}</div>
                      <div style={{ fontSize: 13, color: S.muted, marginTop: 2 }}>
                        {diskHealth.fileSystem} · {diskHealth.totalGb.toFixed(0)} GB total · {diskHealth.freeGb.toFixed(1)} GB free
                      </div>
                    </div>
                    <div style={{ textAlign: "right", flexShrink: 0 }}>
                      <div style={{
                        fontSize: 13, fontWeight: 700, padding: "4px 12px", borderRadius: 20,
                        background: diskHealth.smartStatus === "Verified" ? S.green + "22" : S.red + "22",
                        color: diskHealth.smartStatus === "Verified" ? S.green : diskHealth.smartStatus === "Unknown" ? S.muted : S.red,
                        border: `1px solid ${diskHealth.smartStatus === "Verified" ? S.green + "44" : S.red + "44"}`,
                      }}>
                        S.M.A.R.T.: {diskHealth.smartStatus}
                      </div>
                      {diskHealth.smartStatus === "Verified" && (
                        <div style={{ fontSize: 11, color: S.muted, marginTop: 6 }}>Drive is healthy</div>
                      )}
                    </div>
                  </div>

                  {/* Broken symlinks card */}
                  <div style={{ background: S.card, borderRadius: 14, overflow: "hidden" }}>
                    <div style={{ padding: "16px 20px", display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: diskHealth.brokenSymlinks.length > 0 ? `1px solid ${S.border}` : "none" }}>
                      <div>
                        <div style={{ fontSize: 15, fontWeight: 700, color: S.text }}>🔗 Broken Symlinks</div>
                        <div style={{ fontSize: 13, color: S.muted, marginTop: 2 }}>
                          {diskHealth.brokenSymlinks.length === 0
                            ? "No broken symlinks found"
                            : `${diskHealth.brokenSymlinks.length} broken link${diskHealth.brokenSymlinks.length > 1 ? "s" : ""} found`}
                        </div>
                      </div>
                      {diskHealth.brokenSymlinks.length > 0 && (
                        <button
                          onClick={() => handleFixSymlinks(diskHealth.brokenSymlinks)}
                          disabled={fixingSymlinks}
                          style={{
                            padding: "7px 16px", borderRadius: 8, border: "none",
                            background: S.teal + "22", color: S.teal, fontSize: 13, fontWeight: 600,
                            cursor: fixingSymlinks ? "not-allowed" : "pointer", opacity: fixingSymlinks ? 0.6 : 1,
                          }}
                        >
                          {fixingSymlinks ? "Fixing…" : "Fix All"}
                        </button>
                      )}
                    </div>
                    {diskHealth.brokenSymlinks.slice(0, 12).map((p, i) => (
                      <div key={i} style={{ padding: "9px 20px", borderBottom: i < Math.min(diskHealth.brokenSymlinks.length, 12) - 1 ? `1px solid ${S.border}` : "none", fontSize: 12, color: S.muted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {p}
                      </div>
                    ))}
                    {diskHealth.brokenSymlinks.length > 12 && (
                      <div style={{ padding: "9px 20px", fontSize: 12, color: S.muted }}>
                        …and {diskHealth.brokenSymlinks.length - 12} more
                      </div>
                    )}
                  </div>

                  {/* Volume verify card */}
                  <div style={{ background: S.card, borderRadius: 14, overflow: "hidden" }}>
                    <div style={{ padding: "16px 20px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <div>
                        <div style={{ fontSize: 15, fontWeight: 700, color: S.text }}>🗂 Volume Verification</div>
                        <div style={{ fontSize: 13, color: S.muted, marginTop: 2 }}>
                          {verifyOutput ? "Scan complete" : "Deep scan for filesystem errors (takes 1–2 min)"}
                        </div>
                      </div>
                      <button
                        onClick={handleVerifyDisk}
                        disabled={verifying}
                        style={{
                          padding: "7px 16px", borderRadius: 8, border: "none",
                          background: "rgba(255,255,255,0.08)", color: S.text, fontSize: 13, fontWeight: 600,
                          cursor: verifying ? "not-allowed" : "pointer", opacity: verifying ? 0.6 : 1,
                        }}
                      >
                        {verifying ? "Verifying…" : verifyOutput ? "Re-run" : "Run Verify"}
                      </button>
                    </div>
                    {verifying && (
                      <div style={{ padding: "12px 20px", borderTop: `1px solid ${S.border}`, color: S.muted, fontSize: 13 }}>
                        Running diskutil verifyVolume / — this may take a minute…
                      </div>
                    )}
                    {verifyOutput && (
                      <div style={{ padding: "14px 20px", borderTop: `1px solid ${S.border}` }}>
                        <pre style={{ fontSize: 11, color: verifyOutput.toLowerCase().includes("error") || verifyOutput.toLowerCase().includes("fail") ? S.orange : S.green, margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word", maxHeight: 200, overflow: "auto" }}>
                          {verifyOutput.trim()}
                        </pre>
                      </div>
                    )}
                  </div>

                  {/* ── System Repair Panel ── */}
                  <div style={{ background: S.card, borderRadius: 14, overflow: "hidden" }}>
                    <div style={{ padding: "16px 20px", display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: repairSteps.length > 0 ? `1px solid ${S.border}` : "none" }}>
                      <div>
                        <div style={{ fontSize: 15, fontWeight: 700, color: S.text }}>
                          🛠 System Repair
                        </div>
                        <div style={{ fontSize: 12, color: S.muted, marginTop: 2 }}>
                          {platform === "darwin"
                            ? "Flush DNS · Rebuild font cache · Fix Launch Services · Repair volume · Spotlight"
                            : platform === "win32"
                              ? "Reset network · Restart Audio & Search · SFC system scan · DISM repair"
                              : "Fix broken packages · Flush DNS · Rebuild lib cache · Filesystem check"}
                        </div>
                      </div>
                      <button
                        onClick={handleRunRepairs}
                        disabled={repairing}
                        style={{
                          padding: "8px 18px", borderRadius: 9, border: "none",
                          background: repairing ? "rgba(255,255,255,0.06)" : "#0060CC",
                          color: repairing ? S.muted : "#fff",
                          fontSize: 13, fontWeight: 700,
                          cursor: repairing ? "not-allowed" : "pointer",
                          opacity: repairing ? 0.7 : 1, flexShrink: 0,
                          transition: "all 0.2s",
                        }}
                      >
                        {repairing ? "Repairing…" : repairDone ? "↺ Run Again" : "Run All Repairs"}
                      </button>
                    </div>

                    {/* Live step list */}
                    {repairSteps.length > 0 && (
                      <div>
                        {repairSteps.map((step, i) => {
                          const icon = step.status === "running" ? "⏳"
                            : step.status === "ok" ? "✅"
                            : step.status === "warn" ? "⚠️"
                            : step.status === "error" ? "❌"
                            : step.status === "skipped" ? "⏭"
                            : "•";
                          const color = step.status === "ok" ? S.green
                            : step.status === "warn" ? S.orange
                            : step.status === "error" ? S.red
                            : step.status === "running" ? S.blue
                            : S.muted;
                          return (
                            <div key={step.id} style={{
                              padding: "11px 20px",
                              borderBottom: i < repairSteps.length - 1 ? `1px solid ${S.border}` : "none",
                              display: "flex", alignItems: "flex-start", gap: 12,
                            }}>
                              <span style={{ fontSize: 15, flexShrink: 0, marginTop: 1 }}>{icon}</span>
                              <div style={{ flex: 1, minWidth: 0 }}>
                                <div style={{ fontSize: 13, fontWeight: 600, color: S.text }}>{step.label}</div>
                                {step.detail && (
                                  <div style={{ fontSize: 11, color, marginTop: 3, lineHeight: 1.4, wordBreak: "break-word" }}>
                                    {step.detail}
                                  </div>
                                )}
                                {step.status === "running" && (
                                  <div style={{ marginTop: 6, height: 3, borderRadius: 2, background: "rgba(255,255,255,0.08)", overflow: "hidden", width: "100%" }}>
                                    <div style={{ height: "100%", borderRadius: 2, background: "#0060CC", width: "60%", animation: "indeterminate 1.4s ease infinite" }} />
                                    <style>{`@keyframes indeterminate { 0%{transform:translateX(-100%)} 100%{transform:translateX(300%)} }`}</style>
                                  </div>
                                )}
                              </div>
                            </div>
                          );
                        })}

                        {/* Summary row */}
                        {repairDone && repairSummary && (
                          <div style={{
                            padding: "14px 20px",
                            borderTop: `1px solid ${S.border}`,
                            background: repairSummary.errorCount === 0 ? S.green + "10" : S.orange + "10",
                            display: "flex", alignItems: "center", gap: 14,
                          }}>
                            <span style={{ fontSize: 22 }}>{repairSummary.errorCount === 0 ? "✅" : "⚠️"}</span>
                            <div>
                              <div style={{ fontSize: 14, fontWeight: 700, color: repairSummary.errorCount === 0 ? S.green : S.orange }}>
                                {repairSummary.fixedCount} repair{repairSummary.fixedCount !== 1 ? "s" : ""} completed
                                {repairSummary.errorCount > 0 ? `, ${repairSummary.errorCount} needed admin rights` : " — all clean"}
                              </div>
                              <div style={{ fontSize: 11, color: S.muted, marginTop: 2 }}>
                                {platform === "win32"
                                  ? "A reboot is recommended to apply network and system file changes."
                                  : platform === "darwin"
                                    ? "Some repairs (DNS, font cache) require admin password — run from Terminal if skipped."
                                    : "Some repairs require sudo — run from Terminal if skipped."}
                              </div>
                            </div>
                            <button
                              onClick={() => window.cleaner.diskHealth().then(setDiskHealth)}
                              style={{
                                marginLeft: "auto", padding: "6px 14px", borderRadius: 8, border: "none",
                                background: "rgba(255,255,255,0.08)", color: S.text, fontSize: 12,
                                fontWeight: 600, cursor: "pointer", flexShrink: 0,
                              }}
                            >↺ Re-scan disk</button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                </div>
              )}
            </>
          )}

          {/* ── Scan All tab ── keep mounted (display:none) while scan is running so
              progress state stays visible when the user switches tabs mid-scan */}
          {(tab === "scan-all" || scanningAll) && (
            <div style={{ display: tab === "scan-all" ? undefined : "none" }}>
              {!scanningAll && !scanAllDone && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 20 }}>
                  <div style={{ fontSize: 56 }}>⚡</div>
                  <div style={{ fontSize: 18, fontWeight: 700, color: S.text }}>Full System Scan</div>
                  <div style={{ fontSize: 14, color: S.muted, textAlign: "center", maxWidth: 360, lineHeight: 1.6 }}>
                    Runs all scans at once — junk files, virus & malware, disk health, and broken symlinks.
                  </div>
                  <div style={{ fontSize: 13, color: S.muted }}>Click <strong style={{ color: "#7030B0" }}>⚡ Scan All</strong> to begin</div>
                </div>
              )}

              {scanningAll && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 20 }}>
                  <div style={{ position: "relative", width: 72, height: 72 }}>
                    <div style={{ width: 72, height: 72, borderRadius: "50%", border: `5px solid rgba(112,48,176,0.15)`, borderTop: `5px solid #7030B0`, animation: "spin 0.9s linear infinite" }} />
                    <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                  </div>
                  <div style={{ fontSize: 17, fontWeight: 700, color: S.text }}>Scanning everything…</div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 10, alignItems: "center", width: "100%", maxWidth: 360 }}>
                    <style>{`@keyframes pulse { 0%,100%{opacity:0.3} 50%{opacity:1} }`}</style>

                    {/* Junk row */}
                    <div style={{ width: "100%", textAlign: "center" }}>
                      <div style={{ fontSize: 13, color: S.muted, display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}>
                        <span>🗑</span> Junk files
                        {scanAllRowStatus.junk === "ok" ? (
                          <span style={{ marginLeft: 4, fontSize: 15, lineHeight: 1 }}>✅</span>
                        ) : scanAllRowStatus.junk === "error" ? (
                          <span style={{ marginLeft: 4, fontSize: 15, lineHeight: 1 }} title="Scan failed">❌</span>
                        ) : (
                          <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#7030B0", opacity: 0.6, animation: "pulse 1.2s ease-in-out infinite", display: "inline-block", marginLeft: 4 }} />
                        )}
                      </div>
                      {scanAllJunkProgress && scanAllRowStatus.junk === "pending" && (
                        <div style={{ fontSize: 11, color: "#7030B0", marginTop: 3, opacity: 0.85 }}>
                          {scanAllJunkProgress.found > 0 ? `${scanAllJunkProgress.found} item${scanAllJunkProgress.found !== 1 ? "s" : ""} found` : "Checking locations…"}
                          {" · "}{scanAllJunkProgress.name}
                        </div>
                      )}
                      <div style={{ width: "100%", height: 3, background: "rgba(112,48,176,0.15)", borderRadius: 2, marginTop: 6, overflow: "hidden" }}>
                        <div style={{
                          height: "100%",
                          width: scanAllRowStatus.junk !== "pending" ? "100%" : `${scanAllJunkProgress ? Math.min(100, Math.round((scanAllJunkProgress.scanned / Math.max(scanAllJunkProgress.total, 1)) * 100)) : 0}%`,
                          background: scanAllRowStatus.junk === "error" ? S.red : "#7030B0",
                          borderRadius: 2,
                          transition: "width 0.2s ease",
                        }} />
                      </div>
                    </div>

                    {/* Virus row */}
                    <div style={{ width: "100%", textAlign: "center" }}>
                      <div style={{ fontSize: 13, color: S.muted, display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}>
                        <span>🛡</span> Viruses &amp; malware
                        {scanAllRowStatus.virus === "ok" ? (
                          <span style={{ marginLeft: 4, fontSize: 15, lineHeight: 1 }}>✅</span>
                        ) : scanAllRowStatus.virus === "error" ? (
                          <span style={{ marginLeft: 4, fontSize: 15, lineHeight: 1 }} title="Scan failed">❌</span>
                        ) : (
                          <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#7030B0", opacity: 0.6, animation: "pulse 1.2s ease-in-out infinite", display: "inline-block", marginLeft: 4 }} />
                        )}
                      </div>
                      {scanAllVirusPass && scanAllRowStatus.virus === "pending" && (
                        <div style={{ fontSize: 11, color: "#7030B0", marginTop: 3, opacity: 0.85 }}>
                          {scanAllVirusPass}
                        </div>
                      )}
                    </div>

                    {/* Disk health row */}
                    <div style={{ width: "100%", textAlign: "center" }}>
                      <div style={{ fontSize: 13, color: S.muted, display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}>
                        <span>🔧</span> Disk health
                        {scanAllRowStatus.disk === "ok" ? (
                          <span style={{ marginLeft: 4, fontSize: 15, lineHeight: 1 }}>✅</span>
                        ) : scanAllRowStatus.disk === "error" ? (
                          <span style={{ marginLeft: 4, fontSize: 15, lineHeight: 1 }} title="Scan failed">❌</span>
                        ) : (
                          <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#7030B0", opacity: 0.6, animation: "pulse 1.2s ease-in-out infinite", display: "inline-block", marginLeft: 4 }} />
                        )}
                      </div>
                      {scanAllDiskProgress && scanAllRowStatus.disk === "pending" && (
                        <div style={{ fontSize: 11, color: "#7030B0", marginTop: 3, opacity: 0.85 }}>
                          {scanAllDiskProgress}
                        </div>
                      )}
                      {(() => {
                        const line = scanAllDiskProgress ?? "";
                        const step = scanAllRowStatus.disk !== "pending" ? 3 : line.includes("symlink") ? 3 : line.includes("volume") || line.includes("Volume") ? 2 : line.includes("SMART") ? 1 : 0;
                        return (
                          <>
                            <div style={{ width: "100%", height: 3, background: "rgba(112,48,176,0.15)", borderRadius: 2, marginTop: 6, overflow: "hidden" }}>
                              <div style={{
                                height: "100%",
                                width: `${Math.round((step / 3) * 100)}%`,
                                background: scanAllRowStatus.disk === "error" ? S.red : "#7030B0",
                                borderRadius: 2,
                                transition: "width 0.4s ease",
                              }} />
                            </div>
                            {scanAllRowStatus.disk === "pending" && (
                              <div style={{ display: "flex", justifyContent: "space-between", marginTop: 3 }}>
                                {["Checking SMART", "Reading volume", "Scanning symlinks"].map((label, i) => (
                                  <span key={label} style={{ fontSize: 9, color: step > i ? "#7030B0" : S.muted, opacity: step > i ? 1 : 0.5, transition: "color 0.3s, opacity 0.3s" }}>
                                    {label}
                                  </span>
                                ))}
                              </div>
                            )}
                          </>
                        );
                      })()}
                    </div>

                    {/* Symlinks row — part of disk health scan */}
                    <div style={{ fontSize: 13, color: S.muted, display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}>
                      <span>🔗</span> Broken symlinks
                      {scanAllRowStatus.disk === "ok" ? (
                        <span style={{ marginLeft: 4, fontSize: 15, lineHeight: 1 }}>✅</span>
                      ) : scanAllRowStatus.disk === "error" ? (
                        <span style={{ marginLeft: 4, fontSize: 15, lineHeight: 1 }} title="Scan failed">❌</span>
                      ) : (
                        <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#7030B0", opacity: 0.6, animation: "pulse 1.2s ease-in-out infinite", display: "inline-block", marginLeft: 4 }} />
                      )}
                    </div>
                  </div>
                </div>
              )}

              {scanAllDone && !scanningAll && (
                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

                  {/* Error banner — shown when one or more scans failed */}
                  {scanAllError && (
                    <div style={{ background: "#ff3b3018", border: "1px solid #ff3b3044", borderRadius: 14, padding: "14px 20px", display: "flex", alignItems: "flex-start", gap: 12 }}>
                      <div style={{ fontSize: 22, flexShrink: 0 }}>⚠️</div>
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 700, color: "#ff3b30" }}>Scan incomplete</div>
                        <div style={{ fontSize: 13, color: "#ff3b30", opacity: 0.85, marginTop: 3, lineHeight: 1.5 }}>{scanAllError}</div>
                      </div>
                    </div>
                  )}

                  {/* Summary row */}
                  {(() => {
                    const junkMb = scanResults.reduce((s, r) => s + r.sizeMb, 0);
                    const threats = virusResult?.threats.length ?? 0;
                    const symlinks = diskHealth?.brokenSymlinks.length ?? 0;
                    const smartOk = diskHealth?.smartStatus === "Verified";
                    const totalIssues = (junkMb > 0 ? 1 : 0) + threats + (symlinks > 0 ? 1 : 0) + (smartOk ? 0 : 1);
                    return (
                      <div style={{ background: totalIssues === 0 ? S.green + "18" : "#7030B018", border: `1px solid ${totalIssues === 0 ? S.green + "44" : "#7030B044"}`, borderRadius: 14, padding: "18px 24px", display: "flex", alignItems: "center", gap: 16 }}>
                        <div style={{ fontSize: 34 }}>{totalIssues === 0 ? "✅" : "⚠️"}</div>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 16, fontWeight: 700, color: S.text }}>
                            {totalIssues === 0 ? "Your Mac is clean!" : `${totalIssues} issue${totalIssues !== 1 ? "s" : ""} found`}
                          </div>
                          <div style={{ fontSize: 13, color: S.muted, marginTop: 3 }}>
                            {junkMb > 0 && `${fmtMb(junkMb)} junk  `}
                            {threats > 0 && `${threats} threat${threats !== 1 ? "s" : ""}  `}
                            {symlinks > 0 && `${symlinks} broken symlink${symlinks !== 1 ? "s" : ""}  `}
                            {!smartOk && diskHealth && `Drive: ${diskHealth.smartStatus}`}
                            {totalIssues === 0 && "No junk, no threats, disk is healthy"}
                          </div>
                        </div>
                      </div>
                    );
                  })()}

                  {/* Junk row */}
                  {(() => {
                    const junkMb = scanResults.reduce((s, r) => s + r.sizeMb, 0);
                    return (
                      <div style={{ background: S.card, borderRadius: 14, padding: "16px 20px", display: "flex", alignItems: "center", gap: 14 }}>
                        <div style={{ width: 42, height: 42, borderRadius: 12, background: S.orange + "22", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22, flexShrink: 0 }}>🗑</div>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 15, fontWeight: 700, color: S.text }}>System Junk</div>
                          <div style={{ fontSize: 13, color: S.muted, marginTop: 2 }}>
                            {junkMb > 0 ? `${fmtMb(junkMb)} across ${scanResults.length} items` : "Nothing to clean"}
                          </div>
                        </div>
                        {junkMb > 0 && (
                          <button
                            onClick={async () => {
                              if (!window.cleaner || selected.size === 0) return;
                              const r = await window.cleaner.clean(Array.from(selected));
                              setFreedMb(p => p + r.freedMb);
                              saveLastCleaned();
                              const fresh = await window.cleaner.scan();
                              setScanResults(fresh);
                              setSelected(new Set());
                              showToast(`Freed ${fmtMb(r.freedMb)}`);
                            }}
                            style={{ padding: "7px 16px", borderRadius: 8, border: "none", background: S.orange + "22", color: S.orange, fontSize: 13, fontWeight: 600, cursor: "pointer", flexShrink: 0 }}
                          >
                            Clean
                          </button>
                        )}
                        {junkMb === 0 && <div style={{ fontSize: 20 }}>✅</div>}
                      </div>
                    );
                  })()}

                  {/* Virus row */}
                  {virusResult && (
                    <div style={{ background: S.card, borderRadius: 14, padding: "16px 20px", display: "flex", alignItems: "center", gap: 14 }}>
                      <div style={{ width: 42, height: 42, borderRadius: 12, background: S.red + "22", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22, flexShrink: 0 }}>🛡</div>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 15, fontWeight: 700, color: S.text }}>Virus & Malware</div>
                        <div style={{ fontSize: 13, color: S.muted, marginTop: 2 }}>
                          {virusResult.threats.length > 0 ? `${virusResult.threats.length} threat${virusResult.threats.length !== 1 ? "s" : ""} detected` : "No threats found"}
                        </div>
                        {virusResult.threats.length > 0 && (
                          <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
                            {virusResult.threats.slice(0, 3).map((t, i) => (
                              <div key={i} style={{ fontSize: 12, color: S.red, display: "flex", alignItems: "center", gap: 6 }}>
                                <span style={{ width: 6, height: 6, borderRadius: "50%", background: S.red, flexShrink: 0, display: "inline-block" }} />
                                {t.name} — {t.severity}
                              </div>
                            ))}
                            {virusResult.threats.length > 3 && <div style={{ fontSize: 12, color: S.muted }}>…and {virusResult.threats.length - 3} more</div>}
                          </div>
                        )}
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 6, flexShrink: 0 }}>
                        {virusResult.threats.length > 0 && (
                          <button
                            onClick={async () => {
                              if (!window.cleaner || !virusResult) return;
                              for (const t of virusResult.threats) await window.cleaner.quarantineThreat(t.path);
                              setVirusResult(p => p ? { ...p, threats: [], status: "clean" } : null);
                              showToast("All threats quarantined");
                            }}
                            style={{ padding: "7px 14px", borderRadius: 8, border: "none", background: S.red + "22", color: S.red, fontSize: 13, fontWeight: 600, cursor: "pointer" }}
                          >
                            Quarantine All
                          </button>
                        )}
                        {virusResult.threats.length === 0 && <div style={{ fontSize: 20 }}>✅</div>}
                      </div>
                    </div>
                  )}

                  {/* Disk health row */}
                  {diskHealth && (
                    <div style={{ background: S.card, borderRadius: 14, padding: "16px 20px", display: "flex", alignItems: "center", gap: 14 }}>
                      <div style={{ width: 42, height: 42, borderRadius: 12, background: S.teal + "22", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22, flexShrink: 0 }}>🔧</div>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 15, fontWeight: 700, color: S.text }}>Disk Health</div>
                        <div style={{ fontSize: 13, color: S.muted, marginTop: 2 }}>
                          {diskHealth.volumeName} — S.M.A.R.T. {diskHealth.smartStatus} · {diskHealth.freeGb.toFixed(1)} GB free
                        </div>
                        {diskHealth.brokenSymlinks.length > 0 && (
                          <div style={{ fontSize: 12, color: S.orange, marginTop: 4 }}>
                            {diskHealth.brokenSymlinks.length} broken symlink{diskHealth.brokenSymlinks.length !== 1 ? "s" : ""}
                          </div>
                        )}
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 6, alignItems: "flex-end", flexShrink: 0 }}>
                        <div style={{ fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 12, background: diskHealth.smartStatus === "Verified" ? S.green + "22" : S.red + "22", color: diskHealth.smartStatus === "Verified" ? S.green : S.red }}>
                          {diskHealth.smartStatus}
                        </div>
                        {diskHealth.brokenSymlinks.length > 0 && (
                          <button
                            onClick={async () => {
                              if (!window.cleaner || !diskHealth) return;
                              await window.cleaner.fixSymlinks(diskHealth.brokenSymlinks);
                              const fresh = await window.cleaner.diskHealth();
                              setDiskHealth(fresh);
                              showToast(`Fixed ${diskHealth.brokenSymlinks.length} symlinks`);
                            }}
                            style={{ padding: "5px 12px", borderRadius: 7, border: "none", background: S.teal + "22", color: S.teal, fontSize: 12, fontWeight: 600, cursor: "pointer" }}
                          >
                            Fix Symlinks
                          </button>
                        )}
                      </div>
                    </div>
                  )}

                </div>
              )}
            </div>
          )}

          {/* ── Virus Scan tab ── */}
          {tab === "virus" && (
            <>
              {!loadingVirus && !virusResult && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                  <div style={{ fontSize: 52 }}>🛡</div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: S.text }}>Virus & Malware Scanner</div>
                  <div style={{ fontSize: 14, color: S.muted, textAlign: "center", maxWidth: 340 }}>
                    Scans LaunchAgents, startup folders, and known malware locations.
                    On Windows, also runs Windows Defender.
                  </div>
                  <div style={{ fontSize: 12, color: S.muted, marginTop: 4 }}>Click <strong style={{ color: S.text }}>Run Scan</strong> to start</div>
                </div>
              )}
              {loadingVirus && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                  <div style={{ width: 60, height: 60, borderRadius: "50%", border: `4px solid rgba(255,255,255,0.08)`, borderTop: `4px solid #FF453A`, animation: "spin 0.8s linear infinite" }} />
                  <div style={{ color: S.text, fontSize: 16, fontWeight: 700 }}>Scanning for threats…</div>
                  {virusProgress ? (
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
                      <div style={{ color: S.muted, fontSize: 13, textAlign: "center", maxWidth: 360 }}>
                        {virusProgress.msg}
                      </div>
                      <div style={{ color: S.muted, fontSize: 12, fontWeight: 600 }}>
                        {virusProgress.scanned.toLocaleString()} files scanned
                      </div>
                    </div>
                  ) : (
                    <div style={{ color: S.muted, fontSize: 13, textAlign: "center", maxWidth: 340 }}>
                      {isMac
                        ? "Checking LaunchAgents, Applications, and known malware paths"
                        : "Running Windows Defender + scanning startup locations"}
                    </div>
                  )}
                  <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                </div>
              )}
              {virusResult && !loadingVirus && (
                <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

                  {/* Status banner */}
                  <div style={{
                    background: virusResult.status === "clean" ? S.green + "18" : virusResult.status === "threats_found" ? "#FF453A18" : S.orange + "18",
                    border: `1px solid ${virusResult.status === "clean" ? S.green + "44" : virusResult.status === "threats_found" ? "#FF453A44" : S.orange + "44"}`,
                    borderRadius: 14, padding: "20px 24px", display: "flex", alignItems: "center", gap: 18,
                  }}>
                    <div style={{ fontSize: 36, flexShrink: 0 }}>
                      {virusResult.status === "clean" ? "✅" : virusResult.status === "threats_found" ? "⚠️" : "❓"}
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 16, fontWeight: 700, color: S.text }}>
                        {virusResult.status === "clean" ? "No threats found" : virusResult.status === "threats_found" ? `${virusResult.threats.length} threat${virusResult.threats.length !== 1 ? "s" : ""} detected` : "Scan error"}
                      </div>
                      <div style={{ fontSize: 13, color: S.muted, marginTop: 3 }}>
                        Behavioral scan — checked {virusResult.scannedCount.toLocaleString()} locations in {(virusResult.scanDuration / 1000).toFixed(1)}s
                        {virusResult.error ? ` — ${virusResult.error}` : ""}
                      </div>
                      {virusResult.status === "clean" && (
                        <div style={{ fontSize: 12, color: S.muted, marginTop: 4, fontStyle: "italic" }}>
                          Checks LaunchAgents, login items, startup scripts, and known threat locations. For full signature-based scanning, pair with an antivirus like Malwarebytes.
                        </div>
                      )}
                    </div>
                    <button
                      onClick={handleVirusScan}
                      style={{ padding: "7px 16px", borderRadius: 8, border: "none", background: "rgba(255,255,255,0.08)", color: S.text, fontSize: 13, fontWeight: 600, cursor: "pointer", flexShrink: 0 }}
                    >
                      Re-scan
                    </button>
                  </div>

                  {/* Threats list */}
                  {virusResult.threats.length > 0 && (
                    <div style={{ background: S.card, borderRadius: 14, overflow: "hidden" }}>
                      <div style={{ padding: "14px 20px", borderBottom: `1px solid ${S.border}`, fontSize: 14, fontWeight: 700, color: S.text }}>
                        Detected Threats
                      </div>
                      {virusResult.threats.map((threat, i) => {
                        const sevColor = threat.severity === "critical" ? "#FF453A" : threat.severity === "high" ? S.orange : threat.severity === "medium" ? S.teal : S.muted;
                        return (
                          <div key={i} style={{ padding: "14px 20px", borderBottom: i < virusResult.threats.length - 1 ? `1px solid ${S.border}` : "none", display: "flex", alignItems: "center", gap: 14 }}>
                            <div style={{ width: 8, height: 8, borderRadius: "50%", background: sevColor, flexShrink: 0 }} />
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ fontSize: 14, fontWeight: 600, color: S.text }}>{threat.name}</div>
                              <div style={{ fontSize: 12, color: S.muted, marginTop: 2 }}>{threat.description}</div>
                              <div style={{ fontSize: 11, color: S.muted, marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{threat.path}</div>
                            </div>
                            <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 6, flexShrink: 0 }}>
                              <div style={{ fontSize: 11, fontWeight: 700, padding: "2px 8px", borderRadius: 12, background: sevColor + "22", color: sevColor, textTransform: "uppercase" }}>
                                {threat.severity}
                              </div>
                              <button
                                onClick={() => handleQuarantine(threat)}
                                disabled={quarantining === threat.path}
                                style={{
                                  padding: "5px 12px", borderRadius: 7, border: "none",
                                  background: "#FF453A22", color: "#FF453A", fontSize: 12, fontWeight: 600,
                                  cursor: quarantining === threat.path ? "not-allowed" : "pointer",
                                  opacity: quarantining === threat.path ? 0.5 : 1,
                                }}
                              >
                                {quarantining === threat.path ? "Moving…" : "Quarantine"}
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {virusResult.status === "clean" && (
                    <div style={{ fontSize: 12, color: S.muted, textAlign: "center", padding: "4px 0 8px" }}>
                      For a deeper scan, consider running a full system scan with a dedicated antivirus tool.
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {/* ── Duplicates tab ── */}
          {tab === "duplicates" && (
            <>
              {!loadingDups && !dupsDone && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                  <div style={{ fontSize: 52 }}>👯</div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: S.text }}>Duplicate File Finder</div>
                  <div style={{ fontSize: 14, color: S.muted, textAlign: "center", maxWidth: 380 }}>
                    Scans Desktop, Documents, Downloads, Pictures, Music, and Movies for exact duplicate files using SHA-256 hashing.
                  </div>
                  <div style={{ fontSize: 12, color: S.muted, marginTop: 4 }}>Click <strong style={{ color: S.text }}>Scan for Duplicates</strong> to start</div>
                </div>
              )}
              {loadingDups && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                  <div style={{ width: 60, height: 60, borderRadius: "50%", border: `4px solid rgba(0,0,0,0.06)`, borderTop: `4px solid ${S.orange}`, animation: "spin 0.8s linear infinite" }} />
                  <div style={{ color: S.text, fontSize: 16, fontWeight: 700 }}>Scanning for duplicates…</div>
                  {dupProgress ? (
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
                      <div style={{ color: S.muted, fontSize: 13 }}>
                        {dupProgress.phase === "walk"
                          ? `Indexing files… ${dupProgress.scanned.toLocaleString()} / ${dupProgress.total.toLocaleString()}`
                          : `Hashing for duplicates… ${dupProgress.scanned.toLocaleString()} / ${dupProgress.total.toLocaleString()}`}
                      </div>
                      {dupProgress.total > 0 && (
                        <div style={{ width: 200, height: 4, borderRadius: 2, background: "rgba(0,0,0,0.08)", overflow: "hidden" }}>
                          <div style={{
                            height: "100%", borderRadius: 2, background: S.orange,
                            width: `${Math.min(100, Math.round((dupProgress.scanned / dupProgress.total) * 100))}%`,
                            transition: "width 0.3s ease",
                          }} />
                        </div>
                      )}
                    </div>
                  ) : (
                    <div style={{ color: S.muted, fontSize: 13 }}>Hashing files in Desktop, Documents, Downloads, Pictures, Music, Movies</div>
                  )}
                  <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                </div>
              )}
              {dupsDone && dupResult && (
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  {/* Summary bar */}
                  <div style={{ background: S.card, borderRadius: 14, padding: "16px 20px", display: "flex", alignItems: "center", gap: 24 }}>
                    <div style={{ textAlign: "center" }}>
                      <div style={{ fontSize: 22, fontWeight: 800, color: S.text }}>{dupResult.groups.length}</div>
                      <div style={{ fontSize: 11, color: S.muted }}>Duplicate Groups</div>
                    </div>
                    <div style={{ width: 1, height: 36, background: S.border }} />
                    <div style={{ textAlign: "center" }}>
                      <div style={{ fontSize: 22, fontWeight: 800, color: S.orange }}>{fmtMb(dupResult.totalWasteMb)}</div>
                      <div style={{ fontSize: 11, color: S.muted }}>Wasted Space</div>
                    </div>
                    <div style={{ width: 1, height: 36, background: S.border }} />
                    <div style={{ textAlign: "center" }}>
                      <div style={{ fontSize: 22, fontWeight: 800, color: S.text }}>{dupResult.scannedCount.toLocaleString()}</div>
                      <div style={{ fontSize: 11, color: S.muted }}>Files Scanned</div>
                    </div>
                    {dupResult.groups.length > 0 && (
                      <>
                        <div style={{ flex: 1 }} />
                        <button
                          onClick={() => {
                            const allDups = new Set<string>();
                            dupResult.groups.forEach(g => g.files.slice(1).forEach(f => allDups.add(f.path)));
                            setDupSelected(allDups);
                          }}
                          style={{ padding: "7px 16px", borderRadius: 8, border: `1px solid ${S.border}`, background: "transparent", color: S.text, fontSize: 13, fontWeight: 600, cursor: "pointer" }}
                        >
                          Select All Duplicates
                        </button>
                        <button
                          onClick={() => setDupSelected(new Set())}
                          style={{ padding: "7px 16px", borderRadius: 8, border: `1px solid ${S.border}`, background: "transparent", color: S.muted, fontSize: 13, cursor: "pointer" }}
                        >
                          Clear
                        </button>
                      </>
                    )}
                  </div>

                  {dupResult.groups.length === 0 ? (
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "60px 0", gap: 12 }}>
                      <div style={{ fontSize: 48 }}>✨</div>
                      <div style={{ fontSize: 18, color: S.text, fontWeight: 600 }}>No duplicates found!</div>
                      <div style={{ fontSize: 14, color: S.muted }}>All files in your common folders are unique.</div>
                    </div>
                  ) : (
                    dupResult.groups.map((group, gi) => (
                      <div key={group.hash} style={{ background: S.card, borderRadius: 14, overflow: "hidden" }}>
                        <div style={{ padding: "12px 20px", background: S.card2, borderBottom: `1px solid ${S.border}`, display: "flex", alignItems: "center", gap: 10 }}>
                          <span style={{ fontSize: 13, fontWeight: 700, color: S.text }}>{group.files.length} identical files</span>
                          <span style={{ fontSize: 12, color: S.muted }}>·</span>
                          <span style={{ fontSize: 12, color: S.orange, fontWeight: 600 }}>{fmtMb(group.sizeMb)} each</span>
                          <span style={{ fontSize: 12, color: S.muted }}>·</span>
                          <span style={{ fontSize: 12, color: S.muted }}>wasting {fmtMb(group.sizeMb * (group.files.length - 1))}</span>
                        </div>
                        {group.files.map((file, fi) => {
                          const isSelected = dupSelected.has(file.path);
                          const isFirst = fi === 0;
                          return (
                            <div key={file.path}
                              onClick={() => {
                                setDupSelected(prev => {
                                  const next = new Set(prev);
                                  if (next.has(file.path)) next.delete(file.path);
                                  else next.add(file.path);
                                  return next;
                                });
                              }}
                              style={{
                                padding: "12px 20px",
                                borderBottom: fi < group.files.length - 1 ? `1px solid ${S.border}` : "none",
                                display: "flex", alignItems: "center", gap: 14, cursor: "pointer",
                                background: isSelected ? "#FF453A11" : "transparent",
                                transition: "background 0.15s",
                              }}
                            >
                              <div style={{
                                width: 18, height: 18, borderRadius: 4, border: `2px solid ${isSelected ? "#C42020" : S.border}`,
                                background: isSelected ? "#C42020" : "transparent", flexShrink: 0,
                                display: "flex", alignItems: "center", justifyContent: "center",
                              }}>
                                {isSelected && <span style={{ color: "#fff", fontSize: 11, fontWeight: 900 }}>✓</span>}
                              </div>
                              <div style={{ flex: 1, minWidth: 0 }}>
                                <div style={{ fontSize: 13, fontWeight: 600, color: S.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                  {file.name}
                                  {isFirst && <span style={{ marginLeft: 8, fontSize: 10, fontWeight: 700, padding: "2px 6px", borderRadius: 6, background: "#1A8C3822", color: S.green }}>KEEP (newest)</span>}
                                </div>
                                <div style={{ fontSize: 11, color: S.muted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: 2 }}>{file.path}</div>
                              </div>
                              <div style={{ fontSize: 12, color: S.muted, flexShrink: 0 }}>
                                {new Date(file.modifiedAt).toLocaleDateString()}
                              </div>
                              <button
                                onClick={e => { e.stopPropagation(); window.cleaner.openPath(file.path); }}
                                style={{ padding: "4px 10px", borderRadius: 6, border: `1px solid ${S.border}`, background: "transparent", color: S.muted, fontSize: 11, cursor: "pointer" }}
                              >
                                Show
                              </button>
                            </div>
                          );
                        })}
                        <div style={{ padding: "10px 20px", borderTop: `1px solid ${S.border}`, display: "flex", gap: 8 }}>
                          <button
                            onClick={() => {
                              setDupSelected(prev => {
                                const next = new Set(prev);
                                group.files.slice(1).forEach(f => next.add(f.path));
                                return next;
                              });
                            }}
                            style={{ padding: "5px 12px", borderRadius: 7, border: `1px solid ${S.border}`, background: "transparent", color: S.text, fontSize: 12, cursor: "pointer" }}
                          >
                            Select duplicates in group #{gi + 1}
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}
            </>
          )}

          {/* ── Cleaner tabs ── */}
          {!isUninstallerTab && !isRepairTab && !isExternalTab && tab !== "virus" && tab !== "duplicates" && (
            <>
              {/* Parallels version + VM banner */}
              {tab === "parallels" && parallelsInfo && (
                <div style={{
                  margin: "0 0 4px 0",
                  padding: "14px 20px",
                  background: parallelsInfo.installed
                    ? `linear-gradient(135deg, ${S.purple}22 0%, ${S.purple}08 100%)`
                    : "rgba(0,0,0,0.04)",
                  borderBottom: `1px solid ${S.border}`,
                  display: "flex", alignItems: "center", gap: 18, flexShrink: 0,
                }}>
                  <div style={{ fontSize: 36 }}>💻</div>
                  <div style={{ flex: 1 }}>
                    {parallelsInfo.installed ? (
                      <>
                        <div style={{ fontSize: 14, fontWeight: 700, color: S.text }}>
                          Parallels Desktop {parallelsInfo.version ? parallelsInfo.version.split(".")[0] : ""} detected
                          {parallelsInfo.version && (
                            <span style={{ fontSize: 11, fontWeight: 400, color: S.muted, marginLeft: 8 }}>
                              v{parallelsInfo.version}
                            </span>
                          )}
                        </div>
                        {parallelsInfo.vms.length > 0 ? (
                          <div style={{ fontSize: 12, color: S.muted, marginTop: 4, display: "flex", gap: 12, flexWrap: "wrap" }}>
                            {parallelsInfo.vms.map(vm => (
                              <span key={vm.name} style={{
                                background: S.purple + "20", borderRadius: 6, padding: "2px 8px",
                                color: S.purple, fontWeight: 500,
                              }}>
                                {vm.name} · {fmtMb(vm.sizeMb)}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <div style={{ fontSize: 12, color: S.muted, marginTop: 3 }}>No VMs found in ~/Parallels</div>
                        )}
                      </>
                    ) : (
                      <div style={{ fontSize: 14, color: S.muted }}>Parallels Desktop not detected on this Mac</div>
                    )}
                  </div>
                  {parallelsInfo.installed && parallelsInfo.totalVmSizeMb > 0 && (
                    <div style={{ textAlign: "right", flexShrink: 0 }}>
                      <div style={{ fontSize: 20, fontWeight: 800, color: S.purple }}>{fmtMb(parallelsInfo.totalVmSizeMb)}</div>
                      <div style={{ fontSize: 11, color: S.muted }}>total VMs</div>
                    </div>
                  )}
                </div>
              )}
              {!scanning && !scanDone && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 20 }}>

                  {/* ── Big health score ring ── */}
                  {(() => {
                    const r = 72, circ = 2 * Math.PI * r;
                    const dash = (healthScore / 100) * circ;
                    return (
                      <div style={{ position: "relative", display: "flex", flexDirection: "column", alignItems: "center", gap: 0 }}>
                        <svg width={180} height={180} viewBox="0 0 180 180">
                          {/* Glow */}
                          <circle cx={90} cy={90} r={88} fill="none" stroke={healthColor} strokeWidth={1} opacity={0.12}/>
                          {/* Track */}
                          <circle cx={90} cy={90} r={r} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth={12}/>
                          {/* Progress arc */}
                          <circle
                            cx={90} cy={90} r={r} fill="none" stroke={healthColor} strokeWidth={12}
                            strokeLinecap="round"
                            strokeDasharray={`${dash} ${circ}`}
                            strokeDashoffset={circ / 4}
                            style={{ transition: "stroke-dasharray 1s ease, stroke 0.5s ease", filter: `drop-shadow(0 0 8px ${healthColor}88)` }}
                          />
                          {/* Score number */}
                          <text x={90} y={82} textAnchor="middle" fill={S.text} fontSize={38} fontWeight={800} fontFamily="-apple-system,sans-serif">
                            {healthScore}
                          </text>
                          {/* / 100 */}
                          <text x={90} y={100} textAnchor="middle" fill={S.muted} fontSize={13} fontFamily="-apple-system,sans-serif">
                            / 100
                          </text>
                          {/* Label */}
                          <text x={90} y={120} textAnchor="middle" fill={healthColor} fontSize={15} fontWeight={700} fontFamily="-apple-system,sans-serif">
                            {healthLabel}
                          </text>
                        </svg>
                      </div>
                    );
                  })()}

                  {/* Sub-metrics row */}
                  <div style={{ display: "flex", gap: 24, marginTop: 4 }}>
                    {[
                      { label: "Disk", val: `${diskPct}%`, ok: diskPct < 70 },
                      { label: "RAM",  val: `${ramPct}%`,  ok: ramPct < 75 },
                      { label: "Freed",val: fmtMb(freedMb), ok: freedMb > 0 },
                      { label: "Cleaned", val: cleanOverdue ? "Overdue!" : "Up to date", ok: !cleanOverdue },
                    ].map(({ label, val, ok }) => (
                      <div key={label} style={{ textAlign: "center" }}>
                        <div style={{ fontSize: 14, fontWeight: 700, color: ok ? S.green : S.orange }}>{val}</div>
                        <div style={{ fontSize: 11, color: S.muted, marginTop: 1 }}>{label}</div>
                      </div>
                    ))}
                  </div>

                  {statsError && (
                    <div style={{ background: S.orange + "18", border: `1px solid ${S.orange}44`, borderRadius: 12, padding: "10px 16px", display: "flex", alignItems: "center", gap: 8, maxWidth: 400 }}>
                      <span style={{ fontSize: 16, flexShrink: 0 }}>⚠️</span>
                      <div style={{ fontSize: 12, color: S.orange }}>{statsError}</div>
                    </div>
                  )}

                  {ramPct > 90 && (
                    <div style={{ fontSize: 12, color: S.orange, background: S.orange + "18", border: `1px solid ${S.orange}44`, borderRadius: 8, padding: "6px 14px" }}>
                      ⚠ Memory nearly full — close unused apps to improve score
                    </div>
                  )}

                  <div style={{ fontSize: 14, color: S.muted }}>
                    Click <strong style={{ color: S.text }}>Scan</strong> to find junk files
                  </div>
                </div>
              )}
              {scanning && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                  <div style={{ width: 60, height: 60, borderRadius: "50%", border: `4px solid rgba(255,255,255,0.08)`, borderTop: `4px solid ${S.green}`, animation: "spin 0.8s linear infinite" }} />
                  <div style={{ color: S.text, fontSize: 15, fontWeight: 600 }}>Scanning…</div>
                  {scanProgress ? (
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
                      <div style={{ color: S.muted, fontSize: 13 }}>
                        Scanned {scanProgress.scanned} / {scanProgress.total} directories
                      </div>
                      <div style={{ color: S.muted, fontSize: 12, maxWidth: 280, textAlign: "center", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {scanProgress.currentName}
                      </div>
                      {scanProgress.total > 0 && (
                        <div style={{ width: 200, height: 4, borderRadius: 2, background: "rgba(0,0,0,0.08)", overflow: "hidden" }}>
                          <div style={{
                            height: "100%", borderRadius: 2, background: S.green,
                            width: `${Math.min(100, Math.round((scanProgress.scanned / scanProgress.total) * 100))}%`,
                            transition: "width 0.3s ease",
                          }} />
                        </div>
                      )}
                    </div>
                  ) : (
                    <div style={{ color: S.muted, fontSize: 13 }}>Checking system directories…</div>
                  )}
                  <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                </div>
              )}
              {scanDone && !scanning && (
                <>
                  {filteredResults.length === 0 ? (
                    <div style={{ textAlign: "center", color: S.muted, marginTop: 60 }}>
                      {needsPermission ? (
                        <>
                          <div style={{ fontSize: 48, marginBottom: 16 }}>🔒</div>
                          <div style={{ fontSize: 18, color: S.text, fontWeight: 600 }}>Full Disk Access required</div>
                          <div style={{ fontSize: 14, marginTop: 8, maxWidth: 380, margin: "8px auto 0" }}>
                            macOS is blocking Mac Cleaner from reading your cache folders.
                            Grant Full Disk Access and then scan again.
                          </div>
                          <div style={{
                            marginTop: 20, padding: "14px 18px", borderRadius: 12,
                            background: "rgba(0,0,0,0.06)", textAlign: "left",
                            maxWidth: 380, margin: "20px auto 0", fontSize: 13, lineHeight: 1.7,
                          }}>
                            <strong>How to fix:</strong><br />
                            1. Open <strong>System Settings</strong><br />
                            2. Go to <strong>Privacy &amp; Security → Full Disk Access</strong><br />
                            3. Click <strong>+</strong> and add <strong>Mac Cleaner</strong><br />
                            4. Restart the app and click <strong>Scan</strong> again
                          </div>
                          <button
                            onClick={() => window.cleaner?.openPath("/System/Library/PreferencePanes/Security.prefPane")}
                            style={{
                              marginTop: 18, padding: "10px 22px", borderRadius: 10,
                              background: S.green, color: "#fff", border: "none",
                              fontSize: 14, fontWeight: 600, cursor: "pointer",
                            }}
                          >
                            Open Privacy &amp; Security Settings
                          </button>
                        </>
                      ) : tab === "external" ? (
                        externalVolumes.length > 0 ? (
                          <div style={{ width: "100%", textAlign: "left" }}>
                            <div style={{ fontSize: 13, fontWeight: 700, color: S.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 10 }}>
                              Connected Drives
                            </div>
                            {externalVolumes.map((vol) => {
                              const usedGb = vol.totalGb - vol.freeGb;
                              const pct = vol.totalGb > 0 ? Math.round((usedGb / vol.totalGb) * 100) : 0;
                              return (
                                <div key={vol.path} style={{ background: S.card, borderRadius: 12, padding: "14px 18px", marginBottom: 10 }}>
                                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                                    <span style={{ fontSize: 15, fontWeight: 600, color: S.text }}>💾 {vol.name}</span>
                                    <span style={{ fontSize: 12, color: S.muted }}>{vol.totalGb > 0 ? `${usedGb.toFixed(1)} GB used of ${vol.totalGb.toFixed(1)} GB` : "Size unknown"}</span>
                                  </div>
                                  {vol.totalGb > 0 && (
                                    <div style={{ height: 6, background: "rgba(0,0,0,0.08)", borderRadius: 3, overflow: "hidden" }}>
                                      <div style={{ height: "100%", width: `${pct}%`, background: pct > 85 ? S.red : S.green, borderRadius: 3, transition: "width 0.4s" }} />
                                    </div>
                                  )}
                                  <div style={{ fontSize: 12, color: S.green, marginTop: 8 }}>✓ No junk found on this drive</div>
                                </div>
                              );
                            })}
                            <div style={{ fontSize: 13, color: S.muted, marginTop: 8 }}>
                              Run a scan to check for hidden junk files on these drives.
                            </div>
                          </div>
                        ) : externalVolumesError ? (
                          <>
                            <div style={{ fontSize: 48, marginBottom: 16 }}>⚠️</div>
                            <div style={{ fontSize: 18, color: S.orange, fontWeight: 600 }}>Could not detect drives</div>
                            <div style={{ fontSize: 13, marginTop: 8, maxWidth: 360, color: S.muted, lineHeight: 1.6 }}>
                              {externalVolumesError}
                            </div>
                          </>
                        ) : (
                          <>
                            <div style={{ fontSize: 48, marginBottom: 16 }}>💾</div>
                            <div style={{ fontSize: 18, color: S.text, fontWeight: 600 }}>No external drives found</div>
                            <div style={{ fontSize: 14, marginTop: 8 }}>
                              Plug in a USB drive, SD card, or external HDD and scan again.
                            </div>
                          </>
                        )
                      ) : (
                        <>
                          <div style={{ fontSize: 48, marginBottom: 16 }}>✨</div>
                          <div style={{ fontSize: 18, color: S.text, fontWeight: 600 }}>All clean!</div>
                          <div style={{ fontSize: 14, marginTop: 8 }}>No junk found in this category.</div>
                        </>
                      )}
                    </div>
                  ) : (
                    categories.map((cat) => (
                      <CategoryGroup
                        key={cat}
                        category={cat}
                        items={filteredResults.filter((r) => r.category === cat)}
                        selected={selected}
                        onToggle={toggleItem}
                        onReveal={revealPath}
                      />
                    ))
                  )}
                </>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function MiniStat({ label, used, total, pct, color }: { label: string; used: string; total: string; pct: number; color: string }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
        <span style={{ fontSize: 11, color: S.muted }}>{label}</span>
        <span style={{ fontSize: 11, color: S.muted }}>{used}{total ? ` / ${total}` : ""}</span>
      </div>
      <div style={{ height: 4, background: "rgba(255,255,255,0.08)", borderRadius: 2, overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: 2, transition: "width 0.4s" }} />
      </div>
    </div>
  );
}
