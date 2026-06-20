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
};

type AppInfo = {
  name: string;
  appPath: string;
  bundleId: string;
  sizeMb: number;
  associatedPaths: string[];
  associatedSizeMb: number;
};

type DiskHealth = {
  smartStatus: string;
  volumeName: string;
  fileSystem: string;
  totalGb: number;
  freeGb: number;
  brokenSymlinks: string[];
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

declare global {
  interface Window {
    cleaner: {
      platform: string;
      scan: () => Promise<ScanResult[]>;
      clean: (ids: string[]) => Promise<{ freedMb: number; errors: string[] }>;
      getStats: () => Promise<SystemStats>;
      openPath: (path: string) => Promise<void>;
      scanApps: () => Promise<AppInfo[]>;
      uninstallApp: (appPath: string, associatedPaths: string[]) => Promise<{ freedMb: number; errors: string[] }>;
      diskHealth: () => Promise<DiskHealth>;
      verifyDisk: () => Promise<string>;
      fixSymlinks: (paths: string[]) => Promise<{ fixed: number; errors: string[] }>;
      virusScan: () => Promise<VirusScanResult>;
      quarantineThreat: (threatPath: string) => Promise<{ ok: boolean; error?: string }>;
    };
  }
}

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

type Tab = "scan-all" | "smart" | "junk" | "privacy" | "parallels" | "uninstaller" | "repair" | "virus";

const NAV: { id: Tab; label: string; emoji: string; color: string }[] = [
  { id: "scan-all",    label: "Scan All",     emoji: "⚡", color: "#7030B0" },
  { id: "smart",       label: "Smart Scan",   emoji: "🔍", color: S.green  },
  { id: "junk",        label: "System Junk",  emoji: "🗑", color: S.orange },
  { id: "privacy",     label: "Privacy",      emoji: "🔒", color: S.blue   },
  { id: "parallels",   label: "Parallels",    emoji: "💻", color: S.purple },
  { id: "uninstaller", label: "Uninstaller",  emoji: "🗂", color: S.red    },
  { id: "repair",      label: "Disk Health",  emoji: "🔧", color: S.teal   },
  { id: "virus",       label: "Virus Scan",   emoji: "🛡", color: "#C42020" },
];

function fmtMb(mb: number): string {
  if (mb >= 1024) return (mb / 1024).toFixed(1) + " GB";
  if (mb >= 1) return mb.toFixed(0) + " MB";
  return (mb * 1024).toFixed(0) + " KB";
}

function fmtGb(gb: number): string {
  return gb.toFixed(1) + " GB";
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

  // Uninstaller state
  const [appList, setAppList] = useState<AppInfo[]>([]);
  const [loadingApps, setLoadingApps] = useState(false);
  const [appsDone, setAppsDone] = useState(false);
  const [uninstallingApp, setUninstallingApp] = useState<string | null>(null);
  const [confirmApp, setConfirmApp] = useState<AppInfo | null>(null);

  // Scan All state
  const [scanningAll, setScanningAll] = useState(false);
  const [scanAllDone, setScanAllDone] = useState(false);
  const [fixingAll, setFixingAll] = useState(false);

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

  const platform = window.cleaner?.platform ?? "darwin";
  const isMac = platform === "darwin";

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3500);
  };

  useEffect(() => {
    if (!window.cleaner) return;
    window.cleaner.getStats().then(setStats).catch(console.error);
    const iv = setInterval(() => {
      window.cleaner.getStats().then(setStats).catch(console.error);
    }, 5000);
    return () => clearInterval(iv);
  }, []);

  const handleScan = useCallback(async () => {
    if (!window.cleaner) return;
    setScanning(true);
    setScanDone(false);
    setSelected(new Set());
    try {
      const results = await window.cleaner.scan();
      setScanResults(results);
      setSelected(new Set(results.filter((r) => r.safe).map((r) => r.id)));
      setScanDone(true);
    } finally {
      setScanning(false);
    }
  }, []);

  const handleClean = useCallback(async () => {
    if (!window.cleaner || selected.size === 0) return;
    setCleaning(true);
    try {
      const result = await window.cleaner.clean(Array.from(selected));
      setFreedMb((prev) => prev + result.freedMb);
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
    setVirusResult(null);
    setDiskHealth(null);
    setScanResults([]);
    setSelected(new Set());
    try {
      const [junkRes, virusRes, diskRes] = await Promise.all([
        window.cleaner.scan(),
        window.cleaner.virusScan(),
        window.cleaner.diskHealth(),
      ]);
      setScanResults(junkRes);
      setSelected(new Set(junkRes.filter((r) => r.safe).map((r) => r.id)));
      setScanDone(true);
      setVirusResult(virusRes);
      setDiskHealth(diskRes);
      setScanAllDone(true);
    } finally {
      setScanningAll(false);
    }
  }, []);

  const handleFixAll = useCallback(async () => {
    if (!window.cleaner) return;
    setFixingAll(true);
    try {
      // 1. Clean junk
      if (selected.size > 0) {
        const r = await window.cleaner.clean(Array.from(selected));
        setFreedMb((prev) => prev + r.freedMb);
        const fresh = await window.cleaner.scan();
        setScanResults(fresh);
        setSelected(new Set());
      }
      // 2. Fix broken symlinks
      if (diskHealth && diskHealth.brokenSymlinks.length > 0) {
        await window.cleaner.fixSymlinks(diskHealth.brokenSymlinks);
        const freshDisk = await window.cleaner.diskHealth();
        setDiskHealth(freshDisk);
      }
      // 3. Quarantine all threats
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
    try {
      const result = await window.cleaner.virusScan();
      setVirusResult(result);
    } finally {
      setLoadingVirus(false);
    }
  }, []);

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
    try {
      const apps = await window.cleaner.scanApps();
      setAppList(apps);
      setAppsDone(true);
    } finally {
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
    return true;
  });

  const categories = Array.from(new Set(filteredResults.map((r) => r.category)));
  const selectedMb = scanResults.filter((r) => selected.has(r.id)).reduce((s, r) => s + r.sizeMb, 0);
  const totalFoundMb = filteredResults.reduce((s, r) => s + r.sizeMb, 0);

  const diskPct = stats ? Math.round((stats.diskUsedGb / stats.diskTotalGb) * 100) : 0;
  const ramPct = stats ? Math.round((stats.ramUsedGb / stats.ramTotalGb) * 100) : 0;

  const isUninstallerTab = tab === "uninstaller";
  const isRepairTab = tab === "repair";

  return (
    <div style={{ display: "flex", height: "100vh", background: S.bgGrad, overflow: "hidden", position: "relative" }}>

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
              <MiniStat label="Disk" used={fmtGb(stats.diskUsedGb)} total={fmtGb(stats.diskTotalGb)} pct={diskPct} color={diskPct > 85 ? S.red : diskPct > 70 ? S.orange : S.green} />
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
                    disabled={fixingAll}
                    style={{
                      padding: "9px 20px", borderRadius: 10, border: "none",
                      background: S.green, color: "#fff", fontSize: 14, fontWeight: 700,
                      cursor: fixingAll ? "not-allowed" : "pointer", opacity: fixingAll ? 0.6 : 1,
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
                {loadingApps ? "Scanning…" : "Scan Apps"}
              </button>
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
                  <div style={{ color: S.muted, fontSize: 15 }}>Scanning Applications…</div>
                  <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
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

                  {/* Note */}
                  <div style={{ fontSize: 12, color: S.muted, textAlign: "center", padding: "4px 0 8px" }}>
                    For deeper repairs, use Disk Utility → First Aid, or boot into Recovery Mode (⌘+R on startup)
                  </div>

                </div>
              )}
            </>
          )}

          {/* ── Scan All tab ── */}
          {tab === "scan-all" && (
            <>
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
                  <div style={{ display: "flex", flexDirection: "column", gap: 8, alignItems: "center" }}>
                    {[["🗑", "Junk files"], ["🛡", "Viruses & malware"], ["🔧", "Disk health"], ["🔗", "Broken symlinks"]].map(([emoji, label]) => (
                      <div key={label} style={{ fontSize: 13, color: S.muted, display: "flex", alignItems: "center", gap: 6 }}>
                        <span>{emoji}</span> {label}
                        <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#7030B0", opacity: 0.6, animation: "pulse 1.2s ease-in-out infinite", display: "inline-block", marginLeft: 4 }} />
                        <style>{`@keyframes pulse { 0%,100%{opacity:0.3} 50%{opacity:1} }`}</style>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {scanAllDone && !scanningAll && (
                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

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
            </>
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
                  <div style={{ color: S.muted, fontSize: 13 }}>
                    {isMac ? "Checking LaunchAgents, Applications, and known malware paths" : "Running Windows Defender + scanning startup locations"}
                  </div>
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

          {/* ── Cleaner tabs ── */}
          {!isUninstallerTab && !isRepairTab && tab !== "virus" && (
            <>
              {!scanning && !scanDone && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 24 }}>
                  {/* Hero graphic */}
                  <div style={{ position: "relative", width: 140, height: 140, marginBottom: 8 }}>
                    <svg viewBox="0 0 140 140" width={140} height={140}>
                      <defs>
                        <radialGradient id="glow" cx="50%" cy="50%" r="50%">
                          <stop offset="0%" stopColor={S.purple} stopOpacity={0.4}/>
                          <stop offset="100%" stopColor={S.purple} stopOpacity={0}/>
                        </radialGradient>
                        <linearGradient id="diskGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                          <stop offset="0%" stopColor="#9b59f0"/>
                          <stop offset="100%" stopColor="#5a30d0"/>
                        </linearGradient>
                      </defs>
                      <circle cx="70" cy="70" r="68" fill="url(#glow)"/>
                      <circle cx="70" cy="70" r="52" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="1"/>
                      <circle cx="70" cy="70" r="36" fill="url(#diskGrad)" opacity="0.9"/>
                      <circle cx="70" cy="70" r="16" fill="rgba(255,255,255,0.12)"/>
                      <circle cx="70" cy="70" r="8" fill="rgba(255,255,255,0.25)"/>
                      {/* Orbit dots */}
                      <circle cx="70" cy="20" r="4" fill={S.green}/>
                      <circle cx="118" cy="95" r="3" fill={S.orange}/>
                      <circle cx="22" cy="95" r="3" fill={S.blue}/>
                    </svg>
                  </div>
                  {stats && (
                    <div style={{ display: "flex", gap: 36, marginBottom: 4 }}>
                      <StatRing percent={diskPct} label="Disk" color={diskPct > 85 ? S.red : diskPct > 70 ? S.orange : S.green} sub={`${fmtGb(stats.diskUsedGb)} / ${fmtGb(stats.diskTotalGb)}`} />
                      <StatRing percent={ramPct} label="Memory" color={ramPct > 85 ? S.red : S.blue} sub={`${fmtGb(stats.ramUsedGb)} / ${fmtGb(stats.ramTotalGb)}`} />
                      <StatRing percent={stats.cpuPercent} label="CPU" color={stats.cpuPercent > 80 ? S.red : S.teal} sub={`${stats.cpuPercent}% used`} />
                    </div>
                  )}
                  {ramPct > 90 && (
                    <div style={{ fontSize: 12, color: S.orange, background: S.orange + "18", border: `1px solid ${S.orange}44`, borderRadius: 8, padding: "6px 14px" }}>
                      ⚠ Memory is nearly full — scanning will help find files to free space
                    </div>
                  )}
                  <div style={{ fontSize: 15, color: S.muted }}>
                    Click <strong style={{ color: S.text }}>Scan</strong> to find junk files
                  </div>
                </div>
              )}
              {scanning && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                  <div style={{ width: 60, height: 60, borderRadius: "50%", border: `4px solid rgba(255,255,255,0.08)`, borderTop: `4px solid ${S.green}`, animation: "spin 0.8s linear infinite" }} />
                  <div style={{ color: S.muted, fontSize: 15 }}>Scanning…</div>
                  <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                </div>
              )}
              {scanDone && !scanning && (
                <>
                  {filteredResults.length === 0 ? (
                    <div style={{ textAlign: "center", color: S.muted, marginTop: 80 }}>
                      <div style={{ fontSize: 48, marginBottom: 16 }}>✨</div>
                      <div style={{ fontSize: 18, color: S.text, fontWeight: 600 }}>All clean!</div>
                      <div style={{ fontSize: 14, marginTop: 8 }}>No junk found in this category.</div>
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
