import { useEffect, useState, useMemo } from "react";
import axios from "axios";
import {
  Radar,
  Shield,
  AlertTriangle,
  Server,
  Clock,
  Users,
  BarChart3,
  Activity,
  Loader2,
  Network,
  MessageSquare,
  History,
} from "lucide-react";
import clsx from "clsx";
import { twMerge } from "tailwind-merge";

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

interface FeedItem {
  pattern: string;
  local_corroboration_score: number;
  status: string;
  independent_sources: number;
  flags: string[];
  downweighted: boolean;
  reports_count: number;
  feedback_count: number;
  first_seen: number;
  last_seen: number;
  sources: string[];
  identities: string[];
}

interface FeedResponse {
  ranked_indicators: FeedItem[];
  total_indicators: number;
  total_messages: number;
  advisory_disclaimer: string;
}

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8001";

export default function App() {
  const [data, setData] = useState<FeedResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<"dashboard" | "nodes">(
    "dashboard",
  );

  const fetchFeed = async () => {
    try {
      const response = await axios.get<FeedResponse>(`${API_URL}/feed`);
      setData(response.data);
      setError("");
    } catch (err: any) {
      setError(err.message || "Failed to fetch P2P gossip feed");
    } finally {
      setLoading(false);
    }
  };

  const handleManualSync = async () => {
    setSyncing(true);
    await fetchFeed();
    setTimeout(() => setSyncing(false), 600); // UI Polish: ensure spinner is visible for a moment
  };

  useEffect(() => {
    fetchFeed();
    const interval = setInterval(fetchFeed, 3000);
    return () => clearInterval(interval);
  }, []);

  // Compute active nodes dynamically from sources
  const activeNodes = useMemo(() => {
    if (!data) return [];
    const nodeSet = new Set<string>();
    data.ranked_indicators.forEach((ind) => {
      (ind.identities || []).forEach((ident) => nodeSet.add(ident));
    });
    return Array.from(nodeSet);
  }, [data]);

  const highTrustCount =
    data?.ranked_indicators.filter((i) => i.local_corroboration_score >= 3.0)
      .length ?? 0;
  const flaggedCount =
    data?.ranked_indicators.filter((i) => i.downweighted).length ?? 0;

  // Analytics
  const avgScore = data?.ranked_indicators.length
    ? (
        data.ranked_indicators.reduce(
          (acc, i) => acc + i.local_corroboration_score,
          0,
        ) / data.ranked_indicators.length
      ).toFixed(2)
    : "0.00";

  const totalFeedbackCount =
    data?.ranked_indicators.reduce((acc, i) => acc + i.feedback_count, 0) ?? 0;

  return (
    <div className="min-h-screen bg-background font-sans text-foreground">
      {/* HEADER */}
      <header className="border-b border-border/50 bg-card/50 backdrop-blur-md sticky top-0 z-50">
        <div className="container mx-auto px-4 md:px-6 py-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div
              className="flex items-center gap-3 cursor-pointer"
              onClick={() => setActiveTab("dashboard")}
            >
              <div className="relative">
                <Network className="h-8 w-8 text-primary" />
                <div className="absolute -top-1 -right-1 h-3 w-3 bg-primary rounded-full animate-pulse" />
              </div>
              <div>
                <h1 className="text-xl font-bold font-mono tracking-tight">
                  SWARM<span className="text-primary">SEC</span>
                </h1>
                <p className="text-xs text-muted-foreground font-mono hidden sm:block">
                  Permissioned P2P CTI Exchange
                </p>
              </div>
            </div>

            <div className="flex items-center gap-4 md:gap-6">
              <nav className="hidden md:flex items-center gap-6 text-sm">
                <button
                  onClick={() => setActiveTab("dashboard")}
                  className={cn(
                    "transition-colors flex items-center gap-2",
                    activeTab === "dashboard"
                      ? "nav-active font-semibold text-foreground"
                      : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  <BarChart3 className="h-4 w-4" />
                  <span>Trust Dashboard</span>
                </button>
                <button
                  onClick={() => setActiveTab("nodes")}
                  className={cn(
                    "transition-colors flex items-center gap-2",
                    activeTab === "nodes"
                      ? "nav-active font-semibold text-foreground"
                      : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  <Users className="h-4 w-4" />
                  <span>Peer Network</span>
                </button>
              </nav>

              <div className="hidden sm:flex items-center gap-2 text-xs font-mono">
                <div
                  className={cn(
                    "h-2 w-2 rounded-full",
                    error ? "bg-destructive" : "bg-success animate-pulse",
                  )}
                />
                <span className="text-muted-foreground">
                  {error ? "Gossip Offline" : "Gossip Active"}
                </span>
              </div>

              <button
                onClick={handleManualSync}
                disabled={syncing}
                className="cyber-button px-4 py-2 rounded-md text-sm font-semibold flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {syncing ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Radar className="w-4 h-4" />
                )}
                <span className="hidden sm:inline">Poll Network</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* MAIN VIEW */}
      <main className="container mx-auto px-4 md:px-6 py-8 space-y-8">
        {activeTab === "dashboard" ? (
          <>
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
              <div>
                <h1 className="text-2xl font-bold font-mono flex items-center gap-3">
                  <Shield className="h-6 w-6 text-primary" />
                  Local Trust Ranking
                </h1>
                <p className="text-sm text-muted-foreground mt-1">
                  Explainable corroboration scores computed locally by this node
                </p>
              </div>
            </div>

            {/* Advisory Warning */}
            <div className="flex items-start sm:items-center gap-3 p-4 border border-info/30 bg-info/10 rounded-lg text-sm font-mono shadow-[0_0_15px_rgba(59,130,246,0.1)]">
              <AlertTriangle className="h-5 w-5 text-info shrink-0 mt-0.5 sm:mt-0" />
              <span className="text-foreground/90">
                <strong className="text-info">ADVISORY ONLY:</strong>{" "}
                {data?.advisory_disclaimer ||
                  "SwarmSec computes local corroboration scores and trust rankings. This is NOT an automated block/allow decision; a human analyst must make that call."}
              </span>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard
                title="STIX 2.1 Indicators"
                value={data?.total_indicators ?? 0}
                subtitle="Gossiped"
                icon={Activity}
                colorClass="text-primary"
                borderClass="border-primary/30"
                bgClass="from-primary/10"
              />
              <StatCard
                title="High Trust Threats"
                value={highTrustCount}
                subtitle="Corroborated"
                icon={Shield}
                colorClass="text-success"
                borderClass="border-success/30"
                bgClass="from-success/10"
              />
              <StatCard
                title="Collusion Clusters"
                value={flaggedCount}
                subtitle="Penalized"
                icon={AlertTriangle}
                colorClass="text-destructive"
                borderClass="border-destructive/30"
                bgClass="from-destructive/10"
              />
              <StatCard
                title="Known Peers"
                value={activeNodes.length}
                subtitle="Identities"
                icon={Users}
                colorClass="text-info"
                borderClass="border-info/30"
                bgClass="from-info/10"
              />
            </div>

            {/* Layout Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left Column (Recent Scans/Feed) */}
              <div className="lg:col-span-2 flex flex-col gap-6">
                <div className="p-6 border border-border/50 bg-card/50 backdrop-blur-sm rounded-xl min-h-[400px]">
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="font-mono font-semibold flex items-center gap-2">
                      <Clock className="h-5 w-5 text-primary" />
                      Live P2P Threat Feed
                    </h2>
                    <span className="text-xs text-muted-foreground font-mono">
                      {data?.total_messages ?? 0} total messages
                    </span>
                  </div>

                  {loading && !data ? (
                    <div className="flex justify-center py-12">
                      <Loader2 className="h-8 w-8 text-primary animate-spin" />
                    </div>
                  ) : error ? (
                    <div className="text-destructive font-mono p-4 bg-destructive/10 rounded-lg border border-destructive/30">
                      {error} - Ensure the Node is running on {API_URL}
                    </div>
                  ) : data?.ranked_indicators.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-center">
                      <Radar className="h-16 w-16 text-primary/20 mb-4" />
                      <p className="text-muted-foreground font-mono">
                        No STIX 2.1 indicators received from peers yet.
                      </p>
                      <p className="text-xs text-muted-foreground/60 mt-2">
                        Waiting for gossip messages...
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {data?.ranked_indicators.map((item) => (
                        <IndicatorRow key={item.pattern} item={item} />
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Right Column (Quick Stats) */}
              <div className="p-6 border border-border/50 bg-card/50 backdrop-blur-sm rounded-xl h-fit sticky top-24">
                <h2 className="font-mono font-semibold flex items-center gap-2 mb-6">
                  <Activity className="h-5 w-5 text-primary" />
                  Node Analytics
                </h2>

                <div className="space-y-4">
                  <div className="flex items-center justify-between p-4 rounded-lg bg-background/50 border border-border/30">
                    <span className="text-sm text-muted-foreground font-medium">
                      Avg Corroboration
                    </span>
                    <span className="font-mono font-bold text-lg">
                      {avgScore}
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-4 rounded-lg bg-background/50 border border-border/30">
                    <span className="text-sm text-muted-foreground font-medium">
                      Cross-Endorsements
                    </span>
                    <span className="font-mono font-bold text-success text-lg">
                      {totalFeedbackCount}
                    </span>
                  </div>
                  <div
                    className={cn(
                      "flex items-center justify-between p-4 rounded-lg border transition-colors",
                      flaggedCount > 0
                        ? "bg-destructive/10 border-destructive/30"
                        : "bg-background/50 border-border/30",
                    )}
                  >
                    <span className="text-sm font-medium text-muted-foreground">
                      Collusion Defense
                    </span>
                    <span
                      className={cn(
                        "font-mono font-bold text-lg",
                        flaggedCount > 0
                          ? "text-destructive text-glow-red"
                          : "text-muted-foreground",
                      )}
                    >
                      {flaggedCount > 0 ? "ACTIVE" : "STANDBY"}
                    </span>
                  </div>
                </div>

                <div className="mt-6 pt-6 border-t border-border/50">
                  <button
                    onClick={() => setActiveTab("nodes")}
                    className="w-full cyber-button bg-transparent py-2.5 rounded-md text-sm font-semibold transition-all flex items-center justify-center gap-2"
                  >
                    <Network className="h-4 w-4" />
                    View P2P Topology
                  </button>
                </div>
              </div>
            </div>
          </>
        ) : (
          /* NODES TAB */
          <div className="space-y-6 animate-fade-in">
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
              <div>
                <h1 className="text-2xl font-bold font-mono flex items-center gap-3">
                  <Network className="h-6 w-6 text-primary" />
                  Peer Organizations
                </h1>
                <p className="text-sm text-muted-foreground mt-1">
                  Cryptographically verified identities contributing to the
                  SwarmSec decentralized exchange
                </p>
              </div>
            </div>

            <div className="p-6 border border-border/50 bg-card/50 backdrop-blur-sm rounded-xl min-h-[400px]">
              {activeNodes.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-center">
                  <Users className="h-16 w-16 text-primary/20 mb-4" />
                  <p className="text-muted-foreground font-mono">
                    No cryptographic peers detected yet.
                  </p>
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                  {activeNodes.map((node) => (
                    <div
                      key={node}
                      className="p-4 border border-border/40 bg-background/40 rounded-lg flex items-center gap-4 hover:border-primary/50 hover:bg-primary/5 transition-all group"
                    >
                      <div className="h-10 w-10 shrink-0 rounded bg-primary/10 flex items-center justify-center border border-primary/20 group-hover:scale-110 transition-transform">
                        <Server className="h-5 w-5 text-primary" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div
                          className="font-mono text-sm font-semibold truncate"
                          title={node}
                        >
                          {node}
                        </div>
                        <div className="text-[10px] text-success flex items-center gap-1.5 mt-1 font-mono uppercase tracking-widest">
                          <div className="h-1.5 w-1.5 bg-success rounded-full animate-pulse" />{" "}
                          Verified by Registrar
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

// ----------------------------------------------------
// COMPONENTS
// ----------------------------------------------------

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  colorClass,
  borderClass,
  bgClass,
}: any) {
  return (
    <div
      className={cn(
        "p-5 rounded-xl border bg-gradient-to-br to-transparent transition-all group hover:-translate-y-1",
        borderClass,
        bgClass,
        "hover:border-opacity-100",
      )}
    >
      <div className="flex items-center justify-between mb-3">
        <Icon className={cn("h-5 w-5", colorClass)} />
        <span
          className={cn(
            "text-[10px] px-2 py-0.5 rounded border uppercase tracking-widest font-semibold bg-background/50",
            borderClass,
            colorClass,
          )}
        >
          {subtitle}
        </span>
      </div>
      <div className={cn("text-3xl font-bold font-mono text-glow", colorClass)}>
        {value}
      </div>
      <div className="text-xs text-muted-foreground mt-1 font-medium">
        {title}
      </div>
    </div>
  );
}

function IndicatorRow({ item }: { item: FeedItem }) {
  const isHighTrust = item.local_corroboration_score >= 3.0;
  const isUnconfirmed = item.status.includes("UNCONFIRMED");

  const formatDate = (timestamp: number) => {
    if (!timestamp) return "Unknown";
    return new Date(timestamp * 1000).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div
      className={cn(
        "flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-lg transition-all border",
        item.downweighted
          ? "border-destructive/30 bg-destructive/10 hover:bg-destructive/20"
          : "border-border/40 bg-background/40 hover:bg-background/80 hover:border-border/80",
      )}
    >
      <div className="flex items-start sm:items-center gap-4 w-full">
        <div className="flex flex-col items-center justify-center p-3 border border-border/30 rounded bg-background/50 min-w-[80px] shrink-0">
          <span
            className={cn(
              "text-xl font-bold font-mono",
              isHighTrust
                ? "text-success text-glow-green"
                : item.downweighted
                  ? "text-destructive text-glow-red"
                  : "text-foreground",
            )}
          >
            {item.local_corroboration_score.toFixed(1)}
          </span>
          <span className="text-[9px] text-muted-foreground uppercase tracking-widest mt-1">
            Score
          </span>
        </div>

        <div className="flex-1 min-w-0 py-1">
          <div className="font-mono text-sm md:text-base font-medium flex flex-wrap items-center gap-2 mb-2">
            <span className="break-all">{item.pattern}</span>
            {item.flags.map((flag, idx) => (
              <span
                key={idx}
                className={cn(
                  "text-[10px] px-2 py-0.5 rounded border uppercase tracking-widest flex items-center font-semibold whitespace-nowrap",
                  flag.includes("downweighted")
                    ? "bg-destructive/20 text-destructive border-destructive/30"
                    : "bg-warning/20 text-warning border-warning/30",
                )}
              >
                {flag.includes("downweighted") ? (
                  <AlertTriangle className="w-3 h-3 mr-1" />
                ) : null}
                {flag.replace(/_/g, " ")}
              </span>
            ))}
            {isHighTrust && !item.downweighted && (
              <span className="text-[10px] px-2 py-0.5 rounded bg-success/20 text-success border border-success/30 uppercase tracking-widest flex items-center font-semibold whitespace-nowrap">
                <Shield className="w-3 h-3 mr-1" /> Verified
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-muted-foreground">
            <span
              className="flex items-center gap-1.5"
              title="Number of independent organizations that endorsed this"
            >
              <Users className="w-3.5 h-3.5" />
              <strong className="text-foreground">
                {item.independent_sources}
              </strong>{" "}
              {item.independent_sources === 1 ? "org" : "orgs"}
            </span>
            <span
              className="flex items-center gap-1.5"
              title="Number of raw report messages"
            >
              <MessageSquare className="w-3.5 h-3.5" />
              <strong className="text-foreground">
                {item.reports_count}
              </strong>{" "}
              {item.reports_count === 1 ? "report" : "reports"}
            </span>
            <span
              className="flex items-center gap-1.5"
              title="Number of feedback/endorsement messages"
            >
              <Activity className="w-3.5 h-3.5" />
              <strong className="text-foreground">
                {item.feedback_count}
              </strong>{" "}
              feedback
            </span>
            <span className="flex items-center gap-1.5" title="Time first seen">
              <History className="w-3.5 h-3.5" />
              {formatDate(item.first_seen)}
            </span>
            <span
              className={cn(
                "px-1.5 py-0.5 rounded bg-background/50 border border-border/50 uppercase tracking-wider text-[10px] font-bold",
                isUnconfirmed ? "text-muted-foreground" : "text-foreground",
              )}
            >
              {item.status}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
