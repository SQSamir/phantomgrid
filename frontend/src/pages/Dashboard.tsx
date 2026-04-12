import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Shield, Zap, Bell, Users, TrendingUp, TrendingDown,
  Minus, Radio, AlertTriangle, Globe,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { apiGet } from '../api/client';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Overview {
  active_decoys: number;
  events_today: number;
  events_yesterday: number;
  events_trend_pct: number | null;
  open_alerts: number;
  unique_attackers_24h: number;
  unique_attackers_prev: number;
  attackers_trend_pct: number | null;
  critical_events_1h: number;
}

interface TimelinePoint  { hour: string; count: number }
interface ProtocolPoint  { protocol: string; count: number }
interface SeverityPoint  { severity: string; count: number }

interface Attacker {
  source_ip: string; event_count: number; protocols: string[];
  protocols_hit: number; last_seen: string;
  country: string | null; country_code: string | null;
  city: string | null; asn: string | null; is_tor: boolean;
}

interface LiveEvent {
  protocol: string; event_type: string; source_ip: string;
  severity: string; created_at?: string; enrichment?: { country?: string };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const WS_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8080')
  .replace(/^http:/, 'ws:').replace(/^https:/, 'wss:');

function countryFlag(code: string | null): string {
  if (!code || code.length !== 2) return '';
  const pts = [...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65);
  return String.fromCodePoint(...pts);
}

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high:     'bg-orange-500',
  medium:   'bg-yellow-500',
  low:      'bg-green-500',
  info:     'bg-blue-500',
};

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-900/70 text-red-300',
  high:     'bg-orange-900/70 text-orange-300',
  medium:   'bg-yellow-900/70 text-yellow-300',
  low:      'bg-green-900/70 text-green-300',
  info:     'bg-blue-900/70 text-blue-300',
};

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function ThreatBanner({ critical1h, topIp }: { critical1h: number; topIp?: Attacker }) {
  if (critical1h === 0) return null;
  return (
    <div className="flex items-center gap-3 px-4 py-2.5 bg-red-950 border border-red-800 rounded-lg text-sm">
      <AlertTriangle size={16} className="text-red-400 flex-shrink-0 animate-pulse" />
      <span className="text-red-300 font-medium">
        {critical1h} critical event{critical1h > 1 ? 's' : ''} in the last hour
      </span>
      {topIp && (
        <span className="text-red-500 text-xs ml-auto">
          Most active: {topIp.source_ip}
          {topIp.country && ` · ${countryFlag(topIp.country_code)} ${topIp.country}`}
          {' · '}{topIp.event_count} events
        </span>
      )}
    </div>
  );
}

function TrendIcon({ pct }: { pct: number | null }) {
  if (pct === null) return <Minus size={14} className="text-gray-600" />;
  if (pct > 0)  return <TrendingUp  size={14} className="text-red-400" />;
  if (pct < 0)  return <TrendingDown size={14} className="text-green-400" />;
  return <Minus size={14} className="text-gray-600" />;
}

function StatCard({
  icon: Icon, label, value, color, trend, sub,
}: {
  icon: React.ElementType; label: string; value: number | string;
  color: string; trend?: number | null; sub?: string;
}) {
  return (
    <div className="card flex items-center gap-4">
      <div className={`p-3 rounded-lg flex-shrink-0 ${color}`}>
        <Icon size={20} />
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-gray-400 text-xs">{label}</p>
        <div className="flex items-baseline gap-2">
          <p className="text-2xl font-bold text-white">{value}</p>
          {trend !== undefined && (
            <span className="flex items-center gap-0.5 text-xs text-gray-500">
              <TrendIcon pct={trend ?? null} />
              {trend !== null ? `${Math.abs(trend)}%` : ''}
            </span>
          )}
        </div>
        {sub && <p className="text-xs text-gray-600 truncate mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

function TimelineChart({ data }: { data: TimelinePoint[] }) {
  if (!data.length) {
    return (
      <div className="h-28 flex items-center justify-center text-gray-600 text-xs">
        No events in selected window
      </div>
    );
  }
  const W = 600, H = 90, PX = 6, PY = 8;
  const maxC = Math.max(...data.map(d => d.count), 1);

  const pts = data.map((d, i) => ({
    x: PX + (i / Math.max(data.length - 1, 1)) * (W - PX * 2),
    y: PY + (1 - d.count / maxC) * (H - PY * 2),
    count: d.count,
    hour: d.hour,
  }));

  const line = pts.map((p, i) =>
    `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`
  ).join(' ');
  const area = `${line} L${pts[pts.length - 1].x.toFixed(1)},${H} L${pts[0].x.toFixed(1)},${H} Z`;

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-28" preserveAspectRatio="none">
        <defs>
          <linearGradient id="tl-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="#6366f1" stopOpacity="0.4" />
            <stop offset="100%" stopColor="#6366f1" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {/* Grid lines */}
        {[0.25, 0.5, 0.75].map(f => (
          <line key={f}
            x1={PX} y1={PY + f * (H - PY * 2)}
            x2={W - PX} y2={PY + f * (H - PY * 2)}
            stroke="#1f2937" strokeWidth="1"
          />
        ))}
        <path d={area} fill="url(#tl-fill)" />
        <path d={line}  fill="none" stroke="#6366f1" strokeWidth="1.5" strokeLinejoin="round" />
        {/* Peak markers */}
        {pts.filter(p => p.count === maxC).map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r="3" fill="#6366f1" />
        ))}
      </svg>
      <div className="flex justify-between text-gray-600 text-[10px] mt-0.5 px-1">
        {data.length > 0 && (
          <>
            <span>{new Date(data[0].hour).getHours()}:00</span>
            <span>now</span>
          </>
        )}
      </div>
    </div>
  );
}

function LiveFeed({ events }: { events: LiveEvent[] }) {
  return (
    <div className="space-y-1 overflow-y-auto max-h-52">
      {events.length === 0 && (
        <p className="text-gray-600 text-xs text-center py-8">Waiting for events…</p>
      )}
      {events.map((ev, i) => (
        <div
          key={i}
          className="flex items-center gap-2 text-xs py-1 px-1.5 rounded hover:bg-gray-800/50 transition-colors animate-[fadeIn_0.3s_ease]"
        >
          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${SEV_DOT[ev.severity] ?? 'bg-gray-600'}`} />
          <span className="font-mono text-gray-400 w-28 flex-shrink-0 truncate">{ev.source_ip}</span>
          <span className="text-indigo-400 flex-shrink-0 w-16 truncate">{ev.protocol}</span>
          <span className="text-gray-500 truncate flex-1">{ev.event_type.replace(/_/g, ' ')}</span>
          {ev.enrichment?.country && (
            <span className="text-gray-600 flex-shrink-0">{ev.enrichment.country}</span>
          )}
        </div>
      ))}
    </div>
  );
}

function ProtocolBars({ data }: { data: ProtocolPoint[] }) {
  const max = Math.max(1, ...data.map(p => p.count));
  const colors = [
    'bg-indigo-500', 'bg-purple-500', 'bg-blue-500', 'bg-cyan-500',
    'bg-teal-500',   'bg-emerald-500', 'bg-orange-500', 'bg-red-500',
  ];
  return (
    <div className="space-y-1.5">
      {data.slice(0, 10).map((p, i) => (
        <div key={p.protocol} className="flex items-center gap-3">
          <span className="text-xs text-gray-400 w-24 truncate font-mono">{p.protocol}</span>
          <div className="flex-1 bg-gray-800 rounded-full h-1.5 overflow-hidden">
            <div
              className={`${colors[i % colors.length]} h-1.5 rounded-full transition-all duration-500`}
              style={{ width: `${(p.count / max) * 100}%` }}
            />
          </div>
          <span className="text-xs text-gray-500 w-8 text-right">{p.count}</span>
        </div>
      ))}
    </div>
  );
}

function TopAttackers({ data }: { data: Attacker[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  if (!data.length) {
    return <p className="text-gray-600 text-xs text-center py-8">No attackers yet</p>;
  }
  return (
    <div className="space-y-1">
      {data.slice(0, 8).map(a => (
        <div key={a.source_ip}>
          <button
            className="w-full flex items-center gap-2 text-xs py-1.5 px-1 rounded hover:bg-gray-800/60 transition-colors"
            onClick={() => setExpanded(expanded === a.source_ip ? null : a.source_ip)}
          >
            <span className={`w-2 h-2 rounded-full flex-shrink-0 ${
              a.event_count > 100 ? 'bg-red-500' :
              a.event_count > 30  ? 'bg-orange-500' : 'bg-yellow-500'
            }`} />
            <span className="font-mono text-gray-300 w-32 text-left truncate">{a.source_ip}</span>
            {a.country_code && (
              <span className="flex-shrink-0" title={a.country ?? ''}>
                {countryFlag(a.country_code)}
              </span>
            )}
            {a.is_tor && (
              <span className="bg-purple-900/60 text-purple-300 px-1 rounded text-[10px] flex-shrink-0">TOR</span>
            )}
            <span className="text-gray-500 ml-auto flex-shrink-0">{a.event_count} events</span>
            <span className="text-indigo-500 flex-shrink-0">{a.protocols_hit}p</span>
          </button>
          {expanded === a.source_ip && (
            <div className="ml-5 mb-1 p-2 bg-gray-800/40 rounded text-[11px] text-gray-400 space-y-0.5">
              {a.city && <p>City: <span className="text-gray-300">{a.city}</span></p>}
              {a.asn  && <p>ASN: <span className="text-gray-300 font-mono">{a.asn}</span></p>}
              <p>Protocols: <span className="text-indigo-300">{a.protocols.join(', ')}</span></p>
              <p>Last seen: <span className="text-gray-300">
                {formatDistanceToNow(new Date(a.last_seen), { addSuffix: true })}
              </span></p>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function SeverityBreakdown({ data }: { data: SeverityPoint[] }) {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const total = data.reduce((s, d) => s + d.count, 0) || 1;
  const sorted = [...data].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  const barColors: Record<string, string> = {
    critical: 'bg-red-500',
    high:     'bg-orange-500',
    medium:   'bg-yellow-500',
    low:      'bg-green-500',
    info:     'bg-blue-500',
  };
  return (
    <div className="space-y-2.5">
      {sorted.map(s => (
        <div key={s.severity} className="space-y-1">
          <div className="flex items-center justify-between text-xs">
            <span className={`capitalize font-medium px-1.5 py-0.5 rounded ${SEV_BADGE[s.severity] ?? ''}`}>
              {s.severity}
            </span>
            <span className="text-gray-400">{s.count} ({Math.round(s.count / total * 100)}%)</span>
          </div>
          <div className="bg-gray-800 rounded-full h-1.5">
            <div
              className={`${barColors[s.severity] ?? 'bg-gray-500'} h-1.5 rounded-full transition-all duration-500`}
              style={{ width: `${(s.count / total) * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Dashboard
// ---------------------------------------------------------------------------

export default function Dashboard() {
  const [liveFeed, setLiveFeed] = useState<LiveEvent[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  // ── WebSocket live feed ────────────────────────────────────────────────
  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) return;
    let ws: WebSocket;
    const connect = () => {
      ws = new WebSocket(`${WS_URL}/ws?token=${token}`);
      ws.onmessage = (e) => {
        try {
          const data: LiveEvent = JSON.parse(e.data);
          setLiveFeed(prev => [data, ...prev].slice(0, 40));
        } catch { /* ignore parse errors */ }
      };
      ws.onclose = () => { /* reconnect after 3s */ setTimeout(connect, 3000); };
      wsRef.current = ws;
    };
    connect();
    return () => wsRef.current?.close();
  }, []);

  // ── Queries ───────────────────────────────────────────────────────────
  const { data: overview } = useQuery<Overview>({
    queryKey: ['overview'],
    queryFn:  () => apiGet('/api/analytics/overview'),
    refetchInterval: 20_000,
  });
  const { data: timeline } = useQuery<TimelinePoint[]>({
    queryKey: ['timeline'],
    queryFn:  () => apiGet('/api/analytics/events/timeline?hours=24'),
    refetchInterval: 60_000,
  });
  const { data: protocol } = useQuery<ProtocolPoint[]>({
    queryKey: ['by-protocol'],
    queryFn:  () => apiGet('/api/analytics/events/by-protocol'),
    refetchInterval: 60_000,
  });
  const { data: severity } = useQuery<SeverityPoint[]>({
    queryKey: ['by-severity'],
    queryFn:  () => apiGet('/api/analytics/events/by-severity'),
    refetchInterval: 60_000,
  });
  const { data: attackers } = useQuery<Attacker[]>({
    queryKey: ['top-attackers-dash'],
    queryFn:  () => apiGet('/api/analytics/top-attackers?hours=24&limit=8'),
    refetchInterval: 30_000,
  });

  const topIp = attackers?.[0];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Dashboard</h1>
        <div className="flex items-center gap-1.5 text-xs text-gray-500">
          <Radio size={12} className="text-green-500 animate-pulse" />
          Live
        </div>
      </div>

      {/* Threat banner */}
      <ThreatBanner critical1h={overview?.critical_events_1h ?? 0} topIp={topIp} />

      {/* Stat cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
        <StatCard
          icon={Shield} label="Active Decoys"
          value={overview?.active_decoys ?? '—'}
          color="bg-indigo-900/50 text-indigo-300"
        />
        <StatCard
          icon={Zap} label="Events (24h)"
          value={overview?.events_today ?? '—'}
          color="bg-yellow-900/50 text-yellow-300"
          trend={overview?.events_trend_pct}
          sub={overview?.events_yesterday !== undefined ? `${overview.events_yesterday} yesterday` : undefined}
        />
        <StatCard
          icon={Bell} label="Open Alerts"
          value={overview?.open_alerts ?? '—'}
          color="bg-red-900/50 text-red-300"
        />
        <StatCard
          icon={Users} label="Unique Attackers (24h)"
          value={overview?.unique_attackers_24h ?? '—'}
          color="bg-purple-900/50 text-purple-300"
          trend={overview?.attackers_trend_pct}
          sub={overview?.unique_attackers_prev !== undefined ? `${overview.unique_attackers_prev} prev 24h` : undefined}
        />
      </div>

      {/* Timeline + Live Feed */}
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
        <div className="card xl:col-span-3">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-gray-300">Attack Timeline — 24h</h2>
            {timeline?.length ? (
              <span className="text-xs text-gray-600">
                peak {Math.max(...timeline.map(t => t.count))} events/hr
              </span>
            ) : null}
          </div>
          <TimelineChart data={timeline ?? []} />
        </div>

        <div className="card xl:col-span-2">
          <div className="flex items-center gap-2 mb-3">
            <Radio size={12} className="text-green-500 animate-pulse" />
            <h2 className="text-sm font-semibold text-gray-300">Live Feed</h2>
            <span className="ml-auto text-xs text-gray-600">{liveFeed.length} events</span>
          </div>
          <LiveFeed events={liveFeed} />
        </div>
      </div>

      {/* Top Attackers + Protocol bars */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
              <Globe size={14} className="text-gray-500" />
              Top Attackers (24h)
            </h2>
            <a href="/attackers" className="text-xs text-indigo-400 hover:text-indigo-300">
              View all →
            </a>
          </div>
          <TopAttackers data={attackers ?? []} />
        </div>

        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Events by Protocol (24h)</h2>
          {protocol?.length
            ? <ProtocolBars data={protocol} />
            : <p className="text-gray-600 text-xs text-center py-8">No events yet</p>}
        </div>
      </div>

      {/* Severity breakdown */}
      <div className="card">
        <h2 className="text-sm font-semibold text-gray-300 mb-3">Severity Breakdown (24h)</h2>
        {severity?.length
          ? <SeverityBreakdown data={severity} />
          : <p className="text-gray-600 text-xs text-center py-4">No events yet</p>}
      </div>
    </div>
  );
}
