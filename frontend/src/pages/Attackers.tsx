import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { formatDistanceToNow } from 'date-fns';
import {
  ChevronDown, ChevronRight, Shield, Download,
  Globe, Wifi, AlertTriangle,
} from 'lucide-react';
import { apiGet } from '../api/client';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Attacker {
  source_ip:    string;
  event_count:  number;
  protocols_hit: number;
  protocols:    string[];
  last_seen:    string;
  country:      string | null;
  country_code: string | null;
  city:         string | null;
  asn:          string | null;
  isp:          string | null;
  lat:          number | null;
  lon:          number | null;
  is_tor:       boolean;
}

interface RecentEvent {
  id: string; event_type: string; protocol: string;
  severity: string; created_at: string; raw_data?: Record<string, unknown>;
}

interface EventsResponse { total: number; items: RecentEvent[] }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function countryFlag(code: string | null | undefined): string {
  if (!code || code.length !== 2) return '';
  const pts = [...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65);
  return String.fromCodePoint(...pts);
}

const SEV_BADGE: Record<string, string> = {
  critical: 'badge-critical', high: 'badge-high',
  medium: 'badge-medium', low: 'badge-low', info: 'badge-info',
};

const PROTO_COLORS: Record<string, string> = {
  SSH:       'bg-emerald-900/60 text-emerald-300',
  HTTP:      'bg-blue-900/60 text-blue-300',
  HTTPS:     'bg-blue-900/60 text-blue-300',
  RDP:       'bg-purple-900/60 text-purple-300',
  SMB:       'bg-purple-900/60 text-purple-300',
  MSSQL:     'bg-orange-900/60 text-orange-300',
  TELNET:    'bg-yellow-900/60 text-yellow-300',
  MODBUS:    'bg-red-900/60 text-red-300',
  DNP3:      'bg-red-900/60 text-red-300',
  S7COMM:    'bg-red-900/60 text-red-300',
  MQTT:      'bg-teal-900/60 text-teal-300',
  COAP:      'bg-teal-900/60 text-teal-300',
  DOCKER_API:'bg-cyan-900/60 text-cyan-300',
  K8S_API:   'bg-cyan-900/60 text-cyan-300',
};

function ThreatScore({ a }: { a: Attacker }) {
  let score = 0;
  if (a.event_count > 200) score += 3;
  else if (a.event_count > 50) score += 2;
  else score += 1;
  if (a.is_tor) score += 3;
  if (a.protocols_hit >= 4) score += 2;
  else if (a.protocols_hit >= 2) score += 1;
  if (a.protocols.some(p => ['MODBUS','DNP3','S7COMM'].includes(p))) score += 2;
  if (a.protocols.some(p => ['DOCKER_API','K8S_API'].includes(p))) score += 2;

  const capped = Math.min(score, 10);
  const color = capped >= 7 ? 'text-red-400' : capped >= 4 ? 'text-orange-400' : 'text-yellow-400';
  const label = capped >= 7 ? 'Critical' : capped >= 4 ? 'High' : 'Medium';

  return (
    <div className="flex items-center gap-1.5">
      <div className="flex gap-0.5">
        {Array.from({ length: 10 }).map((_, i) => (
          <div
            key={i}
            className={`w-1.5 h-3 rounded-sm ${
              i < capped
                ? capped >= 7 ? 'bg-red-500'
                : capped >= 4 ? 'bg-orange-500' : 'bg-yellow-500'
                : 'bg-gray-700'
            }`}
          />
        ))}
      </div>
      <span className={`text-xs font-semibold ${color}`}>{label}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Attacker detail panel
// ---------------------------------------------------------------------------

function AttackerDetail({ attacker }: { attacker: Attacker }) {
  const { data } = useQuery<EventsResponse>({
    queryKey: ['attacker-events', attacker.source_ip],
    queryFn: () => apiGet(
      `/api/events?source_ip=${encodeURIComponent(attacker.source_ip)}&limit=20`
    ),
  });

  const credentials: Array<{ username?: string; password?: string; protocol: string }> = [];
  data?.items.forEach(ev => {
    if (ev.raw_data?.username || ev.raw_data?.password) {
      credentials.push({
        username: ev.raw_data.username as string,
        password: ev.raw_data.password as string,
        protocol: ev.protocol,
      });
    }
  });

  const uniqueCreds = credentials.filter(
    (c, i, arr) => arr.findIndex(x => x.username === c.username && x.password === c.password) === i
  );

  return (
    <div className="mt-3 pt-3 border-t border-gray-800 grid grid-cols-1 xl:grid-cols-3 gap-4">
      {/* Info */}
      <div className="space-y-3">
        <div>
          <p className="text-xs text-gray-500 mb-1.5 flex items-center gap-1">
            <Globe size={11} /> Geolocation
          </p>
          <div className="bg-gray-800/50 rounded p-2 space-y-1 text-xs">
            {[
              ['Country',   attacker.country],
              ['City',      attacker.city],
              ['ASN',       attacker.asn],
              ['ISP',       attacker.isp],
              ['Latitude',  attacker.lat != null ? String(attacker.lat) : null],
              ['Longitude', attacker.lon != null ? String(attacker.lon) : null],
            ].filter(([,v]) => v).map(([k, v]) => (
              <div key={k} className="flex gap-2">
                <span className="text-gray-500 w-20 flex-shrink-0">{k}</span>
                <span className="text-gray-300 font-mono">{v}</span>
              </div>
            ))}
            {attacker.is_tor && (
              <div className="flex items-center gap-1.5 mt-1 text-purple-300">
                <Wifi size={10} /> Using TOR anonymization
              </div>
            )}
          </div>
        </div>

        <div>
          <p className="text-xs text-gray-500 mb-1.5">Protocols Targeted</p>
          <div className="flex flex-wrap gap-1">
            {attacker.protocols.map(p => (
              <span
                key={p}
                className={`text-[11px] px-1.5 py-0.5 rounded font-mono ${
                  PROTO_COLORS[p] ?? 'bg-gray-800 text-gray-400'
                }`}
              >
                {p}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Captured credentials */}
      <div>
        <p className="text-xs text-gray-500 mb-1.5 flex items-center gap-1">
          <Shield size={11} /> Captured Credentials ({uniqueCreds.length})
        </p>
        {uniqueCreds.length > 0 ? (
          <div className="bg-gray-800/50 rounded p-2 space-y-1.5 max-h-48 overflow-y-auto">
            {uniqueCreds.slice(0, 15).map((c, i) => (
              <div key={i} className="text-xs border-b border-gray-700/50 pb-1 last:border-0">
                <div className="flex gap-2">
                  <span className="text-gray-600 w-16 flex-shrink-0">{c.protocol}</span>
                  <span className="text-green-400 font-mono">{c.username || '—'}</span>
                  <span className="text-gray-500">:</span>
                  <span className="text-yellow-400 font-mono">{c.password || '—'}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-gray-600 bg-gray-800/50 rounded p-2">
            No credentials captured yet
          </p>
        )}
      </div>

      {/* Recent events */}
      <div>
        <p className="text-xs text-gray-500 mb-1.5">Recent Events (last 20)</p>
        <div className="space-y-1 max-h-48 overflow-y-auto">
          {data?.items.map(ev => (
            <div key={ev.id} className="flex items-center gap-2 text-xs py-0.5">
              <span className={`text-[11px] px-1 py-px rounded ${SEV_BADGE[ev.severity] ?? ''}`}>
                {ev.severity.slice(0, 4)}
              </span>
              <span className="text-indigo-400 font-mono w-16 truncate">{ev.protocol}</span>
              <span className="text-gray-400 truncate flex-1">
                {ev.event_type.replace(/_/g, ' ')}
              </span>
              <span className="text-gray-600 text-[11px] flex-shrink-0">
                {formatDistanceToNow(new Date(ev.created_at), { addSuffix: true })}
              </span>
            </div>
          ))}
          {!data?.items.length && (
            <p className="text-xs text-gray-600">Loading…</p>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function Attackers() {
  const [hours,    setHours]    = useState(24);
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data: attackers, isLoading } = useQuery<Attacker[]>({
    queryKey: ['attackers', hours],
    queryFn:  () => apiGet(`/api/analytics/top-attackers?hours=${hours}&limit=50`),
    refetchInterval: 30_000,
  });

  const handleExport = async () => {
    const token = localStorage.getItem('access_token');
    const res = await fetch(
      `${import.meta.env.VITE_API_URL || 'http://localhost:8080'}/api/analytics/ioc-export?hours=${hours * 7}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    const cd   = res.headers.get('Content-Disposition') || '';
    const fn   = cd.match(/filename="([^"]+)"/)?.[1] || 'ioc-export.csv';
    a.href = url; a.download = fn; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Attackers</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            IP profiles, captured credentials, and threat scoring
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            className="input w-32"
            value={hours}
            onChange={e => setHours(Number(e.target.value))}
          >
            <option value={1}>Last 1h</option>
            <option value={6}>Last 6h</option>
            <option value={24}>Last 24h</option>
            <option value={72}>Last 3d</option>
            <option value={168}>Last 7d</option>
          </select>
          <button className="btn-secondary flex items-center gap-1.5" onClick={handleExport}>
            <Download size={14} /> Export IOCs
          </button>
        </div>
      </div>

      {/* Stats bar */}
      {attackers && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Total Attackers',  value: attackers.length },
            { label: 'TOR Users',        value: attackers.filter(a => a.is_tor).length },
            { label: 'Multi-Protocol',   value: attackers.filter(a => a.protocols_hit > 1).length },
            { label: 'OT/ICS Targets',   value: attackers.filter(a =>
              a.protocols.some(p => ['MODBUS','DNP3','S7COMM'].includes(p))
            ).length },
          ].map(s => (
            <div key={s.label} className="card py-3">
              <p className="text-2xl font-bold text-white">{s.value}</p>
              <p className="text-xs text-gray-500 mt-0.5">{s.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Attacker list */}
      <div className="space-y-2">
        {isLoading && (
          <div className="card text-center text-gray-500 py-8">Loading attackers…</div>
        )}
        {!isLoading && !attackers?.length && (
          <div className="card text-center text-gray-500 py-8">
            No attacker data for this period
          </div>
        )}

        {attackers?.map(a => {
          const isExp = expanded === a.source_ip;
          return (
            <div key={a.source_ip} className="card">
              <button
                className="w-full flex items-center gap-3 text-left"
                onClick={() => setExpanded(isExp ? null : a.source_ip)}
              >
                {/* Expand toggle */}
                <span className="text-gray-600 flex-shrink-0">
                  {isExp ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </span>

                {/* IP + Location */}
                <div className="flex items-center gap-2 flex-1 min-w-0">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-gray-100 text-sm">{a.source_ip}</span>
                      {a.country_code && (
                        <span className="text-base" title={a.country ?? ''}>{countryFlag(a.country_code)}</span>
                      )}
                      {a.is_tor && (
                        <span className="bg-purple-900/60 text-purple-300 text-[10px] px-1.5 py-px rounded flex items-center gap-0.5">
                          <Wifi size={9} /> TOR
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-gray-500 mt-0.5">
                      {[a.city, a.country].filter(Boolean).join(', ') || 'Unknown location'}
                      {a.asn && <span className="text-gray-600 ml-2 font-mono">{a.asn.split(' ')[0]}</span>}
                    </p>
                  </div>
                </div>

                {/* Protocols */}
                <div className="hidden xl:flex flex-wrap gap-1 max-w-xs">
                  {a.protocols.slice(0, 5).map(p => (
                    <span
                      key={p}
                      className={`text-[11px] px-1 py-px rounded font-mono ${
                        PROTO_COLORS[p] ?? 'bg-gray-800 text-gray-400'
                      }`}
                    >
                      {p}
                    </span>
                  ))}
                  {a.protocols.length > 5 && (
                    <span className="text-[11px] text-gray-600">+{a.protocols.length - 5}</span>
                  )}
                </div>

                {/* Threat score */}
                <div className="hidden xl:block flex-shrink-0">
                  <ThreatScore a={a} />
                </div>

                {/* Stats */}
                <div className="flex items-center gap-4 flex-shrink-0 text-right">
                  <div>
                    <p className="text-sm font-bold text-white">{a.event_count}</p>
                    <p className="text-xs text-gray-500">events</p>
                  </div>
                  <div>
                    <p className="text-sm font-bold text-indigo-300">{a.protocols_hit}</p>
                    <p className="text-xs text-gray-500">protocols</p>
                  </div>
                  <div className="hidden xl:block text-xs text-gray-500">
                    {formatDistanceToNow(new Date(a.last_seen), { addSuffix: true })}
                  </div>
                </div>

                {/* Threat indicator */}
                {a.event_count > 100 || a.is_tor || a.protocols.some(p => ['MODBUS','K8S_API','DOCKER_API'].includes(p)) ? (
                  <AlertTriangle size={14} className="text-orange-400 flex-shrink-0" />
                ) : null}
              </button>

              {/* Expanded detail */}
              {isExp && <AttackerDetail attacker={a} />}
            </div>
          );
        })}
      </div>
    </div>
  );
}
