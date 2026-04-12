import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { format, formatDistanceToNow } from 'date-fns';
import { ChevronDown, ChevronRight, Terminal, Key, Search, Download } from 'lucide-react';
import { apiGet } from '../api/client';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface RawData { [key: string]: unknown }

interface Event {
  id: string;
  source_ip: string;
  source_port: number | null;
  protocol: string;
  event_type: string;
  severity: string;
  session_id: string | null;
  raw_data: RawData;
  enrichment?: {
    country?: string; country_code?: string;
    city?: string; asn?: string;
    is_tor?: boolean; abuse_score?: number;
  };
  mitre_technique_ids?: string[];
  created_at: string;
}

interface EventsResponse { total: number; items: Event[] }

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEV_BADGE: Record<string, string> = {
  critical: 'badge-critical',
  high:     'badge-high',
  medium:   'badge-medium',
  low:      'badge-low',
  info:     'badge-info',
};

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info'];

const ALL_PROTOCOLS = [
  '', 'SSH', 'HTTP', 'HTTPS', 'TELNET', 'FTP', 'RDP', 'SMB',
  'MYSQL', 'POSTGRESQL', 'REDIS', 'MSSQL', 'MONGODB',
  'DNS', 'SMTP', 'SNMP', 'VNC',
  'K8S_API', 'DOCKER_API', 'AWS_METADATA',
  'MODBUS', 'DNP3', 'S7COMM', 'MQTT', 'COAP',
  'HONEYTOKEN',
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function countryFlag(code: string | null | undefined): string {
  if (!code || code.length !== 2) return '';
  const pts = [...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65);
  return String.fromCodePoint(...pts);
}

function renderValue(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'object') return JSON.stringify(v, null, 2);
  return String(v);
}

// ---------------------------------------------------------------------------
// Event detail panel
// ---------------------------------------------------------------------------

function Transcript({ transcript }: { transcript: Array<{ seq?: number; cmd: string; ts?: string }> }) {
  return (
    <div className="bg-gray-950 rounded-lg p-3 font-mono text-xs overflow-x-auto max-h-64 overflow-y-auto border border-gray-800">
      <div className="text-green-500 mb-2 text-[11px]">
        ┌── Session Transcript ({transcript.length} commands) ──────────────────
      </div>
      {transcript.map((t, i) => (
        <div key={i} className="flex gap-3 mb-1">
          <span className="text-gray-600 select-none w-4 text-right flex-shrink-0">
            {t.seq ?? i + 1}
          </span>
          <span className="text-yellow-400 flex-shrink-0">$</span>
          <span className="text-green-300 break-all">{t.cmd}</span>
          {t.ts && (
            <span className="text-gray-600 ml-auto flex-shrink-0 text-[10px]">
              {format(new Date(t.ts), 'HH:mm:ss')}
            </span>
          )}
        </div>
      ))}
      {transcript.length === 0 && (
        <span className="text-gray-600">No commands recorded</span>
      )}
    </div>
  );
}

function CredentialRow({ label, value }: { label: string; value?: string }) {
  const [show, setShow] = useState(false);
  if (!value) return null;
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="text-gray-500 w-20 flex-shrink-0">{label}</span>
      <span className={`font-mono ${show ? 'text-yellow-300' : 'text-gray-600'}`}>
        {show ? value : '•'.repeat(Math.min(value.length, 20))}
      </span>
      <button
        onClick={() => setShow(!show)}
        className="text-indigo-400 hover:text-indigo-300 text-[11px]"
      >
        {show ? 'hide' : 'reveal'}
      </button>
    </div>
  );
}

function EventDetail({ event }: { event: Event }) {
  const raw = event.raw_data || {};
  const transcript = (raw.transcript as Array<{ cmd: string; seq?: number; ts?: string }>) ?? [];
  const hasTranscript = transcript.length > 0;
  const hasCredentials = raw.username || raw.password;

  const enrichFields = [
    ['Country',     event.enrichment?.country],
    ['City',        event.enrichment?.city],
    ['ASN',         event.enrichment?.asn],
    ['TOR',         event.enrichment?.is_tor ? 'Yes' : null],
    ['Abuse Score', event.enrichment?.abuse_score ? String(event.enrichment.abuse_score) : null],
  ].filter(([, v]) => v);

  const rawFields = Object.entries(raw).filter(
    ([k]) => !['transcript', 'command_count', 'duration_seconds'].includes(k)
  );

  return (
    <div className="mt-3 pt-3 border-t border-gray-800 grid grid-cols-1 xl:grid-cols-2 gap-4">
      {/* Left: raw data fields */}
      <div className="space-y-3">
        {hasCredentials && (
          <div>
            <div className="flex items-center gap-1.5 text-xs text-gray-500 mb-1.5">
              <Key size={11} /> Captured Credentials
            </div>
            <div className="bg-gray-800/50 rounded p-2 space-y-1">
              <CredentialRow label="Username" value={raw.username as string} />
              <CredentialRow label="Password" value={raw.password as string} />
              {raw.hash && <CredentialRow label="Hash" value={raw.hash as string} />}
              {raw.community && <CredentialRow label="Community" value={raw.community as string} />}
            </div>
          </div>
        )}

        {rawFields.length > 0 && !hasCredentials && (
          <div>
            <p className="text-xs text-gray-500 mb-1.5">Raw Data</p>
            <div className="bg-gray-800/50 rounded p-2 space-y-1">
              {rawFields.slice(0, 12).map(([k, v]) => (
                <div key={k} className="flex gap-2 text-xs">
                  <span className="text-gray-500 w-28 flex-shrink-0 truncate">{k}</span>
                  <span className="text-gray-300 font-mono break-all">
                    {renderValue(v).slice(0, 120)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {rawFields.length > 0 && hasCredentials && (
          <div>
            <p className="text-xs text-gray-500 mb-1.5">Additional Data</p>
            <div className="bg-gray-800/50 rounded p-2 space-y-1">
              {rawFields.filter(([k]) => !['username','password','hash'].includes(k))
                .slice(0, 8).map(([k, v]) => (
                  <div key={k} className="flex gap-2 text-xs">
                    <span className="text-gray-500 w-28 flex-shrink-0 truncate">{k}</span>
                    <span className="text-gray-300 font-mono break-all">
                      {renderValue(v).slice(0, 100)}
                    </span>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* Enrichment */}
        {enrichFields.length > 0 && (
          <div>
            <p className="text-xs text-gray-500 mb-1.5">Enrichment</p>
            <div className="bg-gray-800/50 rounded p-2 space-y-1">
              {enrichFields.map(([k, v]) => (
                <div key={k} className="flex gap-2 text-xs">
                  <span className="text-gray-500 w-28 flex-shrink-0">{k}</span>
                  <span className="text-gray-300">{v}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* MITRE techniques */}
        {(event.mitre_technique_ids?.length ?? 0) > 0 && (
          <div className="flex flex-wrap gap-1">
            {event.mitre_technique_ids!.map(t => (
              <a
                key={t}
                href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`}
                target="_blank" rel="noopener noreferrer"
                className="text-[11px] bg-indigo-900/40 text-indigo-300 px-1.5 py-0.5 rounded hover:bg-indigo-900"
              >
                {t}
              </a>
            ))}
          </div>
        )}
      </div>

      {/* Right: transcript */}
      <div>
        {hasTranscript ? (
          <div>
            <div className="flex items-center gap-1.5 text-xs text-gray-500 mb-1.5">
              <Terminal size={11} /> Shell Transcript
            </div>
            <Transcript transcript={transcript} />
          </div>
        ) : event.session_id ? (
          <div className="text-xs text-gray-600 flex items-center gap-1.5 mt-1">
            <Terminal size={11} />
            Session: <span className="font-mono">{event.session_id}</span>
            <a href={`/sessions?id=${event.session_id}`} className="text-indigo-400 hover:text-indigo-300 ml-1">
              Replay →
            </a>
          </div>
        ) : (
          <pre className="text-[11px] text-gray-600 font-mono bg-gray-900 rounded p-2 overflow-auto max-h-48">
            {JSON.stringify(raw, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function Events() {
  const [page,      setPage]      = useState(0);
  const [severity,  setSeverity]  = useState('');
  const [protocol,  setProtocol]  = useState('');
  const [sourceIp,  setSourceIp]  = useState('');
  const [ipInput,   setIpInput]   = useState('');
  const [expanded,  setExpanded]  = useState<string | null>(null);
  const limit = 50;

  const { data, isLoading } = useQuery<EventsResponse>({
    queryKey: ['events', page, severity, protocol, sourceIp],
    queryFn: () => {
      const params = new URLSearchParams({
        offset: String(page * limit),
        limit:  String(limit),
      });
      if (severity) params.set('severity',  severity);
      if (protocol) params.set('protocol',  protocol);
      if (sourceIp) params.set('source_ip', sourceIp);
      return apiGet(`/api/events?${params}`);
    },
    refetchInterval: 15_000,
  });

  const handleIpSearch = () => {
    setSourceIp(ipInput.trim());
    setPage(0);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Events</h1>
        <span className="text-sm text-gray-400">{data?.total ?? 0} total</span>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <select
          className="input w-40"
          value={severity}
          onChange={(e) => { setSeverity(e.target.value); setPage(0); }}
        >
          {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All severities'}</option>)}
        </select>

        <select
          className="input w-44"
          value={protocol}
          onChange={(e) => { setProtocol(e.target.value); setPage(0); }}
        >
          {ALL_PROTOCOLS.map(p => <option key={p} value={p}>{p || 'All protocols'}</option>)}
        </select>

        {/* IP search */}
        <div className="flex gap-1">
          <input
            className="input w-36"
            placeholder="Filter by IP"
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleIpSearch()}
          />
          <button className="btn-secondary px-2" onClick={handleIpSearch}>
            <Search size={14} />
          </button>
          {sourceIp && (
            <button
              className="btn-secondary px-2 text-xs"
              onClick={() => { setSourceIp(''); setIpInput(''); setPage(0); }}
            >
              ✕
            </button>
          )}
        </div>

        {/* IOC Export */}
        <a
          href={`${import.meta.env.VITE_API_URL || 'http://localhost:8080'}/api/analytics/ioc-export`}
          className="btn-secondary flex items-center gap-1.5 ml-auto"
          onClick={async (e) => {
            e.preventDefault();
            const token = localStorage.getItem('access_token');
            const res = await fetch(
              `${import.meta.env.VITE_API_URL || 'http://localhost:8080'}/api/analytics/ioc-export`,
              { headers: { Authorization: `Bearer ${token}` } }
            );
            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            const cd = res.headers.get('Content-Disposition') || '';
            const fn = cd.match(/filename="([^"]+)"/)?.[1] || 'ioc-export.csv';
            a.href = url; a.download = fn; a.click();
            URL.revokeObjectURL(url);
          }}
        >
          <Download size={14} />
          Export IOCs
        </a>
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase">
              <th className="w-6 px-3 py-3" />
              <th className="px-4 py-3 text-left">Time</th>
              <th className="px-4 py-3 text-left">Source IP</th>
              <th className="px-4 py-3 text-left">Location</th>
              <th className="px-4 py-3 text-left">Protocol</th>
              <th className="px-4 py-3 text-left">Event Type</th>
              <th className="px-4 py-3 text-left">Severity</th>
              <th className="px-4 py-3 text-left">Flags</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={8} className="px-4 py-8 text-center text-gray-500">Loading…</td></tr>
            )}
            {!isLoading && !data?.items.length && (
              <tr><td colSpan={8} className="px-4 py-8 text-center text-gray-500">No events</td></tr>
            )}
            {data?.items.map(ev => {
              const isExp = expanded === ev.id;
              return (
                <>
                  <tr
                    key={ev.id}
                    className={`table-row cursor-pointer ${isExp ? 'bg-gray-800/40' : ''}`}
                    onClick={() => setExpanded(isExp ? null : ev.id)}
                  >
                    <td className="px-3 py-2.5 text-gray-600">
                      {isExp
                        ? <ChevronDown size={13} />
                        : <ChevronRight size={13} />}
                    </td>
                    <td className="px-4 py-2.5 text-gray-400 whitespace-nowrap text-xs">
                      <div>{format(new Date(ev.created_at), 'HH:mm:ss')}</div>
                      <div className="text-gray-600 text-[11px]">
                        {formatDistanceToNow(new Date(ev.created_at), { addSuffix: true })}
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <button
                        className="font-mono text-gray-200 hover:text-indigo-300 transition-colors text-xs"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSourceIp(ev.source_ip);
                          setIpInput(ev.source_ip);
                          setPage(0);
                        }}
                        title="Filter by this IP"
                      >
                        {ev.source_ip}
                      </button>
                      {ev.source_port && (
                        <span className="text-gray-600 text-[11px] ml-1">:{ev.source_port}</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-xs">
                      {ev.enrichment?.country_code && (
                        <span>{countryFlag(ev.enrichment.country_code)} </span>
                      )}
                      <span className="text-gray-400">{ev.enrichment?.country ?? '—'}</span>
                      {ev.enrichment?.city && (
                        <span className="text-gray-600 text-[11px] block">{ev.enrichment.city}</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-indigo-300 font-mono text-xs">{ev.protocol}</td>
                    <td className="px-4 py-2.5 text-gray-300 text-xs">{ev.event_type.replace(/_/g, ' ')}</td>
                    <td className="px-4 py-2.5">
                      <span className={SEV_BADGE[ev.severity] ?? 'badge-info'}>{ev.severity}</span>
                    </td>
                    <td className="px-4 py-2.5 text-xs space-x-1">
                      {ev.enrichment?.is_tor && (
                        <span className="badge-high">TOR</span>
                      )}
                      {ev.session_id && (
                        <span className="text-gray-600 font-mono text-[11px]">session</span>
                      )}
                      {ev.enrichment?.asn && (
                        <span className="text-gray-600 text-[11px]">{ev.enrichment.asn.split(' ')[0]}</span>
                      )}
                    </td>
                  </tr>

                  {/* Expanded detail row */}
                  {isExp && (
                    <tr key={`${ev.id}-detail`} className="bg-gray-900/50">
                      <td colSpan={8} className="px-4 pb-4">
                        <EventDetail event={ev} />
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm">
        <button
          className="btn-secondary"
          disabled={page === 0}
          onClick={() => setPage(p => p - 1)}
        >
          Previous
        </button>
        <span className="text-gray-400">
          Page {page + 1} · {data?.total ?? 0} events
        </span>
        <button
          className="btn-secondary"
          disabled={!data || (page + 1) * limit >= data.total}
          onClick={() => setPage(p => p + 1)}
        >
          Next
        </button>
      </div>
    </div>
  );
}
