import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { format, formatDistanceToNow } from 'date-fns';
import {
  Terminal, ChevronLeft, Clock, User, Globe,
  Wifi, Download,
} from 'lucide-react';
import { apiGet } from '../api/client';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Session {
  session_id:   string;
  source_ip:    string;
  protocol:     string;
  country:      string | null;
  country_code: string | null;
  is_tor:       boolean;
  started_at:   string | null;
  ended_at:     string | null;
  duration_s:   number;
  event_count:  number;
}

interface SessionsResponse { total: number; items: Session[] }

interface TranscriptEntry { seq?: number; cmd: string; ts?: string }

interface SessionDetail {
  session_id:  string;
  source_ip:   string;
  protocol:    string;
  enrichment:  {
    country?: string; city?: string; asn?: string;
    is_tor?: boolean; country_code?: string;
  };
  credentials: { username?: string; password?: string };
  started_at:  string | null;
  ended_at:    string | null;
  duration_s:  number;
  event_count: number;
  transcript:  TranscriptEntry[];
  events: Array<{
    event_type: string; severity: string;
    raw_data: Record<string, unknown>; created_at: string;
  }>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function countryFlag(code: string | null | undefined): string {
  if (!code || code.length !== 2) return '';
  const pts = [...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65);
  return String.fromCodePoint(...pts);
}

function fmtDuration(s: number): string {
  if (s < 60)  return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  medium:   'text-yellow-400',
  low:      'text-green-400',
  info:     'text-blue-400',
};

// ---------------------------------------------------------------------------
// Terminal Replay
// ---------------------------------------------------------------------------

function TerminalReplay({ detail }: { detail: SessionDetail }) {
  const [playing, setPlaying] = useState(false);
  const [cursor,  setCursor]  = useState(0);

  const transcript = detail.transcript;
  const hostname   = 'web-prod-01';
  const user       = detail.credentials?.username || 'root';

  const handlePlay = () => {
    if (playing) { setPlaying(false); return; }
    if (cursor >= transcript.length) { setCursor(0); }
    setPlaying(true);
    let i = cursor;
    const tick = () => {
      if (i >= transcript.length) { setPlaying(false); return; }
      setCursor(++i);
      setTimeout(tick, 600);
    };
    setTimeout(tick, 400);
  };

  const downloadTranscript = () => {
    const lines = [
      `# Session: ${detail.session_id}`,
      `# IP: ${detail.source_ip} | Protocol: ${detail.protocol}`,
      `# Duration: ${fmtDuration(detail.duration_s)}`,
      `# Start: ${detail.started_at}`,
      '',
      ...transcript.map(t =>
        `[${t.ts ? format(new Date(t.ts), 'HH:mm:ss') : '--:--:--'}] $ ${t.cmd}`
      ),
    ].join('\n');
    const blob = new Blob([lines], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = `session-${detail.session_id.slice(0, 8)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Session metadata */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
        {[
          { icon: User,   label: 'Attacker',  value: `${detail.source_ip}${detail.enrichment?.country ? ` · ${countryFlag(detail.enrichment.country_code)} ${detail.enrichment.country}` : ''}` },
          { icon: Clock,  label: 'Duration',  value: fmtDuration(detail.duration_s) },
          { icon: Terminal, label: 'Commands', value: `${transcript.length} commands` },
          { icon: Globe,  label: 'ASN',       value: detail.enrichment?.asn || '—' },
        ].map(m => (
          <div key={m.label} className="card py-3 flex items-center gap-3">
            <m.icon size={16} className="text-gray-500 flex-shrink-0" />
            <div>
              <p className="text-xs text-gray-500">{m.label}</p>
              <p className="text-sm text-white font-medium truncate">{m.value}</p>
            </div>
          </div>
        ))}
      </div>

      {detail.credentials?.username && (
        <div className="bg-yellow-950/40 border border-yellow-800/40 rounded-lg px-4 py-2.5 text-sm flex items-center gap-3">
          <span className="text-yellow-400 font-semibold">Credentials captured:</span>
          <code className="text-green-400 font-mono">
            {detail.credentials.username}
          </code>
          <span className="text-gray-500">:</span>
          <code className="text-yellow-300 font-mono">
            {detail.credentials.password || '(empty)'}
          </code>
        </div>
      )}

      {/* Terminal */}
      <div className="card p-0 overflow-hidden">
        {/* Terminal title bar */}
        <div className="flex items-center gap-2 px-4 py-2.5 bg-gray-800 border-b border-gray-700">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500/70" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/70" />
            <div className="w-3 h-3 rounded-full bg-green-500/70" />
          </div>
          <span className="flex-1 text-center text-xs text-gray-400 font-mono">
            {user}@{hostname}: ~
          </span>
          <div className="flex gap-2">
            <button
              className="text-xs text-gray-400 hover:text-gray-200 px-2 py-0.5 rounded bg-gray-700 hover:bg-gray-600"
              onClick={handlePlay}
            >
              {playing ? '⏸ Pause' : cursor === 0 ? '▶ Play' : '▶ Resume'}
            </button>
            <button
              className="text-xs text-gray-400 hover:text-gray-200 px-2 py-0.5 rounded bg-gray-700 hover:bg-gray-600"
              onClick={() => { setCursor(transcript.length); setPlaying(false); }}
            >
              ⏭ End
            </button>
            <button
              className="text-xs text-gray-400 hover:text-gray-200 px-2 py-0.5 rounded bg-gray-700 hover:bg-gray-600"
              onClick={downloadTranscript}
            >
              <Download size={11} />
            </button>
          </div>
        </div>

        {/* Terminal body */}
        <div className="bg-gray-950 p-4 font-mono text-xs min-h-64 max-h-[28rem] overflow-y-auto">
          {/* Banner */}
          <div className="text-gray-500 mb-3 text-[11px]">
            <p>Ubuntu 22.04.3 LTS {hostname} tty1</p>
            <p className="mt-0.5">{hostname} login: <span className="text-white">{user}</span></p>
            <p className="text-green-500 mt-1">Last login: {detail.started_at ? format(new Date(detail.started_at), 'EEE MMM dd HH:mm:ss yyyy') : ''}</p>
            <p className="mt-2" />
          </div>

          {transcript.slice(0, cursor).map((t, i) => (
            <div key={i} className="mb-2">
              <div className="flex items-center gap-1">
                <span className="text-green-500">{user}@{hostname}</span>
                <span className="text-gray-500">:</span>
                <span className="text-blue-400">~</span>
                <span className="text-white">$</span>
                <span className="text-white ml-1">{t.cmd}</span>
              </div>
              {/* Show fake output for common commands */}
              {t.cmd === 'whoami' && (
                <div className="text-gray-300 ml-0 mt-0.5">{user}</div>
              )}
              {t.cmd.startsWith('ls') && (
                <div className="text-blue-300 mt-0.5">
                  Documents  Downloads  .bash_history  .ssh
                </div>
              )}
              {t.cmd === 'pwd' && (
                <div className="text-gray-300 mt-0.5">/root</div>
              )}
            </div>
          ))}

          {/* Blinking cursor */}
          {cursor < transcript.length && (
            <div className="flex items-center gap-1">
              <span className="text-green-500">{user}@{hostname}</span>
              <span className="text-gray-500">:</span>
              <span className="text-blue-400">~</span>
              <span className="text-white">$</span>
              <span className="w-1.5 h-3 bg-white animate-pulse ml-1" />
            </div>
          )}

          {cursor >= transcript.length && transcript.length > 0 && (
            <div className="text-gray-600 text-[11px] mt-3 border-t border-gray-800 pt-2">
              Session ended · {fmtDuration(detail.duration_s)} · {transcript.length} commands
            </div>
          )}

          {transcript.length === 0 && (
            <div className="text-gray-600 text-center py-8">
              No command transcript available for this session
            </div>
          )}
        </div>
      </div>

      {/* Event timeline */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-300 mb-3">Session Event Timeline</h3>
        <div className="space-y-1.5">
          {detail.events.map((ev, i) => (
            <div key={i} className="flex items-start gap-3 text-xs">
              <span className={`font-semibold flex-shrink-0 w-16 ${SEV_COLOR[ev.severity] ?? 'text-gray-400'}`}>
                {ev.event_type.replace(/_/g, ' ').slice(0, 14)}
              </span>
              <span className="text-gray-500 flex-shrink-0">
                {ev.created_at ? format(new Date(ev.created_at), 'HH:mm:ss') : ''}
              </span>
              <span className="text-gray-400 truncate">
                {ev.raw_data?.command
                  ? `$ ${ev.raw_data.command}`
                  : ev.raw_data?.username
                  ? `user: ${ev.raw_data.username}`
                  : ''}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sessions list
// ---------------------------------------------------------------------------

function SessionRow({
  session,
  onSelect,
}: {
  session: Session;
  onSelect: (id: string) => void;
}) {
  return (
    <tr
      className="table-row cursor-pointer"
      onClick={() => onSelect(session.session_id)}
    >
      <td className="px-4 py-2.5 font-mono text-xs text-gray-400">
        {session.session_id.slice(0, 16)}…
      </td>
      <td className="px-4 py-2.5 font-mono text-gray-200 text-xs">
        {session.source_ip}
        {session.country_code && (
          <span className="ml-2" title={session.country ?? ''}>
            {countryFlag(session.country_code)}
          </span>
        )}
      </td>
      <td className="px-4 py-2.5 text-xs">
        <span className="text-indigo-300 font-mono">{session.protocol}</span>
      </td>
      <td className="px-4 py-2.5 text-xs text-gray-400">
        {session.started_at
          ? formatDistanceToNow(new Date(session.started_at), { addSuffix: true })
          : '—'}
      </td>
      <td className="px-4 py-2.5 text-xs text-gray-400">
        {fmtDuration(session.duration_s)}
      </td>
      <td className="px-4 py-2.5 text-xs text-gray-400">
        {session.event_count}
      </td>
      <td className="px-4 py-2.5 text-xs">
        {session.is_tor && (
          <span className="bg-purple-900/60 text-purple-300 px-1.5 py-px rounded flex items-center gap-0.5 w-fit">
            <Wifi size={9} /> TOR
          </span>
        )}
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function Sessions() {
  const [page,       setPage]       = useState(0);
  const [protocol,   setProtocol]   = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const limit = 30;

  const { data, isLoading } = useQuery<SessionsResponse>({
    queryKey: ['sessions', page, protocol],
    queryFn: () => {
      const p = new URLSearchParams({ offset: String(page * limit), limit: String(limit) });
      if (protocol) p.set('protocol', protocol);
      return apiGet(`/api/analytics/sessions?${p}`);
    },
    refetchInterval: 30_000,
  });

  const { data: detail, isLoading: detailLoading } = useQuery<SessionDetail>({
    queryKey: ['session-detail', selectedId],
    queryFn:  () => apiGet(`/api/analytics/sessions/${selectedId}`),
    enabled:  !!selectedId,
  });

  // Detail view
  if (selectedId) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <button
            className="btn-secondary flex items-center gap-1.5 text-sm"
            onClick={() => setSelectedId(null)}
          >
            <ChevronLeft size={14} /> Back
          </button>
          <div>
            <h1 className="text-xl font-bold text-white">Session Replay</h1>
            <p className="text-xs text-gray-500 font-mono">{selectedId}</p>
          </div>
        </div>
        {detailLoading && (
          <div className="card text-center text-gray-500 py-8">Loading session…</div>
        )}
        {detail && <TerminalReplay detail={detail} />}
      </div>
    );
  }

  // List view
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Sessions</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Interactive attacker sessions with full command replay
          </p>
        </div>
        <span className="text-sm text-gray-400">{data?.total ?? 0} sessions</span>
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        <select
          className="input w-40"
          value={protocol}
          onChange={e => { setProtocol(e.target.value); setPage(0); }}
        >
          <option value="">All protocols</option>
          <option value="SSH">SSH</option>
          <option value="TELNET">Telnet</option>
          <option value="FTP">FTP</option>
        </select>
      </div>

      <div className="card p-0 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase">
              <th className="px-4 py-3 text-left">Session ID</th>
              <th className="px-4 py-3 text-left">Source IP</th>
              <th className="px-4 py-3 text-left">Protocol</th>
              <th className="px-4 py-3 text-left">Started</th>
              <th className="px-4 py-3 text-left">Duration</th>
              <th className="px-4 py-3 text-left">Events</th>
              <th className="px-4 py-3 text-left">Flags</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-500">Loading…</td>
              </tr>
            )}
            {!isLoading && !data?.items.length && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                  No sessions yet. Deploy an SSH or Telnet decoy and wait for connections.
                </td>
              </tr>
            )}
            {data?.items.map(s => (
              <SessionRow key={s.session_id} session={s} onSelect={setSelectedId} />
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm">
        <button
          className="btn-secondary"
          disabled={page === 0}
          onClick={() => setPage(p => p - 1)}
        >
          Previous
        </button>
        <span className="text-gray-400">Page {page + 1} · {data?.total ?? 0} sessions</span>
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
