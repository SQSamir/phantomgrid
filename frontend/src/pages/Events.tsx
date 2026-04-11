import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { formatDistanceToNow } from 'date-fns';
import { apiGet } from '../api/client';

interface Event {
  id: string;
  source_ip: string;
  protocol: string;
  event_type: string;
  severity: string;
  created_at: string;
  enrichment?: { country?: string; asn?: string; is_tor?: boolean };
}

interface EventsResponse { total: number; items: Event[] }

const SEV_BADGE: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
};

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info'];
const PROTOCOLS = ['', 'SSH', 'HTTP', 'HTTPS', 'REDIS', 'MYSQL', 'POSTGRESQL', 'DNS', 'TELNET', 'FTP', 'RDP', 'SMB', 'K8S_API', 'DOCKER_API', 'AWS_METADATA'];

export default function Events() {
  const [page, setPage] = useState(0);
  const [severity, setSeverity] = useState('');
  const [protocol, setProtocol] = useState('');
  const limit = 50;

  const { data, isLoading } = useQuery<EventsResponse>({
    queryKey: ['events', page, severity, protocol],
    queryFn: () => {
      const params = new URLSearchParams({ offset: String(page * limit), limit: String(limit) });
      if (severity) params.set('severity', severity);
      if (protocol) params.set('protocol', protocol);
      return apiGet(`/api/events?${params}`);
    },
    refetchInterval: 15_000,
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Events</h1>
        <span className="text-sm text-gray-400">{data?.total ?? 0} total</span>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <select className="input w-40" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(0); }}>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s || 'All severities'}</option>)}
        </select>
        <select className="input w-40" value={protocol} onChange={(e) => { setProtocol(e.target.value); setPage(0); }}>
          {PROTOCOLS.map((p) => <option key={p} value={p}>{p || 'All protocols'}</option>)}
        </select>
      </div>

      <div className="card p-0 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase">
              <th className="px-4 py-3 text-left">Time</th>
              <th className="px-4 py-3 text-left">Source IP</th>
              <th className="px-4 py-3 text-left">Country</th>
              <th className="px-4 py-3 text-left">Protocol</th>
              <th className="px-4 py-3 text-left">Event Type</th>
              <th className="px-4 py-3 text-left">Severity</th>
              <th className="px-4 py-3 text-left">Flags</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-500">Loading…</td></tr>
            )}
            {!isLoading && !data?.items.length && (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-500">No events</td></tr>
            )}
            {data?.items.map((ev) => (
              <tr key={ev.id} className="table-row">
                <td className="px-4 py-2.5 text-gray-400 whitespace-nowrap">
                  {formatDistanceToNow(new Date(ev.created_at), { addSuffix: true })}
                </td>
                <td className="px-4 py-2.5 font-mono text-gray-200">{ev.source_ip}</td>
                <td className="px-4 py-2.5 text-gray-400">{ev.enrichment?.country ?? '—'}</td>
                <td className="px-4 py-2.5 text-indigo-300">{ev.protocol}</td>
                <td className="px-4 py-2.5 text-gray-300">{ev.event_type}</td>
                <td className="px-4 py-2.5">
                  <span className={SEV_BADGE[ev.severity] ?? 'badge-info'}>{ev.severity}</span>
                </td>
                <td className="px-4 py-2.5 text-gray-500 text-xs">
                  {ev.enrichment?.is_tor && <span className="badge-high mr-1">TOR</span>}
                  {ev.enrichment?.asn && <span>{ev.enrichment.asn}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm">
        <button className="btn-secondary" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>Previous</button>
        <span className="text-gray-400">Page {page + 1}</span>
        <button
          className="btn-secondary"
          disabled={!data || (page + 1) * limit >= data.total}
          onClick={() => setPage((p) => p + 1)}
        >
          Next
        </button>
      </div>
    </div>
  );
}
