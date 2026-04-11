import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { formatDistanceToNow } from 'date-fns';
import { apiGet, apiPatch } from '../api/client';

interface Alert {
  id: string;
  title: string;
  summary: string;
  severity: string;
  status: string;
  source_ip: string | null;
  mitre_technique_ids: string[];
  first_seen_at: string;
  last_seen_at: string;
  event_count: number;
}

interface AlertsResponse { total: number; items: Alert[] }

const SEV_BADGE: Record<string, string> = {
  critical: 'badge-critical', high: 'badge-high',
  medium: 'badge-medium', low: 'badge-low', info: 'badge-info',
};

const STATUS_COLOR: Record<string, string> = {
  new: 'text-red-400', investigating: 'text-yellow-400',
  resolved: 'text-green-400', suppressed: 'text-gray-500',
};

const STATUSES = ['', 'new', 'investigating', 'resolved', 'suppressed'];

export default function Alerts() {
  const qc = useQueryClient();
  const [status, setStatus] = useState('new');
  const [page, setPage] = useState(0);
  const limit = 50;

  const { data, isLoading } = useQuery<AlertsResponse>({
    queryKey: ['alerts', page, status],
    queryFn: () => {
      const params = new URLSearchParams({ offset: String(page * limit), limit: String(limit) });
      if (status) params.set('status', status);
      return apiGet(`/api/alerts?${params}`);
    },
    refetchInterval: 15_000,
  });

  const updateStatus = useMutation({
    mutationFn: ({ id, newStatus }: { id: string; newStatus: string }) =>
      apiPatch(`/api/alerts/${id}`, { status: newStatus }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Alerts</h1>
        <span className="text-sm text-gray-400">{data?.total ?? 0} matching</span>
      </div>

      <div className="flex gap-3">
        <select className="input w-44" value={status} onChange={(e) => { setStatus(e.target.value); setPage(0); }}>
          {STATUSES.map((s) => <option key={s} value={s}>{s || 'All statuses'}</option>)}
        </select>
      </div>

      <div className="space-y-3">
        {isLoading && <p className="text-gray-500 text-center py-8">Loading…</p>}
        {!isLoading && !data?.items.length && <p className="text-gray-500 text-center py-8">No alerts</p>}
        {data?.items.map((al) => (
          <div key={al.id} className="card hover:border-gray-700 transition-colors">
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className={SEV_BADGE[al.severity] ?? 'badge-info'}>{al.severity}</span>
                  <span className={`text-xs font-medium capitalize ${STATUS_COLOR[al.status] ?? 'text-gray-400'}`}>
                    {al.status}
                  </span>
                  <span className="text-xs text-gray-600">#{al.id.slice(0, 8)}</span>
                </div>
                <h3 className="font-semibold text-white">{al.title}</h3>
                <p className="text-sm text-gray-400 mt-0.5">{al.summary}</p>
                <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                  {al.source_ip && <span>IP: <span className="font-mono text-gray-400">{al.source_ip}</span></span>}
                  <span>{al.event_count} events</span>
                  <span>First seen {formatDistanceToNow(new Date(al.first_seen_at), { addSuffix: true })}</span>
                  {al.mitre_technique_ids.length > 0 && (
                    <span className="text-indigo-400">{al.mitre_technique_ids.join(', ')}</span>
                  )}
                </div>
              </div>
              <div className="flex gap-2 flex-shrink-0">
                {al.status === 'new' && (
                  <button
                    className="btn-secondary text-xs py-1"
                    onClick={() => updateStatus.mutate({ id: al.id, newStatus: 'investigating' })}
                  >
                    Investigate
                  </button>
                )}
                {al.status !== 'resolved' && al.status !== 'suppressed' && (
                  <button
                    className="btn-primary text-xs py-1"
                    onClick={() => updateStatus.mutate({ id: al.id, newStatus: 'resolved' })}
                  >
                    Resolve
                  </button>
                )}
                {al.status !== 'suppressed' && (
                  <button
                    className="btn-secondary text-xs py-1 text-gray-500"
                    onClick={() => updateStatus.mutate({ id: al.id, newStatus: 'suppressed' })}
                  >
                    Suppress
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

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
