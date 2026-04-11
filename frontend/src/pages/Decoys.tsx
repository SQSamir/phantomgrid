import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Play, Pause, Trash2, RefreshCw } from 'lucide-react';
import { apiGet, apiPost, apiDelete } from '../api/client';
import { apiFetch } from '../api/client';

interface Decoy {
  id: string; name: string; type: string; status: string;
  ip_address: string | null; port: number | null; interaction_count: number;
  deployed_at: string | null; created_at: string;
}
interface DecoyNetwork { id: string; name: string; cidr: string; }

const STATUS_COLOR: Record<string, string> = {
  draft: 'text-gray-400', deploying: 'text-yellow-400', active: 'text-green-400',
  paused: 'text-orange-400', error: 'text-red-400', destroyed: 'text-gray-600',
};

const DECOY_TYPES = [
  'ssh_honeypot','http_honeypot','https_honeypot','redis_honeypot','mysql_honeypot',
  'ftp_honeypot','telnet_honeypot','dns_honeypot','smb_honeypot','k8s_api_honeypot',
  'docker_api_honeypot','aws_metadata_honeypot',
];

export default function Decoys() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState('');
  const [type, setType] = useState('ssh_honeypot');
  const [port, setPort] = useState('');
  const [error, setError] = useState('');

  const { data: decoys = [], isLoading } = useQuery<Decoy[]>({
    queryKey: ['decoys'],
    queryFn: async () => {
      const r = await apiGet<{ items: Decoy[] }>('/api/decoys?limit=200');
      return r.items;
    },
    refetchInterval: 20_000,
  });

  const action = useMutation({
    mutationFn: ({ id, act }: { id: string; act: string }) =>
      apiFetch(`/api/decoys/${id}/${act}`, { method: 'POST' }).then((r) => {
        if (!r.ok) throw new Error(`Action ${act} failed`);
        return r.json();
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['decoys'] }),
  });

  const destroy = useMutation({
    mutationFn: (id: string) => apiDelete(`/api/decoys/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['decoys'] }),
  });

  const create = useMutation({
    mutationFn: () => apiPost('/api/decoys', {
      name, type, port: port ? parseInt(port) : undefined,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['decoys'] });
      setShowCreate(false); setName(''); setPort(''); setError('');
    },
    onError: (e: any) => setError(e.message),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Decoys</h1>
        <button className="btn-primary flex items-center gap-2" onClick={() => setShowCreate(true)}>
          <Plus size={16} /> New Decoy
        </button>
      </div>

      {showCreate && (
        <div className="card border-indigo-800">
          <h3 className="font-semibold mb-4">Create Decoy</h3>
          {error && <p className="text-red-400 text-sm mb-3">{error}</p>}
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Name</label>
              <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Type</label>
              <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
                {DECOY_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Port (optional)</label>
              <input className="input" type="number" value={port} onChange={(e) => setPort(e.target.value)} />
            </div>
          </div>
          <div className="flex gap-2 mt-4">
            <button className="btn-primary" onClick={() => create.mutate()} disabled={!name || create.isPending}>
              {create.isPending ? 'Creating…' : 'Create'}
            </button>
            <button className="btn-secondary" onClick={() => { setShowCreate(false); setError(''); }}>Cancel</button>
          </div>
        </div>
      )}

      <div className="card p-0 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase">
              <th className="px-4 py-3 text-left">Name</th>
              <th className="px-4 py-3 text-left">Type</th>
              <th className="px-4 py-3 text-left">Status</th>
              <th className="px-4 py-3 text-left">Address</th>
              <th className="px-4 py-3 text-left">Interactions</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">Loading…</td></tr>}
            {!isLoading && !decoys.length && <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">No decoys yet</td></tr>}
            {decoys.filter((d) => d.status !== 'destroyed').map((d) => (
              <tr key={d.id} className="table-row">
                <td className="px-4 py-2.5 font-medium text-white">{d.name}</td>
                <td className="px-4 py-2.5 text-gray-400">{d.type}</td>
                <td className="px-4 py-2.5">
                  <span className={`text-xs font-medium capitalize ${STATUS_COLOR[d.status] ?? 'text-gray-400'}`}>
                    {d.status}
                  </span>
                </td>
                <td className="px-4 py-2.5 font-mono text-gray-400 text-xs">
                  {d.ip_address ? `${d.ip_address}:${d.port ?? '?'}` : '—'}
                </td>
                <td className="px-4 py-2.5 text-gray-300">{d.interaction_count}</td>
                <td className="px-4 py-2.5 text-right">
                  <div className="flex items-center justify-end gap-1">
                    {d.status === 'draft' && (
                      <button className="p-1.5 rounded hover:bg-gray-700 text-green-400" title="Deploy" onClick={() => action.mutate({ id: d.id, act: 'deploy' })}>
                        <Play size={14} />
                      </button>
                    )}
                    {d.status === 'deploying' && (
                      <button className="p-1.5 rounded hover:bg-gray-700 text-green-400" title="Activate" onClick={() => action.mutate({ id: d.id, act: 'activate' })}>
                        <RefreshCw size={14} />
                      </button>
                    )}
                    {d.status === 'active' && (
                      <button className="p-1.5 rounded hover:bg-gray-700 text-yellow-400" title="Pause" onClick={() => action.mutate({ id: d.id, act: 'pause' })}>
                        <Pause size={14} />
                      </button>
                    )}
                    {d.status === 'paused' && (
                      <button className="p-1.5 rounded hover:bg-gray-700 text-green-400" title="Resume" onClick={() => action.mutate({ id: d.id, act: 'resume' })}>
                        <Play size={14} />
                      </button>
                    )}
                    <button
                      className="p-1.5 rounded hover:bg-gray-700 text-red-400"
                      title="Destroy"
                      onClick={() => { if (confirm('Destroy this decoy?')) destroy.mutate(d.id); }}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
