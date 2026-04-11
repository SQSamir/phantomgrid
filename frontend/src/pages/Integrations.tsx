import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Trash2, TestTube2, ToggleLeft, ToggleRight } from 'lucide-react';
import { apiGet, apiPost, apiPatch, apiDelete, apiFetch } from '../api/client';

interface Integration {
  id: string; name: string; type: string; config: Record<string, any>;
  enabled: boolean; last_triggered_at: string | null; created_at: string;
}
interface IntegrationsResponse { total: number; items: Integration[] }

const TYPE_LABELS: Record<string, string> = {
  webhook: 'Webhook', slack: 'Slack', email: 'Email', pagerduty: 'PagerDuty',
};

function ConfigFields({ type, config, onChange }: {
  type: string;
  config: Record<string, any>;
  onChange: (c: Record<string, any>) => void;
}) {
  const f = (key: string, label: string, placeholder?: string) => (
    <div key={key}>
      <label className="block text-xs text-gray-400 mb-1">{label}</label>
      <input
        className="input"
        value={config[key] ?? ''}
        onChange={(e) => onChange({ ...config, [key]: e.target.value })}
        placeholder={placeholder}
      />
    </div>
  );
  if (type === 'webhook') return <>{f('url', 'URL', 'https://…')}{f('secret', 'HMAC Secret (optional)')}</>;
  if (type === 'slack') return <>{f('webhook_url', 'Slack Webhook URL', 'https://hooks.slack.com/…')}</>;
  if (type === 'email') return (
    <div>
      <label className="block text-xs text-gray-400 mb-1">Recipients (comma-separated)</label>
      <input
        className="input"
        value={(config.to ?? []).join(', ')}
        onChange={(e) => onChange({ ...config, to: e.target.value.split(',').map((s: string) => s.trim()).filter(Boolean) })}
        placeholder="alice@example.com, bob@example.com"
      />
    </div>
  );
  if (type === 'pagerduty') return <>{f('routing_key', 'Routing Key (Events API v2)')}</>;
  return null;
}

export default function Integrations() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState('');
  const [type, setType] = useState('webhook');
  const [config, setConfig] = useState<Record<string, any>>({});
  const [error, setError] = useState('');
  const [testResults, setTestResults] = useState<Record<string, any>>({});

  const { data, isLoading } = useQuery<IntegrationsResponse>({
    queryKey: ['integrations'],
    queryFn: () => apiGet('/api/integrations'),
  });

  const create = useMutation({
    mutationFn: () => apiPost('/api/integrations', { name, type, config }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['integrations'] });
      setShowCreate(false); setName(''); setConfig({}); setError('');
    },
    onError: (e: any) => setError(e.message),
  });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiPatch(`/api/integrations/${id}`, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['integrations'] }),
  });

  const remove = useMutation({
    mutationFn: (id: string) => apiDelete(`/api/integrations/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['integrations'] }),
  });

  const test = async (id: string) => {
    try {
      const res = await apiFetch(`/api/integrations/${id}/test`, { method: 'POST' });
      const d = await res.json();
      setTestResults((prev) => ({ ...prev, [id]: d }));
    } catch (e: any) {
      setTestResults((prev) => ({ ...prev, [id]: { ok: false, error: e.message } }));
    }
    setTimeout(() => setTestResults((prev) => { const next = { ...prev }; delete next[id]; return next; }), 5000);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Integrations</h1>
        <button className="btn-primary flex items-center gap-2" onClick={() => setShowCreate(true)}>
          <Plus size={16} /> Add Integration
        </button>
      </div>

      {showCreate && (
        <div className="card border-indigo-800">
          <h3 className="font-semibold mb-4">New Integration</h3>
          {error && <p className="text-red-400 text-sm mb-3">{error}</p>}
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-gray-400 mb-1">Name</label>
                <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Type</label>
                <select className="input" value={type} onChange={(e) => { setType(e.target.value); setConfig({}); }}>
                  {Object.entries(TYPE_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                </select>
              </div>
            </div>
            <ConfigFields type={type} config={config} onChange={setConfig} />
          </div>
          <div className="flex gap-2 mt-4">
            <button className="btn-primary" onClick={() => create.mutate()} disabled={!name || create.isPending}>
              {create.isPending ? 'Saving…' : 'Save'}
            </button>
            <button className="btn-secondary" onClick={() => { setShowCreate(false); setError(''); }}>Cancel</button>
          </div>
        </div>
      )}

      <div className="space-y-3">
        {isLoading && <p className="text-gray-500 text-center py-8">Loading…</p>}
        {!isLoading && !data?.items.length && <p className="text-gray-500 text-center py-8">No integrations yet</p>}
        {data?.items.map((ig) => (
          <div key={ig.id} className="card flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div>
                <p className="font-medium text-white">{ig.name}</p>
                <p className="text-xs text-gray-500">{TYPE_LABELS[ig.type] ?? ig.type}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {testResults[ig.id] && (
                <span className={`text-xs ${testResults[ig.id].ok ? 'text-green-400' : 'text-red-400'}`}>
                  {testResults[ig.id].ok ? '✓ OK' : `✗ ${testResults[ig.id].error ?? testResults[ig.id].status}`}
                </span>
              )}
              <button className="p-1.5 rounded hover:bg-gray-700 text-indigo-400" title="Test" onClick={() => test(ig.id)}>
                <TestTube2 size={16} />
              </button>
              <button
                className="p-1.5 rounded hover:bg-gray-700"
                title={ig.enabled ? 'Disable' : 'Enable'}
                onClick={() => toggle.mutate({ id: ig.id, enabled: !ig.enabled })}
              >
                {ig.enabled
                  ? <ToggleRight size={18} className="text-green-400" />
                  : <ToggleLeft size={18} className="text-gray-500" />}
              </button>
              <button
                className="p-1.5 rounded hover:bg-gray-700 text-red-400"
                title="Delete"
                onClick={() => { if (confirm('Delete this integration?')) remove.mutate(ig.id); }}
              >
                <Trash2 size={16} />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
