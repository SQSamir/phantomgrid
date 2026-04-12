import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Plus, Trash2, TestTube2, ToggleLeft, ToggleRight,
  Zap, MessageSquare, Mail, Bell, Database, Cloud,
  Server, Shield, Ticket, BookOpen,
} from 'lucide-react';
import { apiGet, apiPost, apiPatch, apiDelete, apiFetch } from '../api/client';

interface Integration {
  id: string; name: string; type: string; config: Record<string, any>;
  enabled: boolean; last_triggered_at: string | null; created_at: string;
}
interface IntegrationsResponse { total: number; items: Integration[] }
interface IntegType { id: string; name: string; category: string }

// ---------------------------------------------------------------------------
// Type metadata
// ---------------------------------------------------------------------------

const TYPE_META: Record<string, { label: string; icon: any; color: string; category: string }> = {
  webhook:     { label: 'Webhook',             icon: Zap,          color: 'text-yellow-400',  category: 'Notification' },
  slack:       { label: 'Slack',               icon: MessageSquare,color: 'text-green-400',   category: 'Notification' },
  email:       { label: 'Email',               icon: Mail,         color: 'text-blue-400',    category: 'Notification' },
  pagerduty:   { label: 'PagerDuty',           icon: Bell,         color: 'text-red-400',     category: 'Notification' },
  splunk:      { label: 'Splunk HEC',          icon: Database,     color: 'text-orange-400',  category: 'SIEM' },
  elastic:     { label: 'Elastic Security',    icon: Database,     color: 'text-yellow-300',  category: 'SIEM' },
  sentinel:    { label: 'Microsoft Sentinel',  icon: Cloud,        color: 'text-blue-300',    category: 'SIEM' },
  qradar:      { label: 'IBM QRadar',          icon: Server,       color: 'text-purple-400',  category: 'SIEM' },
  crowdstrike: { label: 'CrowdStrike Falcon',  icon: Shield,       color: 'text-red-300',     category: 'EDR' },
  sentinelone: { label: 'SentinelOne',         icon: Shield,       color: 'text-purple-300',  category: 'EDR' },
  jira:        { label: 'Jira',                icon: Ticket,       color: 'text-blue-400',    category: 'Ticketing' },
  servicenow:  { label: 'ServiceNow',          icon: Ticket,       color: 'text-green-300',   category: 'Ticketing' },
  thehive:     { label: 'TheHive',             icon: BookOpen,     color: 'text-teal-400',    category: 'Ticketing' },
};

const CATEGORY_ORDER = ['SIEM', 'Notification', 'EDR', 'Ticketing'];

// ---------------------------------------------------------------------------
// Config field components per type
// ---------------------------------------------------------------------------

function ConfigFields({ type, config, onChange }: {
  type: string;
  config: Record<string, any>;
  onChange: (c: Record<string, any>) => void;
}) {
  const f = (key: string, label: string, placeholder?: string, isPassword = false) => (
    <div key={key}>
      <label className="block text-xs text-gray-400 mb-1">{label}</label>
      <input
        className="input"
        type={isPassword ? 'password' : 'text'}
        value={config[key] ?? ''}
        onChange={(e) => onChange({ ...config, [key]: e.target.value })}
        placeholder={placeholder}
      />
    </div>
  );

  switch (type) {
    case 'webhook':
      return <>{f('url', 'URL', 'https://…')}{f('secret', 'HMAC Secret (optional)', '', true)}</>;
    case 'slack':
      return <>{f('webhook_url', 'Slack Webhook URL', 'https://hooks.slack.com/…')}</>;
    case 'email':
      return (
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
    case 'pagerduty':
      return <>{f('routing_key', 'Routing Key (Events API v2)', '', true)}</>;
    case 'splunk':
      return <>
        {f('hec_url', 'HEC URL', 'https://splunk:8088/services/collector/event')}
        {f('hec_token', 'HEC Token', '', true)}
        {f('index', 'Index (optional)', 'main')}
      </>;
    case 'elastic':
      return <>
        {f('url', 'Elasticsearch URL', 'https://elastic:9200')}
        {f('api_key', 'API Key', '', true)}
        {f('index', 'Index', 'phantomgrid-alerts')}
      </>;
    case 'sentinel':
      return <>
        {f('workspace_id', 'Log Analytics Workspace ID')}
        {f('workspace_key', 'Primary Key', '', true)}
        {f('log_type', 'Log Type', 'PhantomGridAlerts')}
      </>;
    case 'qradar':
      return <>
        {f('syslog_host', 'QRadar Syslog Host', 'qradar.corp.local')}
        {f('syslog_port', 'Syslog Port (UDP)', '514')}
      </>;
    case 'crowdstrike':
      return <>
        {f('client_id', 'Client ID')}
        {f('client_secret', 'Client Secret', '', true)}
        {f('base_url', 'API Base URL', 'https://api.crowdstrike.com')}
      </>;
    case 'sentinelone':
      return <>
        {f('management_url', 'Management URL', 'https://yoursite.sentinelone.net')}
        {f('api_token', 'API Token', '', true)}
      </>;
    case 'jira':
      return <>
        {f('url', 'Jira URL', 'https://yourorg.atlassian.net')}
        {f('api_token', 'API Token', '', true)}
        {f('project_key', 'Project Key', 'SEC')}
        {f('user_email', 'User Email')}
      </>;
    case 'servicenow':
      return <>
        {f('url', 'ServiceNow URL', 'https://yourinstance.service-now.com')}
        {f('user', 'Username')}
        {f('password', 'Password', '', true)}
      </>;
    case 'thehive':
      return <>
        {f('url', 'TheHive URL', 'https://thehive.corp.local')}
        {f('api_key', 'API Key', '', true)}
      </>;
    default:
      return null;
  }
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function Integrations() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName]     = useState('');
  const [type, setType]     = useState('webhook');
  const [config, setConfig] = useState<Record<string, any>>({});
  const [error, setError]   = useState('');
  const [testResults, setTestResults] = useState<Record<string, any>>({});
  const [filterCat, setFilterCat] = useState<string>('all');

  const { data: typesData } = useQuery<{ types: IntegType[] }>({
    queryKey: ['integration-types'],
    queryFn: () => apiGet('/api/integrations/types/available'),
  });

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
      setTestResults(p => ({ ...p, [id]: d }));
    } catch (e: any) {
      setTestResults(p => ({ ...p, [id]: { ok: false, error: e.message } }));
    }
    setTimeout(() => setTestResults(p => { const n = { ...p }; delete n[id]; return n; }), 6000);
  };

  // Group available types
  const availableTypes = typesData?.types ?? Object.entries(TYPE_META).map(([id, m]) => ({
    id, name: m.label, category: m.category,
  }));
  const typesByCategory: Record<string, typeof availableTypes> = {};
  for (const t of availableTypes) {
    (typesByCategory[t.category] ??= []).push(t);
  }

  // Filter integrations by category
  const filteredItems = (data?.items ?? []).filter(ig => {
    if (filterCat === 'all') return true;
    return (TYPE_META[ig.type]?.category ?? 'Other') === filterCat;
  });

  const categories = ['all', ...CATEGORY_ORDER];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Integrations</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            SIEM, notifications, ticketing — push alerts everywhere
          </p>
        </div>
        <button className="btn-primary flex items-center gap-2" onClick={() => setShowCreate(true)}>
          <Plus size={16} /> Add Integration
        </button>
      </div>

      {/* Stats */}
      {data && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Total', value: data.total },
            { label: 'Enabled', value: data.items.filter(i => i.enabled).length },
            { label: 'SIEMs', value: data.items.filter(i => TYPE_META[i.type]?.category === 'SIEM').length },
            { label: 'Ticketing', value: data.items.filter(i => TYPE_META[i.type]?.category === 'Ticketing').length },
          ].map(s => (
            <div key={s.label} className="card py-3">
              <p className="text-2xl font-bold text-white">{s.value}</p>
              <p className="text-xs text-gray-500 mt-0.5">{s.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Category filter */}
      <div className="flex gap-2">
        {categories.map(cat => (
          <button
            key={cat}
            onClick={() => setFilterCat(cat)}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
              filterCat === cat
                ? 'bg-indigo-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:text-gray-200'
            }`}
          >
            {cat === 'all' ? 'All' : cat}
          </button>
        ))}
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="card border border-indigo-800">
          <h3 className="font-semibold mb-4 text-white">New Integration</h3>
          {error && <p className="text-red-400 text-sm mb-3">{error}</p>}
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-gray-400 mb-1">Name</label>
                <input className="input" value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="My Splunk SIEM" />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Type</label>
                <select className="input" value={type}
                  onChange={(e) => { setType(e.target.value); setConfig({}); }}>
                  {CATEGORY_ORDER.map(cat => (
                    typesByCategory[cat]?.length
                      ? <optgroup key={cat} label={cat}>
                          {typesByCategory[cat].map(t => (
                            <option key={t.id} value={t.id}>{t.name}</option>
                          ))}
                        </optgroup>
                      : null
                  ))}
                </select>
              </div>
            </div>
            <ConfigFields type={type} config={config} onChange={setConfig} />
          </div>
          <div className="flex gap-2 mt-4">
            <button className="btn-primary" onClick={() => create.mutate()}
              disabled={!name || create.isPending}>
              {create.isPending ? 'Saving…' : 'Save Integration'}
            </button>
            <button className="btn-secondary"
              onClick={() => { setShowCreate(false); setError(''); }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Integration list */}
      <div className="space-y-2">
        {isLoading && <p className="text-gray-500 text-center py-8">Loading…</p>}
        {!isLoading && !filteredItems.length && (
          <div className="card text-center text-gray-500 py-8">
            {filterCat === 'all'
              ? 'No integrations yet — add your first SIEM or notification channel'
              : `No ${filterCat} integrations configured`}
          </div>
        )}
        {filteredItems.map(ig => {
          const meta = TYPE_META[ig.type] ?? {
            label: ig.type, icon: Zap, color: 'text-gray-400', category: 'Other'
          };
          const Icon = meta.icon;
          return (
            <div key={ig.id} className={`card flex items-center justify-between gap-4 ${!ig.enabled ? 'opacity-60' : ''}`}>
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg bg-gray-800 ${meta.color}`}>
                  <Icon size={16} />
                </div>
                <div>
                  <p className="font-medium text-white text-sm">{ig.name}</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    <span className={`${meta.color} mr-2`}>{meta.label}</span>
                    <span className="text-gray-600">{meta.category}</span>
                    {ig.last_triggered_at && (
                      <span className="ml-2 text-gray-600">
                        · last triggered {new Date(ig.last_triggered_at).toLocaleDateString()}
                      </span>
                    )}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                {testResults[ig.id] && (
                  <span className={`text-xs px-2 py-0.5 rounded ${
                    testResults[ig.id].ok ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'
                  }`}>
                    {testResults[ig.id].ok ? '✓ Connected' : `✗ ${testResults[ig.id].error ?? 'failed'}`}
                  </span>
                )}
                <button
                  className="p-1.5 rounded hover:bg-gray-700 text-indigo-400 transition-colors"
                  title="Test connection"
                  onClick={() => test(ig.id)}
                >
                  <TestTube2 size={15} />
                </button>
                <button
                  className="p-1.5 rounded hover:bg-gray-700 transition-colors"
                  title={ig.enabled ? 'Disable' : 'Enable'}
                  onClick={() => toggle.mutate({ id: ig.id, enabled: !ig.enabled })}
                >
                  {ig.enabled
                    ? <ToggleRight size={18} className="text-green-400" />
                    : <ToggleLeft size={18} className="text-gray-500" />}
                </button>
                <button
                  className="p-1.5 rounded hover:bg-gray-700 text-red-400 transition-colors"
                  title="Delete"
                  onClick={() => { if (confirm('Delete this integration?')) remove.mutate(ig.id); }}
                >
                  <Trash2 size={15} />
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Available integrations catalog */}
      {!showCreate && (
        <div className="mt-6">
          <h2 className="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wide">
            Available Connectors
          </h2>
          {CATEGORY_ORDER.map(cat => (
            typesByCategory[cat]?.length
              ? <div key={cat} className="mb-4">
                  <p className="text-xs text-gray-600 mb-2 uppercase tracking-wider">{cat}</p>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                    {typesByCategory[cat].map(t => {
                      const meta = TYPE_META[t.id] ?? { icon: Zap, color: 'text-gray-400', label: t.name };
                      const Icon = meta.icon;
                      const configured = (data?.items ?? []).some(i => i.type === t.id);
                      return (
                        <button
                          key={t.id}
                          className={`flex items-center gap-2 p-2 rounded-lg border text-left transition-colors ${
                            configured
                              ? 'border-green-800 bg-green-900/10 text-green-300'
                              : 'border-gray-800 hover:border-gray-700 text-gray-400 hover:text-gray-200'
                          }`}
                          onClick={() => { setType(t.id); setConfig({}); setShowCreate(true); }}
                        >
                          <Icon size={14} className={configured ? 'text-green-400' : meta.color} />
                          <span className="text-xs">{t.name}</span>
                          {configured && <span className="ml-auto text-[10px] text-green-500">✓</span>}
                        </button>
                      );
                    })}
                  </div>
                </div>
              : null
          ))}
        </div>
      )}
    </div>
  );
}
