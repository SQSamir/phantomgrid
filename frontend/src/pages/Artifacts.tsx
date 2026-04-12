import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Trash2, Copy, Download, CheckCheck, Zap } from 'lucide-react';
import { apiGet, apiPost, apiDelete } from '../api/client';

interface Artifact {
  id: string; name: string; type: string; subtype: string;
  description: string | null; content: Record<string, any>;
  status: string; trigger_count: number;
  last_triggered_at: string | null; created_at: string;
}

const TYPE_META: Record<string, { label: string; color: string; desc: string }> = {
  lure:        { label: 'Lure',        color: 'text-blue-400 bg-blue-900/30',    desc: 'Fake login page or exposed service to attract attackers' },
  bait:        { label: 'Bait',        color: 'text-yellow-400 bg-yellow-900/30', desc: 'Fake credentials or tokens planted to be stolen' },
  breadcrumb:  { label: 'Breadcrumb',  color: 'text-purple-400 bg-purple-900/30', desc: 'Fake logs or config files that guide attackers deeper' },
  honeytoken:  { label: 'Honeytoken',  color: 'text-red-400 bg-red-900/30',       desc: 'URL or token that fires an alert when touched' },
};

const SUBTYPES: Record<string, { value: string; label: string }[]> = {
  lure:       [{ value: 'login_page', label: 'Login Page (VPN / Admin)' }, { value: 'exposed_api', label: 'Exposed API Endpoint' }],
  bait:       [
    { value: 'aws_key',         label: 'AWS Access Key' },
    { value: 'api_token',       label: 'API Token (GitHub-style)' },
    { value: 'jwt_token',       label: 'JWT Token' },
    { value: 'ssh_key',         label: 'SSH Private Key' },
    { value: 'db_credentials',  label: 'Database Credentials' },
  ],
  breadcrumb: [
    { value: 'bash_history',  label: '.bash_history' },
    { value: 'env_file',      label: '.env File' },
    { value: 'config_file',   label: 'Config File (database.yml)' },
    { value: 'network_map',   label: 'Network Map' },
  ],
  honeytoken: [{ value: 'url_token', label: 'URL Token' }, { value: 'dns_token', label: 'DNS Token' }],
};

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button onClick={copy} className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-white transition-colors" title="Copy">
      {copied ? <CheckCheck size={13} className="text-green-400" /> : <Copy size={13} />}
    </button>
  );
}

function DownloadBtn({ content, filename }: { content: string; filename: string }) {
  const download = () => {
    const blob = new Blob([content], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <button onClick={download} className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-white transition-colors" title="Download">
      <Download size={13} />
    </button>
  );
}

function ContentCard({ artifact }: { artifact: Artifact }) {
  const c = artifact.content;
  const { subtype } = artifact;

  if (subtype === 'aws_key') return (
    <div className="font-mono text-xs space-y-1">
      <Row label="Access Key ID"     value={c.access_key_id} />
      <Row label="Secret Access Key" value={c.secret_access_key} secret />
      <Row label="Region"            value={c.region} />
      <p className="text-gray-500 mt-1">{c.note}</p>
    </div>
  );
  if (subtype === 'api_token') return (
    <div className="font-mono text-xs space-y-1">
      <Row label="Token"   value={c.token} secret />
      <Row label="Service" value={c.service} />
      <p className="text-gray-500 mt-1">{c.note}</p>
    </div>
  );
  if (subtype === 'jwt_token') return (
    <div className="font-mono text-xs space-y-1">
      <Row label="JWT" value={c.token} secret />
      <p className="text-gray-500 mt-1">{c.note}</p>
    </div>
  );
  if (subtype === 'ssh_key') return (
    <div className="text-xs space-y-1">
      <div className="flex items-start gap-1">
        <span className="text-gray-500 w-20 flex-shrink-0">Private Key</span>
        <span className="text-gray-300 font-mono break-all">{c.private_key?.slice(0, 60)}…</span>
        <CopyBtn text={c.private_key ?? ''} />
      </div>
      <p className="text-gray-500">{c.note}</p>
    </div>
  );
  if (subtype === 'db_credentials') return (
    <div className="font-mono text-xs space-y-1">
      <Row label="DSN"      value={c.dsn} secret />
      <Row label="Host"     value={c.host} />
      <Row label="User"     value={c.username} />
      <Row label="Password" value={c.password} secret />
      <p className="text-gray-500 mt-1">{c.note}</p>
    </div>
  );
  if (['bash_history','env_file','config_file','network_map'].includes(subtype)) return (
    <div className="text-xs space-y-1">
      <div className="flex items-center gap-2">
        <span className="font-mono text-gray-400">{c.filename}</span>
        <CopyBtn text={c.content ?? ''} />
        <DownloadBtn content={c.content ?? ''} filename={c.filename ?? 'artifact.txt'} />
      </div>
      <pre className="bg-gray-900 rounded p-2 text-gray-300 overflow-x-auto max-h-28 font-mono text-[11px]">
        {c.content}
      </pre>
      <p className="text-gray-500">{c.note}</p>
    </div>
  );
  if (['url_token','exposed_api','login_page'].includes(subtype)) return (
    <div className="font-mono text-xs space-y-1">
      <Row label="Trigger URL" value={c.trigger_url} />
      {c.fake_path && <Row label="Fake Path" value={c.fake_path} />}
      <p className="text-gray-500 mt-1">{c.note}</p>
    </div>
  );
  if (subtype === 'dns_token') return (
    <div className="font-mono text-xs space-y-1">
      <Row label="Hostname" value={c.hostname} />
      <p className="text-gray-500 mt-1">{c.note}</p>
    </div>
  );
  return <pre className="text-xs text-gray-400 font-mono">{JSON.stringify(c, null, 2)}</pre>;
}

function Row({ label, value, secret }: { label: string; value?: string; secret?: boolean }) {
  const [show, setShow] = useState(false);
  const display = secret && !show ? '•'.repeat(Math.min(value?.length ?? 12, 24)) : value;
  return (
    <div className="flex items-center gap-1">
      <span className="text-gray-500 w-28 flex-shrink-0">{label}</span>
      <span className="text-gray-300 font-mono truncate max-w-xs">{display}</span>
      {secret && (
        <button onClick={() => setShow(!show)} className="text-xs text-indigo-400 hover:text-indigo-200 ml-1">
          {show ? 'hide' : 'show'}
        </button>
      )}
      {value && <CopyBtn text={value} />}
    </div>
  );
}

export default function Artifacts() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate]   = useState(false);
  const [name, setName]               = useState('');
  const [type, setType]               = useState<keyof typeof SUBTYPES>('honeytoken');
  const [subtype, setSubtype]         = useState('url_token');
  const [description, setDescription] = useState('');
  const [error, setError]             = useState('');
  const [expanded, setExpanded]       = useState<string | null>(null);

  const { data, isLoading } = useQuery<{ total: number; items: Artifact[] }>({
    queryKey: ['artifacts'],
    queryFn: () => apiGet('/api/artifacts?limit=200'),
    refetchInterval: 30_000,
  });
  const artifacts = data?.items ?? [];

  const create = useMutation({
    mutationFn: () => apiPost('/api/artifacts', { name, type, subtype, description: description || undefined }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['artifacts'] });
      setShowCreate(false); setName(''); setDescription(''); setError('');
    },
    onError: (e: any) => setError(e.message),
  });

  const remove = useMutation({
    mutationFn: (id: string) => apiDelete(`/api/artifacts/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['artifacts'] }),
  });

  const handleTypeChange = (t: string) => {
    setType(t as keyof typeof SUBTYPES);
    setSubtype(SUBTYPES[t]?.[0]?.value ?? '');
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Deception Artifacts</h1>
          <p className="text-xs text-gray-500 mt-0.5">Plant lures, bait credentials, breadcrumbs, and honeytokens across your environment</p>
        </div>
        <button className="btn-primary flex items-center gap-2" onClick={() => setShowCreate(true)}>
          <Plus size={16} /> New Artifact
        </button>
      </div>

      {/* Type legend */}
      <div className="grid grid-cols-4 gap-3">
        {Object.entries(TYPE_META).map(([t, m]) => (
          <div key={t} className="card py-3">
            <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${m.color}`}>{m.label}</span>
            <p className="text-xs text-gray-500 mt-1.5">{m.desc}</p>
          </div>
        ))}
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="card border-indigo-800">
          <h3 className="font-semibold mb-4">Create Artifact</h3>
          {error && <p className="text-red-400 text-sm mb-3">{error}</p>}
          <div className="grid grid-cols-4 gap-3">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Name</label>
              <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Finance AWS Key" />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Type</label>
              <select className="input" value={type} onChange={(e) => handleTypeChange(e.target.value)}>
                {Object.entries(TYPE_META).map(([v, m]) => (
                  <option key={v} value={v}>{m.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Subtype</label>
              <select className="input" value={subtype} onChange={(e) => setSubtype(e.target.value)}>
                {(SUBTYPES[type] ?? []).map((s) => (
                  <option key={s.value} value={s.value}>{s.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Description (optional)</label>
              <input className="input" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Where will you plant it?" />
            </div>
          </div>
          <div className="flex gap-2 mt-4">
            <button className="btn-primary" onClick={() => create.mutate()} disabled={!name || create.isPending}>
              {create.isPending ? 'Generating…' : 'Generate & Create'}
            </button>
            <button className="btn-secondary" onClick={() => { setShowCreate(false); setError(''); }}>Cancel</button>
          </div>
        </div>
      )}

      {/* Artifact list */}
      <div className="space-y-2">
        {isLoading && <div className="card text-center text-gray-500 py-8">Loading…</div>}
        {!isLoading && !artifacts.length && (
          <div className="card text-center text-gray-500 py-8">
            No artifacts yet — plant your first lure, bait, or honeytoken above.
          </div>
        )}
        {artifacts.map((a) => {
          const meta = TYPE_META[a.type];
          const isExpanded = expanded === a.id;
          return (
            <div key={a.id} className="card">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3 min-w-0">
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded-full flex-shrink-0 ${meta?.color ?? 'text-gray-400'}`}>
                    {meta?.label ?? a.type}
                  </span>
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-white truncate">{a.name}</p>
                    <p className="text-xs text-gray-500">{a.subtype.replace(/_/g, ' ')} {a.description ? `· ${a.description}` : ''}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0 ml-4">
                  {a.trigger_count > 0 && (
                    <div className="flex items-center gap-1 text-red-400 text-xs font-semibold">
                      <Zap size={12} />
                      <span>{a.trigger_count}× triggered</span>
                      {a.last_triggered_at && (
                        <span className="text-gray-500 font-normal ml-1">
                          {new Date(a.last_triggered_at).toLocaleString()}
                        </span>
                      )}
                    </div>
                  )}
                  <button
                    onClick={() => setExpanded(isExpanded ? null : a.id)}
                    className="text-xs text-indigo-400 hover:text-indigo-200"
                  >
                    {isExpanded ? 'Hide' : 'View'}
                  </button>
                  <button
                    onClick={() => { if (confirm('Delete this artifact?')) remove.mutate(a.id); }}
                    className="p-1.5 rounded hover:bg-gray-700 text-red-400"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
              {isExpanded && (
                <div className="mt-3 pt-3 border-t border-gray-800">
                  <ContentCard artifact={a} />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
