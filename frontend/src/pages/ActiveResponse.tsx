import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { formatDistanceToNow } from 'date-fns';
import {
  Shield, ShieldOff, Clock, Zap, BookOpen, Trash2,
  CheckCircle, XCircle, Play, AlertTriangle, Activity,
} from 'lucide-react';
import { apiGet, apiFetch } from '../api/client';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface BlockedIP {
  ip: string;
  ts: string;
  reason: string;
  tenant_id: string;
  firewall_type: string;
}

interface TarpittedIP {
  ip: string;
  expires_in_seconds: number;
}

interface PlaybookAction {
  action: string;
  success: boolean;
  error?: string;
  ok?: boolean;
}

interface PlaybookExecution {
  id: string;
  alert_id: string;
  tenant_id: string;
  playbook: string;
  source_ip: string;
  actions: PlaybookAction[];
  executed_at: string;
}

interface Playbook {
  actions: string[];
  action_count: number;
}

// ---------------------------------------------------------------------------
// Action display name map
// ---------------------------------------------------------------------------

const ACTION_LABELS: Record<string, { label: string; color: string }> = {
  block_ip_firewall:     { label: 'Block IP (Firewall)',       color: 'text-red-400' },
  tarpit_connection:     { label: 'Tarpit Connection',         color: 'text-orange-400' },
  create_alert_record:   { label: 'Create Alert',              color: 'text-yellow-400' },
  notify_channels:       { label: 'Notify Channels',           color: 'text-blue-400' },
  create_ticket:         { label: 'Create Ticket',             color: 'text-purple-400' },
  export_ioc_to_siem:    { label: 'Export IOC to SIEM',        color: 'text-teal-400' },
  trigger_soar_playbook: { label: 'Trigger SOAR',              color: 'text-indigo-400' },
  inject_fake_credentials:{ label: 'Inject Fake Credentials',  color: 'text-green-400' },
  quarantine_source_host:{ label: 'Quarantine Host',           color: 'text-red-300' },
  trace_access_path:     { label: 'Trace Access Path',         color: 'text-cyan-400' },
};

const PLAYBOOK_LABELS: Record<string, string> = {
  ssh_brute_force:      'SSH Brute Force',
  lateral_movement:     'Lateral Movement',
  ntlm_hash_captured:   'NTLM Hash Captured',
  critical_system_accessed: 'Critical System Access',
  aws_metadata_ssrf:    'AWS Metadata SSRF',
  honeytoken_triggered: 'Honeytoken Triggered',
  ot_ics_attack:        'OT/ICS Attack',
  container_escape:     'Container Escape',
  credential_spray:     'Credential Spray',
};

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

function StatusBadge({ success }: { success: boolean }) {
  return success
    ? <CheckCircle size={12} className="text-green-400" />
    : <XCircle size={12} className="text-red-400" />;
}

function PlaybookCard({ name, pb }: { name: string; pb: Playbook }) {
  return (
    <div className="card">
      <div className="flex items-center justify-between mb-2">
        <p className="text-sm font-semibold text-white">
          {PLAYBOOK_LABELS[name] ?? name}
        </p>
        <span className="text-xs text-gray-500">{pb.action_count} actions</span>
      </div>
      <div className="flex flex-wrap gap-1">
        {pb.actions.map(a => {
          const meta = ACTION_LABELS[a] ?? { label: a, color: 'text-gray-400' };
          return (
            <span key={a} className={`text-[10px] px-1.5 py-0.5 rounded bg-gray-800 ${meta.color}`}>
              {meta.label}
            </span>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function ActiveResponse() {
  const qc = useQueryClient();
  const [tab, setTab] = useState<'log' | 'blocked' | 'tarpit' | 'playbooks'>('log');

  const { data: healthData } = useQuery<{ status: string; tarpitted: number; blocked: number }>({
    queryKey: ['ar-health'],
    queryFn: () => apiGet('/api/active-response/blocked-ips').then(() =>
      apiFetch('/api/active-response/is-tarpitted/0.0.0.0').then(() =>
        apiGet('/health').catch(() => ({ status: 'ok', tarpitted: 0, blocked: 0 }))
      )
    ).catch(() => ({ status: 'ok', tarpitted: 0, blocked: 0 })),
    refetchInterval: 15_000,
  });

  const { data: blockedData, refetch: refetchBlocked } = useQuery<{ total: number; items: BlockedIP[] }>({
    queryKey: ['ar-blocked'],
    queryFn: () => apiGet('/api/active-response/blocked-ips?limit=100'),
    enabled: tab === 'blocked',
    refetchInterval: 30_000,
  });

  const { data: tarpitData } = useQuery<{ total: number; items: TarpittedIP[] }>({
    queryKey: ['ar-tarpit'],
    queryFn: () => apiGet('/api/active-response/tarpitted'),
    enabled: tab === 'tarpit',
    refetchInterval: 15_000,
  });

  const { data: logData } = useQuery<{ total: number; items: PlaybookExecution[] }>({
    queryKey: ['ar-log'],
    queryFn: () => apiGet('/api/active-response/playbook-log?limit=50'),
    enabled: tab === 'log',
    refetchInterval: 15_000,
  });

  const { data: playbooksData } = useQuery<{ playbooks: Record<string, Playbook> }>({
    queryKey: ['ar-playbooks'],
    queryFn: () => apiGet('/api/active-response/playbooks'),
    enabled: tab === 'playbooks',
  });

  const unblock = async (ip: string) => {
    if (!confirm(`Unblock ${ip}?`)) return;
    await apiFetch(`/api/active-response/blocked-ips/${ip}`, { method: 'DELETE' });
    qc.invalidateQueries({ queryKey: ['ar-blocked'] });
  };

  const tabs = [
    { id: 'log',       label: 'Execution Log', icon: Activity },
    { id: 'blocked',   label: 'Blocked IPs',   icon: ShieldOff },
    { id: 'tarpit',    label: 'Tarpitted',      icon: Clock },
    { id: 'playbooks', label: 'Playbooks',      icon: BookOpen },
  ] as const;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Active Response</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Auto-block · Tarpit · Ticket · SOAR — the feature SecurityHive lacks
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 rounded-lg">
            <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            <span className="text-xs text-gray-300">Engine Active</span>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Blocked IPs',     value: blockedData?.total ?? '—', icon: Shield,  color: 'text-red-400' },
          { label: 'Tarpitted',        value: tarpitData?.total  ?? '—', icon: Clock,   color: 'text-orange-400' },
          { label: 'Playbooks Run',    value: logData?.total     ?? '—', icon: Zap,     color: 'text-indigo-400' },
          { label: 'Playbook Types',   value: Object.keys(playbooksData?.playbooks ?? {}).length || 9, icon: BookOpen, color: 'text-teal-400' },
        ].map(s => {
          const Icon = s.icon;
          return (
            <div key={s.label} className="card py-3 flex items-center gap-3">
              <Icon size={20} className={s.color} />
              <div>
                <p className="text-2xl font-bold text-white">{s.value}</p>
                <p className="text-xs text-gray-500">{s.label}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800 pb-0">
        {tabs.map(t => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-1.5 px-4 py-2 text-sm transition-colors border-b-2 -mb-px ${
                tab === t.id
                  ? 'border-indigo-500 text-indigo-300'
                  : 'border-transparent text-gray-500 hover:text-gray-300'
              }`}
            >
              <Icon size={14} />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Execution Log */}
      {tab === 'log' && (
        <div className="space-y-2">
          {!logData?.items.length && (
            <div className="card text-center text-gray-500 py-8">
              No playbook executions yet — triggers when high/critical alerts fire
            </div>
          )}
          {logData?.items.map(exec => {
            const successCount = exec.actions.filter(a => a.success).length;
            const total = exec.actions.length;
            return (
              <div key={exec.id} className="card">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Play size={14} className="text-indigo-400" />
                    <span className="text-sm font-semibold text-white">
                      {PLAYBOOK_LABELS[exec.playbook] ?? exec.playbook}
                    </span>
                    <span className="font-mono text-xs text-indigo-300 bg-indigo-900/30 px-1.5 py-0.5 rounded">
                      {exec.source_ip}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-medium ${
                      successCount === total ? 'text-green-400' : 'text-yellow-400'
                    }`}>
                      {successCount}/{total} actions ok
                    </span>
                    <span className="text-xs text-gray-600">
                      {formatDistanceToNow(new Date(exec.executed_at), { addSuffix: true })}
                    </span>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {exec.actions.map((a, i) => {
                    const meta = ACTION_LABELS[a.action] ?? { label: a.action, color: 'text-gray-400' };
                    return (
                      <div key={i} className="flex items-center gap-1 text-[11px] bg-gray-800/80 px-1.5 py-0.5 rounded">
                        <StatusBadge success={a.success} />
                        <span className={meta.color}>{meta.label}</span>
                        {a.error && <span className="text-red-400 ml-1">({a.error.slice(0, 40)})</span>}
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Blocked IPs */}
      {tab === 'blocked' && (
        <div className="space-y-2">
          {!blockedData?.items.length && (
            <div className="card text-center text-gray-500 py-8">No blocked IPs</div>
          )}
          {blockedData?.items.map(b => (
            <div key={b.ip} className="card flex items-center justify-between">
              <div className="flex items-center gap-3">
                <ShieldOff size={16} className="text-red-400" />
                <div>
                  <p className="font-mono text-sm text-white">{b.ip}</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {b.reason}
                    <span className="ml-2 text-gray-600">· {b.firewall_type}</span>
                    <span className="ml-2 text-gray-600">
                      · {formatDistanceToNow(new Date(b.ts), { addSuffix: true })}
                    </span>
                  </p>
                </div>
              </div>
              <button
                onClick={() => unblock(b.ip)}
                className="flex items-center gap-1 text-xs text-gray-400 hover:text-red-400 transition-colors px-2 py-1 rounded hover:bg-gray-800"
              >
                <Trash2 size={12} /> Unblock
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Tarpitted */}
      {tab === 'tarpit' && (
        <div className="space-y-2">
          {!tarpitData?.items.length && (
            <div className="card text-center text-gray-500 py-8">
              No tarpitted IPs — connections throttled to 1 byte/sec when triggered
            </div>
          )}
          {tarpitData?.items.map(t => (
            <div key={t.ip} className="card flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Clock size={16} className="text-orange-400" />
                <div>
                  <p className="font-mono text-sm text-white">{t.ip}</p>
                  <p className="text-xs text-gray-500">
                    Expires in {Math.floor(t.expires_in_seconds / 60)}m {t.expires_in_seconds % 60}s
                    · Rate: 1 byte/sec
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-24 bg-gray-800 rounded-full h-1.5">
                  <div
                    className="bg-orange-500 h-1.5 rounded-full transition-all"
                    style={{ width: `${Math.min(100, (t.expires_in_seconds / 3600) * 100)}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Playbooks */}
      {tab === 'playbooks' && (
        <div className="space-y-2">
          <div className="card bg-indigo-900/20 border border-indigo-800 mb-4">
            <div className="flex items-start gap-2">
              <AlertTriangle size={16} className="text-indigo-400 mt-0.5 flex-shrink-0" />
              <p className="text-xs text-indigo-300">
                Playbooks execute automatically when high/critical alerts fire.
                Each action is idempotent and logged to the execution log.
                Configure external targets (firewall, SOAR, ticketing) via environment variables.
              </p>
            </div>
          </div>
          {Object.entries(playbooksData?.playbooks ?? {}).map(([name, pb]) => (
            <PlaybookCard key={name} name={name} pb={pb} />
          ))}
          {!playbooksData && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {Object.entries(PLAYBOOK_LABELS).map(([id, label]) => (
                <div key={id} className="card">
                  <p className="text-sm font-semibold text-white">{label}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
