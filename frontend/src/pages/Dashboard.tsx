import { useQuery } from '@tanstack/react-query';
import { Shield, Zap, Bell, Users } from 'lucide-react';
import { apiGet } from '../api/client';

interface Overview {
  active_decoys: number;
  events_today: number;
  open_alerts: number;
  unique_attackers_24h: number;
}

interface TimelinePoint { hour: string; count: number }
interface ProtocolPoint { protocol: string; count: number }
interface SeverityPoint { severity: string; count: number }

function StatCard({ icon: Icon, label, value, color }: {
  icon: React.ElementType; label: string; value: number | string; color: string;
}) {
  return (
    <div className="card flex items-center gap-4">
      <div className={`p-3 rounded-lg ${color}`}>
        <Icon size={20} />
      </div>
      <div>
        <p className="text-gray-400 text-xs">{label}</p>
        <p className="text-2xl font-bold text-white">{value}</p>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { data: overview } = useQuery<Overview>({
    queryKey: ['overview'],
    queryFn: () => apiGet('/api/analytics/overview'),
    refetchInterval: 30_000,
  });
  const { data: protocol } = useQuery<ProtocolPoint[]>({
    queryKey: ['by-protocol'],
    queryFn: () => apiGet('/api/analytics/events/by-protocol'),
    refetchInterval: 60_000,
  });
  const { data: severity } = useQuery<SeverityPoint[]>({
    queryKey: ['by-severity'],
    queryFn: () => apiGet('/api/analytics/events/by-severity'),
    refetchInterval: 60_000,
  });

  const maxProto = Math.max(1, ...(protocol?.map((p) => p.count) ?? [1]));
  const maxSev = Math.max(1, ...(severity?.map((s) => s.count) ?? [1]));

  const sevColor: Record<string, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-green-500',
    info: 'bg-blue-500',
  };

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-white">Dashboard</h1>

      {/* Stat cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard icon={Shield} label="Active Decoys" value={overview?.active_decoys ?? '—'} color="bg-indigo-900/50 text-indigo-300" />
        <StatCard icon={Zap} label="Events (24h)" value={overview?.events_today ?? '—'} color="bg-yellow-900/50 text-yellow-300" />
        <StatCard icon={Bell} label="Open Alerts" value={overview?.open_alerts ?? '—'} color="bg-red-900/50 text-red-300" />
        <StatCard icon={Users} label="Unique Attackers (24h)" value={overview?.unique_attackers_24h ?? '—'} color="bg-purple-900/50 text-purple-300" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        {/* Events by protocol */}
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Events by Protocol (24h)</h2>
          {protocol?.length ? (
            <div className="space-y-2">
              {protocol.slice(0, 10).map((p) => (
                <div key={p.protocol} className="flex items-center gap-3">
                  <span className="text-xs text-gray-400 w-28 truncate">{p.protocol}</span>
                  <div className="flex-1 bg-gray-800 rounded-full h-2 overflow-hidden">
                    <div
                      className="bg-indigo-500 h-2 rounded-full"
                      style={{ width: `${(p.count / maxProto) * 100}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-400 w-10 text-right">{p.count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-600 text-sm text-center py-8">No events yet</p>
          )}
        </div>

        {/* Events by severity */}
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Events by Severity (24h)</h2>
          {severity?.length ? (
            <div className="space-y-2">
              {severity.map((s) => (
                <div key={s.severity} className="flex items-center gap-3">
                  <span className="text-xs text-gray-400 w-20 capitalize">{s.severity}</span>
                  <div className="flex-1 bg-gray-800 rounded-full h-2 overflow-hidden">
                    <div
                      className={`${sevColor[s.severity] ?? 'bg-gray-500'} h-2 rounded-full`}
                      style={{ width: `${(s.count / maxSev) * 100}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-400 w-10 text-right">{s.count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-600 text-sm text-center py-8">No events yet</p>
          )}
        </div>
      </div>
    </div>
  );
}
