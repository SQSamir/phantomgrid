import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ExternalLink } from 'lucide-react';
import { apiGet } from '../api/client';

interface Technique {
  id: string; name: string; tactic: string; url: string; count?: number;
}
interface TechniqueDetail extends Technique {
  triggered_by: { protocol: string; event_type: string }[];
}
interface Coverage {
  total: number;
  mappings: { protocol: string; event_type: string; techniques: Technique[] }[];
}
interface Stats { hours: number; stats: (Technique & { count: number })[] }

const TACTIC_COLOR: Record<string, string> = {
  'initial-access': 'bg-red-900 text-red-300',
  'execution': 'bg-orange-900 text-orange-300',
  'persistence': 'bg-yellow-900 text-yellow-300',
  'privilege-escalation': 'bg-purple-900 text-purple-300',
  'defense-evasion': 'bg-blue-900 text-blue-300',
  'credential-access': 'bg-pink-900 text-pink-300',
  'discovery': 'bg-cyan-900 text-cyan-300',
  'lateral-movement': 'bg-teal-900 text-teal-300',
  'collection': 'bg-green-900 text-green-300',
  'command-and-control': 'bg-indigo-900 text-indigo-300',
  'exfiltration': 'bg-rose-900 text-rose-300',
  'impact': 'bg-gray-800 text-gray-300',
  'reconnaissance': 'bg-violet-900 text-violet-300',
};

export default function Mitre() {
  const [tab, setTab] = useState<'techniques' | 'coverage' | 'stats'>('techniques');
  const [selected, setSelected] = useState<string | null>(null);

  const { data: techniques } = useQuery<{ total: number; items: Technique[] }>({
    queryKey: ['mitre-techniques'],
    queryFn: () => apiGet('/api/mitre/techniques'),
  });

  const { data: detail } = useQuery<TechniqueDetail>({
    queryKey: ['mitre-detail', selected],
    queryFn: () => apiGet(`/api/mitre/techniques/${selected}`),
    enabled: !!selected,
  });

  const { data: stats } = useQuery<Stats>({
    queryKey: ['mitre-stats'],
    queryFn: () => apiGet('/api/mitre/stats?hours=168'),
    enabled: tab === 'stats',
  });

  const { data: coverage } = useQuery<Coverage>({
    queryKey: ['mitre-coverage'],
    queryFn: () => apiGet('/api/mitre/coverage'),
    enabled: tab === 'coverage',
  });

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-white">MITRE ATT&CK</h1>

      <div className="flex gap-1 border-b border-gray-800">
        {(['techniques', 'coverage', 'stats'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm capitalize transition-colors ${
              tab === t ? 'border-b-2 border-indigo-400 text-indigo-300' : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === 'techniques' && (
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="xl:col-span-2 card p-0 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase">
                  <th className="px-4 py-3 text-left">ID</th>
                  <th className="px-4 py-3 text-left">Name</th>
                  <th className="px-4 py-3 text-left">Tactic</th>
                </tr>
              </thead>
              <tbody>
                {techniques?.items.map((t) => (
                  <tr
                    key={t.id}
                    className={`table-row cursor-pointer ${selected === t.id ? 'bg-indigo-900/20' : ''}`}
                    onClick={() => setSelected(t.id === selected ? null : t.id)}
                  >
                    <td className="px-4 py-2.5 font-mono text-indigo-300 text-xs">{t.id}</td>
                    <td className="px-4 py-2.5 text-gray-200">{t.name}</td>
                    <td className="px-4 py-2.5">
                      <span className={`text-xs px-2 py-0.5 rounded-full ${TACTIC_COLOR[t.tactic] ?? 'bg-gray-800 text-gray-300'}`}>
                        {t.tactic}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {selected && detail && (
            <div className="card space-y-3">
              <div className="flex items-start justify-between">
                <div>
                  <p className="font-mono text-indigo-300 text-sm">{detail.id}</p>
                  <h3 className="font-semibold text-white">{detail.name}</h3>
                  <span className={`text-xs px-2 py-0.5 rounded-full mt-1 inline-block ${TACTIC_COLOR[detail.tactic] ?? 'bg-gray-800 text-gray-300'}`}>
                    {detail.tactic}
                  </span>
                </div>
                <a href={detail.url} target="_blank" rel="noreferrer" className="text-gray-500 hover:text-gray-300">
                  <ExternalLink size={14} />
                </a>
              </div>
              <div>
                <p className="text-xs text-gray-500 mb-2">Triggered by</p>
                {detail.triggered_by.map((tb, i) => (
                  <div key={i} className="text-xs text-gray-400 font-mono">
                    {tb.protocol} / {tb.event_type}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'coverage' && (
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase">
                <th className="px-4 py-3 text-left">Protocol</th>
                <th className="px-4 py-3 text-left">Event Type</th>
                <th className="px-4 py-3 text-left">Techniques</th>
              </tr>
            </thead>
            <tbody>
              {coverage?.mappings.map((m, i) => (
                <tr key={i} className="table-row">
                  <td className="px-4 py-2.5 text-indigo-300">{m.protocol}</td>
                  <td className="px-4 py-2.5 text-gray-300">{m.event_type}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {m.techniques.map((t) => (
                        <span key={t.id} className="font-mono text-xs bg-gray-800 text-gray-300 px-1.5 py-0.5 rounded">
                          {t.id}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'stats' && (
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Top Techniques (last 7 days)</h2>
          {stats?.stats.length ? (
            <div className="space-y-2">
              {stats.stats.map((t) => {
                const max = stats.stats[0]?.count ?? 1;
                return (
                  <div key={t.id} className="flex items-center gap-3">
                    <span className="font-mono text-xs text-indigo-300 w-24">{t.id}</span>
                    <span className="text-xs text-gray-400 flex-1 truncate">{t.name}</span>
                    <div className="w-32 bg-gray-800 rounded-full h-2 overflow-hidden">
                      <div className="bg-indigo-500 h-2 rounded-full" style={{ width: `${(t.count / max) * 100}%` }} />
                    </div>
                    <span className="text-xs text-gray-400 w-8 text-right">{t.count}</span>
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="text-gray-600 text-sm text-center py-8">No technique data yet</p>
          )}
        </div>
      )}
    </div>
  );
}
