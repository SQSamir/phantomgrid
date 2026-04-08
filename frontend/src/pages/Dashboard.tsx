import { ReactNode, useEffect, useMemo, useState } from 'react'
import { apiGet } from '../api/client'

type Overview = {
  active_decoys: number
  events_today: number
  active_alerts: number
  attackers_tracked: number
}

type TopAttacker = {
  source_ip: string
  event_count: number
  last_seen?: string
}

type ProtocolItem = { protocol: string; count: number }
type GeoItem = { country: string; count: number }

export default function Dashboard() {
  const [overview, setOverview] = useState<Overview | null>(null)
  const [topAttackers, setTopAttackers] = useState<TopAttacker[]>([])
  const [protocols, setProtocols] = useState<ProtocolItem[]>([])
  const [geo, setGeo] = useState<GeoItem[]>([])
  const [error, setError] = useState<string | null>(null)

  const tenantId = useMemo(() => new URLSearchParams(window.location.search).get('tenant_id') || '', [])

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const q = tenantId ? `?tenant_id=${encodeURIComponent(tenantId)}` : ''
        const [ov, ta, pb, gg] = await Promise.all([
          apiGet(`/analytics/overview${q}`),
          apiGet(`/analytics/top-attackers${q}${q ? '&' : '?'}limit=5`),
          apiGet(`/analytics/protocol-breakdown${q}`),
          apiGet(`/analytics/geographic${q}`),
        ])

        if (cancelled) return
        setOverview(ov)
        setTopAttackers(ta?.items || [])
        setProtocols(pb?.items || [])
        setGeo(gg?.items || [])
        setError(null)
      } catch (e) {
        if (cancelled) return
        setError((e as Error).message)
      }
    }

    load()
    const timer = setInterval(load, 10000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [tenantId])

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <h1 style={{ margin: 0 }}>Dashboard</h1>
      {error && <div style={{ color: '#ff8c8c' }}>Data fetch error: {error}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(120px, 1fr))', gap: 12 }}>
        <Kpi label='Active Decoys' value={overview?.active_decoys ?? 0} />
        <Kpi label='Events Today' value={overview?.events_today ?? 0} />
        <Kpi label='Active Alerts' value={overview?.active_alerts ?? 0} />
        <Kpi label='Attackers Tracked' value={overview?.attackers_tracked ?? 0} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 1fr', gap: 12 }}>
        <Panel title='Top Attackers'>
          <table style={{ width: '100%', fontSize: 13 }}>
            <thead>
              <tr><th align='left'>IP</th><th align='right'>Events</th><th align='left'>Last Seen</th></tr>
            </thead>
            <tbody>
              {topAttackers.map((a) => (
                <tr key={a.source_ip}>
                  <td>{a.source_ip}</td>
                  <td align='right'>{a.event_count}</td>
                  <td>{a.last_seen ? new Date(a.last_seen).toLocaleString() : '-'}</td>
                </tr>
              ))}
              {topAttackers.length === 0 && <tr><td colSpan={3}>No data</td></tr>}
            </tbody>
          </table>
        </Panel>

        <Panel title='Protocol Breakdown'>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {protocols.slice(0, 8).map((p) => <li key={p.protocol}>{p.protocol}: {p.count}</li>)}
            {protocols.length === 0 && <li>No data</li>}
          </ul>
        </Panel>

        <Panel title='Geographic'>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {geo.slice(0, 8).map((g) => <li key={g.country}>{g.country}: {g.count}</li>)}
            {geo.length === 0 && <li>No data</li>}
          </ul>
        </Panel>
      </div>
    </div>
  )
}

function Kpi({ label, value }: { label: string; value: number }) {
  return (
    <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: 10, padding: 12 }}>
      <div style={{ fontSize: 12, opacity: 0.8 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700 }}>{value}</div>
    </div>
  )
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: 10, padding: 12 }}>
      <h3 style={{ marginTop: 0 }}>{title}</h3>
      {children}
    </section>
  )
}
