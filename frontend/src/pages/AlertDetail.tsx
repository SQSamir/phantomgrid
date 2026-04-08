import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { apiGet, apiPatch, apiPost } from '../api/client'

type AlertEvent = { id: string; timestamp: string; protocol: string; event_type: string; summary?: string }
type AlertData = {
  id: string
  severity: string
  title: string
  source_ip: string
  source_country?: string
  source_city?: string
  source_asn?: string
  abuse_score?: number
  is_tor?: boolean
  first_seen_at?: string
  last_seen_at?: string
  event_count?: number
  mitre_techniques?: string[]
  events?: AlertEvent[]
  status_history?: { at: string; status: string; by?: string }[]
}

export default function AlertDetail(){
  const { id = '' } = useParams()
  const [alert, setAlert] = useState<AlertData | null>(null)
  const [note, setNote] = useState('')

  useEffect(() => {
    apiGet(`/alerts/${id}`).then(setAlert).catch(() => null)
  }, [id])

  const resolve = async () => {
    await apiPatch(`/alerts/${id}`, { status: 'resolved' })
    const updated = await apiGet(`/alerts/${id}`)
    setAlert(updated)
  }

  const suppress = async (duration: '1h' | '24h' | '7d') => {
    await apiPost(`/alerts/${id}/suppress`, { duration })
  }

  const exportIOCs = async () => {
    const r = await fetch(`/api/v1/alerts/${id}/iocs/stix`)
    const b = await r.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(b)
    a.download = `alert-${id}-iocs.json`
    a.click()
  }

  const saveNote = async () => {
    await apiPost(`/alerts/${id}/notes`, { note })
    setNote('')
  }

  if (!alert) return <div>Loading alert...</div>

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 14 }}>
      <section style={{ background: '#0f172a', padding: 12, border: '1px solid #1f2937', borderRadius: 10 }}>
        <h1 style={{ marginTop: 0 }}>{alert.title}</h1>
        <h3>Attack Chain Timeline</h3>
        <ul>
          {(alert.events || []).map(e => (
            <li key={e.id}><strong>{e.protocol}</strong> • {e.event_type} • {new Date(e.timestamp).toLocaleString()} — {e.summary || ''}</li>
          ))}
        </ul>

        <h3>MITRE Techniques</h3>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {(alert.mitre_techniques || []).map(t => <span key={t} style={{ border: '1px solid #334155', borderRadius: 8, padding: '6px 10px' }}>{t}</span>)}
        </div>

        <h3>Response Actions</h3>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button onClick={resolve}>Resolve</button>
          <button onClick={() => suppress('1h')}>Suppress 1h</button>
          <button onClick={() => suppress('24h')}>Suppress 24h</button>
          <button onClick={() => suppress('7d')}>Suppress 7d</button>
          <button onClick={exportIOCs}>Export IOCs</button>
        </div>

        <h3>Add Analyst Note</h3>
        <textarea rows={6} value={note} onChange={(e) => setNote(e.target.value)} style={{ width: '100%' }} placeholder='Markdown supported...' />
        <button onClick={saveNote}>Save Note</button>

        <h3>Status History</h3>
        <ul>
          {(alert.status_history || []).map((h, i) => <li key={i}>{new Date(h.at).toLocaleString()} — {h.status} {h.by ? `(by ${h.by})` : ''}</li>)}
        </ul>
      </section>

      <aside style={{ background: '#0f172a', padding: 12, border: '1px solid #1f2937', borderRadius: 10 }}>
        <h3>Attacker Profile</h3>
        <p><strong>IP:</strong> {alert.source_ip}</p>
        <p><strong>Country:</strong> {alert.source_country || '-'} {alert.source_city ? `(${alert.source_city})` : ''}</p>
        <p><strong>ASN:</strong> {alert.source_asn || '-'}</p>
        <p><strong>Abuse score:</strong> {alert.abuse_score ?? '-'}</p>
        {alert.is_tor && <div style={{ display: 'inline-block', padding: '4px 8px', borderRadius: 6, background: '#7c2d12' }}>TOR</div>}
        <p><strong>First seen:</strong> {alert.first_seen_at ? new Date(alert.first_seen_at).toLocaleString() : '-'}</p>
        <p><strong>Last seen:</strong> {alert.last_seen_at ? new Date(alert.last_seen_at).toLocaleString() : '-'}</p>
        <p><strong>Total interactions:</strong> {alert.event_count ?? 0}</p>
      </aside>
    </div>
  )
}
