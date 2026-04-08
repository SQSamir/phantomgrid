import { useMemo, useState } from 'react'
import { FixedSizeList as List, ListChildComponentProps } from 'react-window'
import { LiveEvent } from '../../hooks/useWebSocket'
import EventDetailDrawer from './EventDetailDrawer'

type RowData = {
  items: LiveEvent[]
  onSelect: (event: LiveEvent) => void
  newIds: Set<string>
}

const severityColor: Record<string, string> = {
  low: '#16a34a',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
}

function Row({ index, style, data }: ListChildComponentProps<RowData>) {
  const ev = data.items[index]
  const color = severityColor[ev.severity] || '#60a5fa'
  const isNew = data.newIds.has(ev.id)

  return (
    <div style={{ ...style, padding: '6px 10px', borderBottom: '1px solid #1f2937', display: 'flex', alignItems: 'center', gap: 10, background: isNew ? 'rgba(59,130,246,0.08)' : 'transparent', animation: isNew ? 'pulseNew 1s ease-out' : 'none', cursor: 'pointer' }} onClick={() => data.onSelect(ev)}>
      <span style={{ width: 10, height: 10, borderRadius: 10, background: color }} />
      <div style={{ width: 170, opacity: 0.8 }}>{new Date(ev.timestamp).toLocaleTimeString()}</div>
      <div style={{ width: 120 }}>{ev.source_ip}</div>
      <div style={{ width: 80 }}>{ev.protocol}</div>
      <div style={{ width: 120, color }}>{ev.severity.toUpperCase()}</div>
      <div style={{ flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{ev.summary || ev.event_type}</div>
    </div>
  )
}

export default function LiveEventFeed({ events }: { events: LiveEvent[] }) {
  const [selected, setSelected] = useState<LiveEvent | null>(null)
  const [page, setPage] = useState(0)

  const pageSize = 200
  const maxPage = Math.max(Math.ceil(events.length / pageSize) - 1, 0)
  const pageEvents = useMemo(() => events.slice(page * pageSize, (page + 1) * pageSize), [events, page])
  const newIds = useMemo(() => new Set(events.slice(0, 10).map(e => e.id)), [events])

  return (
    <section style={{ border: '1px solid #1f2937', borderRadius: 10, overflow: 'hidden', background: '#111827' }}>
      <style>{`@keyframes pulseNew {0%{box-shadow: inset 0 0 0 9999px rgba(59,130,246,0.25)}100%{box-shadow:none}}`}</style>
      <div style={{ padding: 10, borderBottom: '1px solid #1f2937', display: 'flex', justifyContent: 'space-between' }}>
        <strong>Live Event Feed</strong>
        <div style={{ display: 'flex', gap: 8 }}>
          <button disabled={page === 0} onClick={() => setPage((p) => Math.max(p - 1, 0))}>Newer</button>
          <span>Page {page + 1}/{maxPage + 1}</span>
          <button disabled={page >= maxPage} onClick={() => setPage((p) => Math.min(p + 1, maxPage))}>Older</button>
        </div>
      </div>

      <List
        height={420}
        width={'100%'}
        itemCount={pageEvents.length}
        itemSize={42}
        itemData={{ items: pageEvents, onSelect: setSelected, newIds }}
      >
        {Row}
      </List>

      <EventDetailDrawer event={selected} onClose={() => setSelected(null)} />
    </section>
  )
}
