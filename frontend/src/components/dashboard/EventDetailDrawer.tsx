import { LiveEvent } from '../../hooks/useWebSocket'

export default function EventDetailDrawer({ event, onClose }: { event: LiveEvent | null, onClose: () => void }) {
  if (!event) return null
  return (
    <div style={{ position: 'fixed', right: 0, top: 0, width: 420, height: '100vh', background: '#0b1220', borderLeft: '1px solid #243043', padding: 16, overflow: 'auto', zIndex: 1000 }}>
      <button onClick={onClose} style={{ float: 'right' }}>Close</button>
      <h3 style={{ marginTop: 0 }}>Event Detail</h3>
      <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 12 }}>
        {JSON.stringify(event, null, 2)}
      </pre>
    </div>
  )
}
