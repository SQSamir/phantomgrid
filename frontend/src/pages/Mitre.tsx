import { useEffect, useMemo, useState } from 'react'
import { apiGet } from '../api/client'

type Technique = { id: string; name: string; tactic: string; detection_count: number; events?: unknown[]; description?: string }

type MatrixResponse = { tactics: string[]; techniques: Technique[] }

const colorForCount = (n: number) => n === 0 ? '#1a1f2e' : n <= 5 ? '#1a3a5c' : n <= 20 ? '#1a5c3a' : '#5c1a1a'

export default function Mitre() {
  const [matrix, setMatrix] = useState<MatrixResponse>({ tactics: [], techniques: [] })
  const [selected, setSelected] = useState<Technique | null>(null)

  useEffect(() => {
    apiGet('/mitre/matrix').then(setMatrix).catch(() => setMatrix({ tactics: [], techniques: [] }))
  }, [])

  const byTactic = useMemo(() => {
    const m = new Map<string, Technique[]>()
    for (const t of matrix.techniques) {
      const arr = m.get(t.tactic) || []
      arr.push(t)
      m.set(t.tactic, arr)
    }
    return m
  }, [matrix])

  const exportNavigator = async () => {
    const r = await fetch('/api/v1/mitre/navigator-layer')
    const blob = await r.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'phantomgrid-attack-navigator.json'
    a.click()
  }

  return (
    <div style={{ position: 'relative' }}>
      <h1>MITRE ATT&CK Matrix</h1>
      <button onClick={exportNavigator}>Export Navigator Layer</button>
      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${matrix.tactics.length || 1}, minmax(180px, 1fr))`, gap: 8, marginTop: 12 }}>
        {matrix.tactics.map((tactic) => (
          <div key={tactic} style={{ border: '1px solid #1f2937', borderRadius: 8, padding: 8, background: '#0f172a' }}>
            <h4 style={{ marginTop: 0 }}>{tactic}</h4>
            <div style={{ display: 'grid', gap: 6 }}>
              {(byTactic.get(tactic) || []).map((tech) => (
                <button key={tech.id} onClick={() => setSelected(tech)} style={{ textAlign: 'left', border: '1px solid #263247', borderRadius: 6, padding: 8, background: colorForCount(tech.detection_count), color: '#e5e7eb' }}>
                  <div>{tech.id}</div>
                  <div style={{ fontWeight: 700 }}>{tech.name}</div>
                  <small>Detections: {tech.detection_count}</small>
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>

      {selected && (
        <aside style={{ position: 'fixed', right: 0, top: 0, width: 460, height: '100vh', background: '#0b1220', borderLeft: '1px solid #1f2937', padding: 16, overflow: 'auto' }}>
          <button onClick={() => setSelected(null)} style={{ float: 'right' }}>Close</button>
          <h3>{selected.id} — {selected.name}</h3>
          <p>{selected.description || 'No description'}</p>
          <h4>Events</h4>
          <pre>{JSON.stringify(selected.events || [], null, 2)}</pre>
        </aside>
      )}
    </div>
  )
}
