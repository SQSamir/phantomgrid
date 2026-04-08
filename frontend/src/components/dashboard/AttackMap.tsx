import { useEffect, useMemo, useRef } from 'react'
import L, { CircleMarker, LayerGroup, Map as LeafletMap } from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { LiveEvent } from '../../hooks/useWebSocket'

type Props = { events: LiveEvent[] }
const severityColor: Record<string, string> = { low: '#16a34a', medium: '#eab308', high: '#f97316', critical: '#ef4444' }

function hashToLatLng(ip: string) {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(Number.isNaN)) return [0, 0] as const
  const lat = ((parts[0] * 256 + parts[1]) % 180) - 90
  const lng = ((parts[2] * 256 + parts[3]) % 360) - 180
  return [lat, lng] as const
}

export default function AttackMap({ events }: Props) {
  const mapDiv = useRef<HTMLDivElement | null>(null)
  const mapRef = useRef<LeafletMap | null>(null)
  const layerRef = useRef<LayerGroup | null>(null)
  const markerRef = useRef<Map<string, CircleMarker>>(new Map())

  const grouped = useMemo(() => {
    const m = new Map<string, { count: number, last: LiveEvent }>()
    for (const e of events) {
      const prev = m.get(e.source_ip)
      if (!prev) m.set(e.source_ip, { count: 1, last: e })
      else m.set(e.source_ip, { count: prev.count + 1, last: e })
    }
    return m
  }, [events])

  useEffect(() => {
    if (!mapDiv.current || mapRef.current) return
    const map = L.map(mapDiv.current, { zoomControl: true }).setView([20, 0], 2)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; OpenStreetMap &copy; CartoDB dark_matter'
    }).addTo(map)
    const layer = L.layerGroup().addTo(map)
    mapRef.current = map
    layerRef.current = layer
    return () => map.remove()
  }, [])

  useEffect(() => {
    const layer = layerRef.current
    if (!layer) return

    grouped.forEach((val, ip) => {
      const color = severityColor[val.last.severity] || '#60a5fa'
      const existing = markerRef.current.get(ip)
      if (existing) {
        existing.setStyle({ color, fillColor: color, fillOpacity: 0.7 })
        existing.setRadius(6 + Math.min(val.count / 10, 8))
      } else {
        const [lat, lng] = hashToLatLng(ip)
        const marker = L.circleMarker([lat, lng], { radius: 8, color, fillColor: color, fillOpacity: 0.7, weight: 1 })
        marker.bindPopup(`<b>${ip}</b><br/>Country: ${val.last.source_country || 'N/A'}<br/>Events: ${val.count}<br/>MITRE: ${(val.last.mitre_techniques || []).join(', ') || 'N/A'}`)
        marker.addTo(layer)
        markerRef.current.set(ip, marker)
      }
    })
  }, [grouped])

  return <div ref={mapDiv} style={{ height: 420, borderRadius: 10, overflow: 'hidden', border: '1px solid #1f2937' }} />
}
