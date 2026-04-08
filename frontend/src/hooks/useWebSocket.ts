import { useEffect, useMemo, useRef, useState } from 'react'

export type LiveEvent = {
  id: string
  timestamp: string
  severity: 'low' | 'medium' | 'high' | 'critical' | string
  source_ip: string
  source_country?: string
  source_flag?: string
  protocol: string
  decoy_name?: string
  event_type: string
  mitre_techniques?: string[]
  summary?: string
}

export type LiveAlert = {
  id: string
  severity: string
  title: string
  source_ip?: string
  source_country?: string
  mitre_techniques?: string[]
  event_count?: number
  first_seen?: string
}

type WsEnvelope = { type: 'event'; data: LiveEvent } | { type: 'alert'; data: LiveAlert } | { type: 'ping' }

export function useWebSocket() {
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [alerts, setAlerts] = useState<LiveAlert[]>([])
  const [connected, setConnected] = useState(false)
  const [lastEvent, setLastEvent] = useState<LiveEvent | LiveAlert | null>(null)

  const wsRef = useRef<WebSocket | null>(null)
  const retryRef = useRef(0)
  const timerRef = useRef<number | null>(null)

  const wsUrl = useMemo(() => {
    const token = localStorage.getItem('accessToken') || ''
    const apiBase = (import.meta.env.VITE_API_BASE || '/api/v1') as string
    const origin = window.location.origin.replace(/^http/, 'ws')
    const path = apiBase.replace(/^https?:\/\/[^/]+/, '')
    return `${origin}${path.replace(/\/api\/v1$/, '')}/ws?token=${encodeURIComponent(token)}`
  }, [])

  useEffect(() => {
    let closedByUser = false

    const clearRetryTimer = () => {
      if (timerRef.current) {
        window.clearTimeout(timerRef.current)
        timerRef.current = null
      }
    }

    const connect = () => {
      clearRetryTimer()
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        retryRef.current = 0
        setConnected(true)
      }

      ws.onmessage = (msg) => {
        try {
          const payload = JSON.parse(msg.data) as WsEnvelope
          if (payload.type === 'ping') {
            ws.send(JSON.stringify({ type: 'pong' }))
            return
          }
          setLastEvent(payload.data)
          if (payload.type === 'event') {
            setEvents((prev) => {
              const next = [payload.data, ...prev]
              return next.slice(0, 500)
            })
          } else if (payload.type === 'alert') {
            setAlerts((prev) => [payload.data, ...prev].slice(0, 500))
          }
        } catch {
          // ignore malformed frame
        }
      }

      ws.onerror = () => {
        ws.close()
      }

      ws.onclose = () => {
        setConnected(false)
        if (closedByUser) return
        retryRef.current += 1
        const delay = Math.min(1000 * (2 ** (retryRef.current - 1)), 30000)
        timerRef.current = window.setTimeout(() => {
          const freshToken = localStorage.getItem('accessToken')
          if (!freshToken) return
          connect()
        }, delay)
      }
    }

    connect()

    return () => {
      closedByUser = true
      clearRetryTimer()
      wsRef.current?.close()
    }
  }, [wsUrl])

  return { events, alerts, connected, lastEvent }
}
