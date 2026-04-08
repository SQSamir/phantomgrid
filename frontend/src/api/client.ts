const API_BASE = import.meta.env.VITE_API_BASE || '/api/v1'

function withAuth(headers?: HeadersInit): HeadersInit {
  const token = localStorage.getItem('accessToken')
  return {
    'Content-Type': 'application/json',
    ...(headers || {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }
}

export async function apiGet(path: string){
  const r = await fetch(`${API_BASE}${path}`, { headers: withAuth() })
  if(!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}

export async function apiPost(path: string, body: unknown){
  const r = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: withAuth(),
    body: JSON.stringify(body),
  })
  if(!r.ok) throw new Error(`HTTP ${r.status}`)
  if (r.status === 204) return null
  return r.json()
}

export async function apiPatch(path: string, body: unknown){
  const r = await fetch(`${API_BASE}${path}`, {
    method: 'PATCH',
    headers: withAuth(),
    body: JSON.stringify(body),
  })
  if(!r.ok) throw new Error(`HTTP ${r.status}`)
  if (r.status === 204) return null
  return r.json()
}
