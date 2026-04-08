const API_BASE = import.meta.env.VITE_API_BASE || '/api/v1'

export async function apiGet(path: string){
  const r = await fetch(`${API_BASE}${path}`)
  if(!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}
