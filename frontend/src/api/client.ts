const API = import.meta.env.VITE_API_URL || 'http://localhost:8080';

async function refreshTokens(): Promise<string | null> {
  const rt = localStorage.getItem('refresh_token');
  if (!rt) return null;
  try {
    const res = await fetch(`${API}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: rt }),
    });
    if (!res.ok) {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      return null;
    }
    const data = await res.json();
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
    return data.access_token;
  } catch {
    return null;
  }
}

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  let token = localStorage.getItem('access_token');
  const makeHeaders = (t: string | null): HeadersInit => ({
    'Content-Type': 'application/json',
    ...(t ? { Authorization: `Bearer ${t}` } : {}),
    ...(options.headers || {}),
  });

  let res = await fetch(`${API}${path}`, { ...options, headers: makeHeaders(token) });

  if (res.status === 401 && token) {
    const newToken = await refreshTokens();
    if (newToken) {
      res = await fetch(`${API}${path}`, { ...options, headers: makeHeaders(newToken) });
    } else {
      window.location.href = '/login';
    }
  }
  return res;
}

export async function apiGet<T>(path: string): Promise<T> {
  const res = await apiFetch(path);
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`);
  return res.json();
}

export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const res = await apiFetch(path, {
    method: 'POST',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `POST ${path} failed: ${res.status}`);
  }
  return res.json();
}

export async function apiPatch<T>(path: string, body: unknown): Promise<T> {
  const res = await apiFetch(path, { method: 'PATCH', body: JSON.stringify(body) });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `PATCH ${path} failed: ${res.status}`);
  }
  return res.json();
}

export async function apiDelete(path: string): Promise<void> {
  const res = await apiFetch(path, { method: 'DELETE' });
  if (!res.ok && res.status !== 204) throw new Error(`DELETE ${path} failed: ${res.status}`);
}
