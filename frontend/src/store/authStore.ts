import { create } from 'zustand';
import { apiFetch } from '../api/client';

interface AuthStore {
  token: string | null;
  isAuthenticated: boolean;
  login: (email: string, password: string, otp?: string) => Promise<void>;
  logout: () => Promise<void>;
  init: () => void;
}

export const useAuthStore = create<AuthStore>((set) => ({
  token: localStorage.getItem('access_token'),
  isAuthenticated: !!localStorage.getItem('access_token'),

  init() {
    const t = localStorage.getItem('access_token');
    set({ token: t, isAuthenticated: !!t });
  },

  async login(email, password, otp) {
    const API = import.meta.env.VITE_API_URL || 'http://localhost:8080';
    const res = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, otp }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Login failed');
    }
    const data = await res.json();
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
    set({ token: data.access_token, isAuthenticated: true });
  },

  async logout() {
    const rt = localStorage.getItem('refresh_token');
    try {
      await apiFetch('/auth/logout', {
        method: 'POST',
        body: JSON.stringify({ refresh_token: rt }),
      });
    } catch { /* best effort */ }
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    set({ token: null, isAuthenticated: false });
  },
}));
