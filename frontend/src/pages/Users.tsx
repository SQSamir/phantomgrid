import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { formatDistanceToNow } from 'date-fns';
import {
  UserPlus, Trash2, Shield, ShieldOff, KeyRound,
  Unlock, ToggleLeft, ToggleRight, UserCog, Eye,
  AlertTriangle, CheckCircle,
} from 'lucide-react';
import { apiGet, apiFetch } from '../api/client';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface User {
  id: string;
  email: string;
  display_name: string | null;
  role: string;
  mfa_enabled: boolean;
  failed_login_attempts: number;
  locked: boolean;
  locked_until: string | null;
  last_login_at: string | null;
  created_at: string;
  active: boolean;
}
interface UsersResp { total: number; items: User[] }
interface Settings { registration_enabled: boolean }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ROLE_META: Record<string, { label: string; color: string }> = {
  tenant_admin: { label: 'Admin',   color: 'bg-indigo-900/60 text-indigo-300' },
  analyst:      { label: 'Analyst', color: 'bg-blue-900/60 text-blue-300' },
  viewer:       { label: 'Viewer',  color: 'bg-gray-800 text-gray-400' },
};

async function authFetch(path: string, init: RequestInit = {}) {
  const token = localStorage.getItem('access_token');
  const res = await fetch(
    `${(import.meta.env.VITE_API_URL as string) || 'http://localhost:8080'}${path}`,
    {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        ...(init.headers as Record<string, string> ?? {}),
      },
    },
  );
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail ?? `HTTP ${res.status}`);
  }
  if (res.status === 204) return null;
  return res.json();
}

// ---------------------------------------------------------------------------
// Create User Modal
// ---------------------------------------------------------------------------

function CreateUserModal({ onClose, onCreated }: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [name, setName]         = useState('');
  const [role, setRole]         = useState('analyst');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);

  const submit = async () => {
    if (!email || !password) { setError('Email and password required'); return; }
    if (password.length < 8) { setError('Password must be at least 8 characters'); return; }
    setLoading(true);
    try {
      await authFetch('/auth/admin/users', {
        method: 'POST',
        body: JSON.stringify({ email, password, display_name: name || null, role }),
      });
      onCreated();
      onClose();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="card w-full max-w-md border border-indigo-800">
        <h3 className="font-semibold text-white mb-4">Create User</h3>
        {error && <p className="text-red-400 text-sm mb-3">{error}</p>}
        <div className="space-y-3">
          <div>
            <label className="block text-xs text-gray-400 mb-1">Email *</label>
            <input className="input" type="email" value={email}
              onChange={e => setEmail(e.target.value)} placeholder="user@example.com" />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Display Name</label>
            <input className="input" value={name}
              onChange={e => setName(e.target.value)} placeholder="John Smith" />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Password *</label>
            <input className="input" type="password" value={password}
              onChange={e => setPassword(e.target.value)} placeholder="Min 8 characters" />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Role</label>
            <select className="input" value={role} onChange={e => setRole(e.target.value)}>
              <option value="tenant_admin">Admin — full access</option>
              <option value="analyst">Analyst — read + acknowledge alerts</option>
              <option value="viewer">Viewer — read-only</option>
            </select>
          </div>
        </div>
        <div className="flex gap-2 mt-4">
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? 'Creating…' : 'Create User'}
          </button>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Reset Password Modal
// ---------------------------------------------------------------------------

function ResetPasswordModal({ user, onClose }: { user: User; onClose: () => void }) {
  const [password, setPassword] = useState('');
  const [done, setDone]         = useState(false);
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);

  const submit = async () => {
    if (password.length < 8) { setError('Min 8 characters'); return; }
    setLoading(true);
    try {
      await authFetch(`/auth/admin/users/${user.id}/reset-password`, {
        method: 'POST',
        body: JSON.stringify({ new_password: password }),
      });
      setDone(true);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="card w-full max-w-sm border border-yellow-800">
        <h3 className="font-semibold text-white mb-1">Reset Password</h3>
        <p className="text-xs text-gray-500 mb-4">{user.email}</p>
        {done ? (
          <div className="flex items-center gap-2 text-green-400 text-sm">
            <CheckCircle size={16} /> Password updated successfully
          </div>
        ) : (
          <>
            {error && <p className="text-red-400 text-sm mb-3">{error}</p>}
            <div>
              <label className="block text-xs text-gray-400 mb-1">New Password</label>
              <input className="input" type="password" value={password}
                onChange={e => setPassword(e.target.value)} placeholder="Min 8 characters" />
            </div>
            <div className="flex gap-2 mt-4">
              <button className="btn-primary" onClick={submit} disabled={loading}>
                {loading ? 'Saving…' : 'Reset Password'}
              </button>
              <button className="btn-secondary" onClick={onClose}>Cancel</button>
            </div>
          </>
        )}
        {done && (
          <button className="btn-secondary mt-3" onClick={onClose}>Close</button>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function Users() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate]       = useState(false);
  const [resetTarget, setResetTarget]     = useState<User | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<User | null>(null);

  const { data, isLoading } = useQuery<UsersResp>({
    queryKey: ['admin-users'],
    queryFn:  () => authFetch('/auth/admin/users?limit=100'),
    refetchInterval: 30_000,
  });

  const { data: settings, isLoading: settingsLoading } = useQuery<Settings>({
    queryKey: ['admin-settings'],
    queryFn:  () => authFetch('/auth/admin/settings'),
  });

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['admin-users'] });
    qc.invalidateQueries({ queryKey: ['admin-settings'] });
  };

  const patch = async (id: string, body: object) => {
    await authFetch(`/auth/admin/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
    refresh();
  };

  const deleteUser = async (u: User) => {
    await authFetch(`/auth/admin/users/${u.id}`, { method: 'DELETE' });
    setConfirmDelete(null);
    refresh();
  };

  const toggleRegistration = async () => {
    if (!settings) return;
    await authFetch('/auth/admin/settings', {
      method: 'PATCH',
      body: JSON.stringify({ registration_enabled: !settings.registration_enabled }),
    });
    qc.invalidateQueries({ queryKey: ['admin-settings'] });
  };

  const users = data?.items ?? [];
  const activeCount      = users.filter(u => u.active).length;
  const adminCount       = users.filter(u => u.role === 'tenant_admin').length;
  const lockedCount      = users.filter(u => u.locked).length;
  const mfaCount         = users.filter(u => u.mfa_enabled).length;

  return (
    <div className="space-y-4">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">User Management</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Manage accounts, roles, passwords and registration settings
          </p>
        </div>
        <button
          className="btn-primary flex items-center gap-2"
          onClick={() => setShowCreate(true)}
        >
          <UserPlus size={15} /> Add User
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total Users',    value: data?.total ?? '—' },
          { label: 'Active',         value: activeCount },
          { label: 'Admins',         value: adminCount },
          { label: 'MFA Enabled',    value: `${mfaCount}/${users.length}` },
        ].map(s => (
          <div key={s.label} className="card py-3">
            <p className="text-2xl font-bold text-white">{s.value}</p>
            <p className="text-xs text-gray-500 mt-0.5">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Registration toggle */}
      <div className="card flex items-center justify-between">
        <div>
          <p className="font-medium text-white text-sm">Self-Registration</p>
          <p className="text-xs text-gray-500 mt-0.5">
            {settings?.registration_enabled
              ? 'Anyone can create an account at /register'
              : 'Registration disabled — only admins can create accounts'}
          </p>
        </div>
        {!settingsLoading && settings && (
          <button
            onClick={toggleRegistration}
            className="flex items-center gap-2 text-sm transition-colors"
            title={settings.registration_enabled ? 'Disable registration' : 'Enable registration'}
          >
            {settings.registration_enabled
              ? <><ToggleRight size={28} className="text-green-400" /><span className="text-green-400 text-xs">Enabled</span></>
              : <><ToggleLeft  size={28} className="text-red-400"   /><span className="text-red-400 text-xs">Disabled</span></>
            }
          </button>
        )}
      </div>

      {/* Locked users warning */}
      {lockedCount > 0 && (
        <div className="card border border-yellow-800 flex items-center gap-3 py-3">
          <AlertTriangle size={16} className="text-yellow-400 flex-shrink-0" />
          <p className="text-sm text-yellow-300">
            {lockedCount} account{lockedCount > 1 ? 's are' : ' is'} currently locked out.
          </p>
        </div>
      )}

      {/* User table */}
      <div className="card p-0 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wide">
              <th className="text-left px-4 py-3">User</th>
              <th className="text-left px-4 py-3">Role</th>
              <th className="text-left px-4 py-3 hidden lg:table-cell">MFA</th>
              <th className="text-left px-4 py-3 hidden lg:table-cell">Last Login</th>
              <th className="text-left px-4 py-3 hidden xl:table-cell">Created</th>
              <th className="text-left px-4 py-3">Status</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={7} className="text-center text-gray-500 py-8">Loading…</td></tr>
            )}
            {!isLoading && !users.length && (
              <tr><td colSpan={7} className="text-center text-gray-500 py-8">No users found</td></tr>
            )}
            {users.map(u => {
              const roleMeta = ROLE_META[u.role] ?? { label: u.role, color: 'bg-gray-800 text-gray-400' };
              return (
                <tr key={u.id} className={`border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors ${!u.active ? 'opacity-50' : ''}`}>

                  {/* User info */}
                  <td className="px-4 py-3">
                    <p className="font-medium text-white">
                      {u.display_name || u.email.split('@')[0]}
                    </p>
                    <p className="text-xs text-gray-500">{u.email}</p>
                  </td>

                  {/* Role */}
                  <td className="px-4 py-3">
                    <select
                      className={`text-xs px-2 py-0.5 rounded font-medium bg-transparent border-0 cursor-pointer ${roleMeta.color}`}
                      value={u.role}
                      onChange={e => patch(u.id, { role: e.target.value })}
                      onClick={e => e.stopPropagation()}
                    >
                      <option value="tenant_admin">Admin</option>
                      <option value="analyst">Analyst</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  </td>

                  {/* MFA */}
                  <td className="px-4 py-3 hidden lg:table-cell">
                    {u.mfa_enabled
                      ? <span className="text-xs text-green-400 flex items-center gap-1"><CheckCircle size={11} /> Active</span>
                      : <span className="text-xs text-gray-600">Off</span>}
                  </td>

                  {/* Last login */}
                  <td className="px-4 py-3 hidden lg:table-cell text-xs text-gray-500">
                    {u.last_login_at
                      ? formatDistanceToNow(new Date(u.last_login_at), { addSuffix: true })
                      : <span className="text-gray-700">Never</span>}
                  </td>

                  {/* Created */}
                  <td className="px-4 py-3 hidden xl:table-cell text-xs text-gray-600">
                    {u.created_at ? formatDistanceToNow(new Date(u.created_at), { addSuffix: true }) : '—'}
                  </td>

                  {/* Status */}
                  <td className="px-4 py-3">
                    {!u.active ? (
                      <span className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-500">Deactivated</span>
                    ) : u.locked ? (
                      <span className="text-xs px-1.5 py-0.5 rounded bg-red-900/50 text-red-300">Locked</span>
                    ) : (
                      <span className="text-xs px-1.5 py-0.5 rounded bg-green-900/30 text-green-400">Active</span>
                    )}
                  </td>

                  {/* Actions */}
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1 justify-end">

                      {/* Unlock */}
                      {u.locked && (
                        <button
                          onClick={() => patch(u.id, { unlock: true })}
                          className="p-1.5 rounded hover:bg-gray-700 text-yellow-400 transition-colors"
                          title="Unlock account"
                        >
                          <Unlock size={13} />
                        </button>
                      )}

                      {/* Reset password */}
                      <button
                        onClick={() => setResetTarget(u)}
                        className="p-1.5 rounded hover:bg-gray-700 text-blue-400 transition-colors"
                        title="Reset password"
                      >
                        <KeyRound size={13} />
                      </button>

                      {/* Activate / Deactivate */}
                      <button
                        onClick={() => patch(u.id, { active: !u.active })}
                        className="p-1.5 rounded hover:bg-gray-700 transition-colors"
                        title={u.active ? 'Deactivate' : 'Reactivate'}
                      >
                        {u.active
                          ? <ShieldOff size={13} className="text-orange-400" />
                          : <Shield    size={13} className="text-green-400"  />}
                      </button>

                      {/* Delete */}
                      <button
                        onClick={() => setConfirmDelete(u)}
                        className="p-1.5 rounded hover:bg-gray-700 text-red-400 transition-colors"
                        title="Delete user"
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Modals */}
      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          onCreated={refresh}
        />
      )}

      {resetTarget && (
        <ResetPasswordModal
          user={resetTarget}
          onClose={() => setResetTarget(null)}
        />
      )}

      {confirmDelete && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="card w-full max-w-sm border border-red-800">
            <h3 className="font-semibold text-white mb-2">Delete User?</h3>
            <p className="text-sm text-gray-400 mb-4">
              Permanently delete <span className="text-white">{confirmDelete.email}</span>?
              This cannot be undone.
            </p>
            <div className="flex gap-2">
              <button
                className="flex-1 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium transition-colors"
                onClick={() => deleteUser(confirmDelete)}
              >
                Delete
              </button>
              <button className="btn-secondary flex-1" onClick={() => setConfirmDelete(null)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
