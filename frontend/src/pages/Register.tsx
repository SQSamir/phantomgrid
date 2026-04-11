import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Ghost } from 'lucide-react';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8080';

export default function Register() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await fetch(`${API}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, display_name: displayName || undefined }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || 'Registration failed');
      }
      navigate('/login');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950 px-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center justify-center gap-2 mb-8">
          <Ghost className="text-indigo-400" size={28} />
          <span className="text-2xl font-bold text-white">PhantomGrid</span>
        </div>
        <div className="card">
          <h2 className="text-lg font-semibold mb-5 text-center">Create account</h2>
          {error && (
            <div className="mb-4 p-3 bg-red-900/40 border border-red-800 rounded-lg text-red-300 text-sm">
              {error}
            </div>
          )}
          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Display name (optional)</label>
              <input className="input" type="text" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Email</label>
              <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Password</label>
              <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} />
            </div>
            <button type="submit" className="btn-primary w-full mt-2" disabled={loading}>
              {loading ? 'Creating…' : 'Create account'}
            </button>
          </form>
          <p className="text-center text-sm text-gray-500 mt-4">
            Already have an account?{' '}
            <Link to="/login" className="text-indigo-400 hover:text-indigo-300">Sign in</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
