import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Ghost } from 'lucide-react';
import { useAuthStore } from '../store/authStore';

export default function Login() {
  const navigate = useNavigate();
  const login = useAuthStore((s) => s.login);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [showOtp, setShowOtp] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(email, password, otp || undefined);
      navigate('/');
    } catch (err: any) {
      const msg: string = err.message || '';
      if (msg.toLowerCase().includes('mfa') || msg.toLowerCase().includes('otp')) {
        setShowOtp(true);
        setError('Enter your MFA code.');
      } else {
        setError(msg);
      }
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
          <h2 className="text-lg font-semibold mb-5 text-center">Sign in</h2>
          {error && (
            <div className="mb-4 p-3 bg-red-900/40 border border-red-800 rounded-lg text-red-300 text-sm">
              {error}
            </div>
          )}
          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Email</label>
              <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Password</label>
              <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            </div>
            {showOtp && (
              <div>
                <label className="block text-xs text-gray-400 mb-1">MFA Code</label>
                <input className="input" type="text" value={otp} onChange={(e) => setOtp(e.target.value)} placeholder="6-digit code" autoFocus />
              </div>
            )}
            <button type="submit" className="btn-primary w-full mt-2" disabled={loading}>
              {loading ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
          <p className="text-center text-sm text-gray-500 mt-4">
            No account?{' '}
            <Link to="/register" className="text-indigo-400 hover:text-indigo-300">Register</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
