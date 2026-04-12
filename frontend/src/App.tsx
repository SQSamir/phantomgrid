import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Events from './pages/Events';
import Alerts from './pages/Alerts';
import Attackers from './pages/Attackers';
import Sessions from './pages/Sessions';
import Decoys from './pages/Decoys';
import Mitre from './pages/Mitre';
import Integrations from './pages/Integrations';
import Artifacts from './pages/Artifacts';

export default function App() {
  return (
    <Routes>
      <Route path="/login"    element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route path="/"             element={<Dashboard />} />
        <Route path="/events"       element={<Events />} />
        <Route path="/alerts"       element={<Alerts />} />
        <Route path="/attackers"    element={<Attackers />} />
        <Route path="/sessions"     element={<Sessions />} />
        <Route path="/decoys"       element={<Decoys />} />
        <Route path="/mitre"        element={<Mitre />} />
        <Route path="/integrations" element={<Integrations />} />
        <Route path="/artifacts"    element={<Artifacts />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
