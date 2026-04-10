import { Routes, Route, Link } from 'react-router-dom';
const P=(n:string)=><div>{n}</div>;
export default function App(){return <div><nav><Link to='/'>Dashboard</Link> | <Link to='/events'>Events</Link> | <Link to='/alerts'>Alerts</Link></nav><Routes>
<Route path='/' element={P('Dashboard')} />
<Route path='/events' element={P('Events')} />
<Route path='/alerts' element={P('Alerts')} />
<Route path='/mitre' element={P('MITRE')} />
<Route path='/decoys' element={P('Decoys')} />
<Route path='/integrations' element={P('Integrations')} />
</Routes></div>}
