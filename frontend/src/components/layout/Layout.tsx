import { Link, Outlet } from 'react-router-dom'

const links = [
  ['/', 'Dashboard'], ['/decoys','Decoys'], ['/networks','Networks'], ['/events','Events'], ['/alerts','Alerts'],
  ['/threat-intel','Threat Intel'], ['/mitre','MITRE'], ['/rules','Rules'], ['/integrations','Integrations'],
  ['/sensors','Sensors'], ['/settings','Settings']
]

export default function Layout(){
  return (
    <div style={{display:'grid', gridTemplateColumns:'220px 1fr', minHeight:'100vh'}}>
      <aside style={{borderRight:'1px solid #1e293b', padding:16}}>
        <h2 style={{marginTop:0}}>PHANTOMGRID</h2>
        <nav style={{display:'grid', gap:8}}>
          {links.map(([to,label]) => <Link key={to} to={to}>{label}</Link>)}
        </nav>
      </aside>
      <main style={{padding:16}}>
        <Outlet />
      </main>
    </div>
  )
}
