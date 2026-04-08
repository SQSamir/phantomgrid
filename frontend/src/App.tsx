import { Route, Routes } from 'react-router-dom'
import Layout from './components/layout/Layout'
import Dashboard from './pages/Dashboard'
import Decoys from './pages/Decoys'
import DecoyDetail from './pages/DecoyDetail'
import Networks from './pages/Networks'
import Events from './pages/Events'
import Alerts from './pages/Alerts'
import AlertDetail from './pages/AlertDetail'
import ThreatIntel from './pages/ThreatIntel'
import Mitre from './pages/Mitre'
import Rules from './pages/Rules'
import Integrations from './pages/Integrations'
import Sensors from './pages/Sensors'
import Settings from './pages/Settings'

export default function App(){
  return (
    <Routes>
      <Route path='/' element={<Layout/>}>
        <Route index element={<Dashboard/>}/>
        <Route path='decoys' element={<Decoys/>}/>
        <Route path='decoys/:id' element={<DecoyDetail/>}/>
        <Route path='networks' element={<Networks/>}/>
        <Route path='events' element={<Events/>}/>
        <Route path='alerts' element={<Alerts/>}/>
        <Route path='alerts/:id' element={<AlertDetail/>}/>
        <Route path='threat-intel' element={<ThreatIntel/>}/>
        <Route path='mitre' element={<Mitre/>}/>
        <Route path='rules' element={<Rules/>}/>
        <Route path='integrations' element={<Integrations/>}/>
        <Route path='sensors' element={<Sensors/>}/>
        <Route path='settings' element={<Settings/>}/>
      </Route>
    </Routes>
  )
}
