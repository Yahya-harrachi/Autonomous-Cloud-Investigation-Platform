import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import IncidentList from './pages/IncidentList';
import IncidentDetail from './pages/IncidentDetail';
import CreateIncident from './pages/CreateIncident';
import EventsViewer from './pages/EventsViewer';
import RuleList from './pages/RuleList';        
import RuleForm from './pages/RuleForm';  
import RealtimeEventsViewer from './pages/RealtimeEventsViewer';


function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-100">
        <Header />
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/incidents" element={<IncidentList />} />
          <Route path="/incidents/new" element={<CreateIncident />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/events" element={<EventsViewer />} />
          <Route path="/rules" element={<RuleList />} />           
          <Route path="/rules/new" element={<RuleForm />} />       
          <Route path="/rules/:id/edit" element={<RuleForm />} />  
          <Route path="/realtime-events" element={<RealtimeEventsViewer />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;