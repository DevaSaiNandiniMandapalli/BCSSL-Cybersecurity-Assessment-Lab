import { useEffect, useState } from 'react';
import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Exercises from './pages/Exercises.jsx';
import ExerciseDetail from './pages/ExerciseDetail.jsx';
import LabTarget from './pages/LabTarget.jsx';
import Evidence from './pages/Evidence.jsx';
import Progress from './pages/Progress.jsx';
import Profile from './pages/Profile.jsx';

function BootScreen() {
  return (
    <div className="boot-screen">
      <div className="boot-logo">BC</div>
      <div className="boot-text">BCSSL CYBER LAB</div>
      <div className="boot-bar">
        <div className="boot-bar-fill" />
      </div>
      <div className="boot-text" style={{ fontSize: 11, opacity: 0.7 }}>
        Blue Cloud Softech Solutions Ltd.
      </div>
    </div>
  );
}

export default function App() {
  const [booting, setBooting] = useState(true);

  useEffect(() => {
    const t = setTimeout(() => setBooting(false), 900);
    return () => clearTimeout(t);
  }, []);

  if (booting) return <BootScreen />;

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="exercises" element={<Exercises />} />
        <Route path="exercises/:slug" element={<ExerciseDetail />} />
        <Route path="lab-target" element={<LabTarget />} />
        <Route path="evidence" element={<Evidence />} />
        <Route path="progress" element={<Progress />} />
        <Route path="profile" element={<Profile />} />
        <Route path="*" element={<Dashboard />} />
      </Route>
    </Routes>
  );
}
