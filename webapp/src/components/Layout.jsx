import { useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import Icon from './Icon.jsx';
import Logo from './Logo.jsx';
import ProgressBar from './ProgressBar.jsx';
import Toast from './Toast.jsx';
import { useProgress } from '../context/ProgressContext.jsx';
import { useTheme } from '../context/ThemeContext.jsx';
import { COURSE } from '../data/exercises.js';

const NAV = [
  { to: '/', label: 'Dashboard', icon: 'dashboard', end: true },
  { to: '/exercises', label: 'Exercises', icon: 'exercises' },
  { to: '/lab-target', label: 'Lab Target', icon: 'target' },
  { to: '/evidence', label: 'Evidence', icon: 'evidence' },
  { to: '/progress', label: 'Progress', icon: 'progress' },
  { to: '/profile', label: 'Profile', icon: 'profile' },
];

const TITLES = [
  { match: /^\/$/, title: 'Dashboard', sub: 'Laboratory control panel' },
  { match: /^\/exercises/, title: 'Exercises', sub: 'Seven progressive lab exercises' },
  { match: /^\/lab-target/, title: 'Lab Target', sub: 'Authorized testing environment' },
  { match: /^\/evidence/, title: 'Evidence & Submissions', sub: 'Compile and track your evidence' },
  { match: /^\/progress/, title: 'Progress', sub: 'Your learning journey' },
  { match: /^\/profile/, title: 'Profile', sub: 'Your student profile' },
];

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const { stats, profile, toast } = useProgress();
  const { theme, toggleTheme } = useTheme();

  const current = TITLES.find((t) => t.match.test(location.pathname)) || TITLES[0];
  const initials = (profile.name || 'Student')
    .split(' ')
    .map((w) => w[0])
    .filter(Boolean)
    .slice(0, 2)
    .join('')
    .toUpperCase();

  return (
    <div className="app-shell">
      <div
        className={`sidebar-overlay ${sidebarOpen ? 'show' : ''}`}
        onClick={() => setSidebarOpen(false)}
      />

      <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
        <div className="sidebar-brand">
          <Logo size="md" chip />
          <div className="brand-text">
            <div className="brand-name">BCSSL Scanner Lab</div>
            <div className="brand-tag">Think Big | AI-First</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-label">Learning Platform</div>
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              onClick={() => setSidebarOpen(false)}
            >
              <Icon name={item.icon} size={19} />
              {item.label}
              {item.to === '/exercises' && stats.done > 0 && (
                <span className="nav-badge">
                  {stats.done}/{stats.total}
                </span>
              )}
            </NavLink>
          ))}

          <div className="nav-section-label">Course</div>
          <div className="nav-item" style={{ cursor: 'default' }}>
            <Icon name="book" size={19} />
            {COURSE.title}
          </div>
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-progress-label">
            <span>Course progress</span>
            <span>
              {stats.done}/{stats.total} exercises
            </span>
          </div>
          <ProgressBar value={stats.pct} showLabel={false} />
          <div className="sidebar-company">Blue Cloud Softech Solutions Ltd.</div>
        </div>
      </aside>

      <div className="app-main">
        <header className="topbar">
          <button className="icon-btn menu-btn" onClick={() => setSidebarOpen(true)} aria-label="Open menu">
            <Icon name="menu" size={22} />
          </button>
          <div>
            <div className="topbar-title">{current.title}</div>
            <div className="topbar-subtitle">{current.sub}</div>
          </div>
          <div className="topbar-spacer" />
          <div className="topbar-target" title="Authorized lab target">
            <span className="dot" />
            {COURSE.target}
          </div>
          <button
            className="icon-btn"
            onClick={toggleTheme}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            <Icon name={theme === 'dark' ? 'sun' : 'moon'} size={19} />
          </button>
          <div
            className="topbar-avatar"
            title={profile.name ? `Signed in as ${profile.name}` : 'Set your name in Profile'}
            onClick={() => navigate('/profile')}
          >
            {initials}
          </div>
        </header>

        <main className="app-content">
          <Outlet />
        </main>

        <footer className="footer-bar">
          <div className="flex-center gap-10">
            <Logo size="sm" chip />
            <span>BCSSL Web Application Security Scanner Lab</span>
          </div>
          <span>Blue Cloud Softech Solutions Ltd. | Authorized lab use only</span>
        </footer>
      </div>

      <Toast toast={toast} />
    </div>
  );
}
