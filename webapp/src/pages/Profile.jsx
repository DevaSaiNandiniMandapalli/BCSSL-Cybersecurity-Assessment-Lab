import { useState } from 'react';
import Icon from '../components/Icon.jsx';
import Logo from '../components/Logo.jsx';
import { useProgress } from '../context/ProgressContext.jsx';
import { COURSE } from '../data/exercises.js';

export default function Profile() {
  const { profile, updateProfile, stats, resetAll, showToast } = useProgress();
  const [form, setForm] = useState(profile);
  const [confirmReset, setConfirmReset] = useState(false);
  const [dirty, setDirty] = useState(false);

  const set = (key) => (e) => {
    setForm((f) => ({ ...f, [key]: e.target.value }));
    setDirty(true);
  };

  const save = () => {
    updateProfile(form);
    setDirty(false);
    showToast('Profile saved', 'success');
  };

  const initials = (form.name || 'Student')
    .split(' ')
    .map((w) => w[0])
    .filter(Boolean)
    .slice(0, 2)
    .join('')
    .toUpperCase();

  return (
    <div>
      <div className="page-header fade-in-up">
        <div className="page-eyebrow">Student Profile</div>
        <h1 className="page-title">Profile</h1>
        <p className="page-subtitle">
          Your identity on the {COURSE.product} platform. This information appears on your lab
          submission cover page.
        </p>
      </div>

      <div className="grid grid-profile">
        {/* Identity card */}
        <div className="card card-pad fade-in-up stagger-1" style={{ textAlign: 'center', alignSelf: 'start' }}>
          <div
            style={{
              width: 84,
              height: 84,
              borderRadius: '50%',
              background: 'linear-gradient(135deg, var(--blue-500), var(--blue-800))',
              color: '#fff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 30,
              fontWeight: 800,
              margin: '0 auto 16px',
              boxShadow: 'var(--shadow-blue)',
            }}
          >
            {initials}
          </div>
          <h3 style={{ fontSize: 18 }}>{form.name || 'Student'}</h3>
          <p className="text-muted" style={{ fontSize: 13, marginTop: 4 }}>
            {form.studentId ? `ID: ${form.studentId}` : 'No student ID set'}
          </p>
          <hr className="divider" />
          <div style={{ textAlign: 'left', display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div className="flex-between">
              <span className="text-small text-muted">Program</span>
              <span className="text-small" style={{ fontWeight: 600 }}>Web Application Security Scanner Lab</span>
            </div>
            <div className="flex-between">
              <span className="text-small text-muted">Exercises done</span>
              <span className="text-small" style={{ fontWeight: 600 }}>{stats.done}/{stats.total}</span>
            </div>
            <div className="flex-between">
              <span className="text-small text-muted">Evidence ready</span>
              <span className="text-small" style={{ fontWeight: 600 }}>
                {stats.evidenceDone}/{stats.evidenceTotal}
              </span>
            </div>
          </div>
          <hr className="divider" />
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <Logo size="lg" chip />
          </div>
          <p className="text-small text-muted" style={{ marginTop: 12, fontWeight: 600 }}>
            {COURSE.company}
          </p>
          <p className="text-small" style={{ color: 'var(--text-4)', marginTop: 2 }}>
            {COURSE.tagline}
          </p>
        </div>

        {/* Edit form */}
        <div className="card card-pad fade-in-up stagger-2">
          <h3 style={{ fontSize: 16, marginBottom: 18, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="profile" size={18} className="text-blue" />
            Profile Details
          </h3>

          <div className="grid grid-2" style={{ gap: 0 }}>
            <div className="field" style={{ marginRight: 16 }}>
              <label htmlFor="pf-name">Full name</label>
              <input
                id="pf-name"
                className="input"
                placeholder="e.g. Alex Morgan"
                value={form.name}
                onChange={set('name')}
              />
            </div>
            <div className="field">
              <label htmlFor="pf-id">Student ID</label>
              <input
                id="pf-id"
                className="input"
                placeholder="e.g. BCSSL-2026-001"
                value={form.studentId}
                onChange={set('studentId')}
              />
            </div>
            <div className="field" style={{ marginRight: 16 }}>
              <label htmlFor="pf-email">Email</label>
              <input
                id="pf-email"
                type="email"
                className="input"
                placeholder="you@school.edu"
                value={form.email}
                onChange={set('email')}
              />
            </div>
            <div className="field">
              <label htmlFor="pf-cohort">Cohort / Class</label>
              <input
                id="pf-cohort"
                className="input"
                placeholder="e.g. CYB-2026-A"
                value={form.cohort}
                onChange={set('cohort')}
              />
            </div>
          </div>

          <div className="flex gap-12 mt-8">
            <button className="btn btn-blue" onClick={save} disabled={!dirty}>
              <Icon name="check" size={15} />
              {dirty ? 'Save Changes' : 'Saved'}
            </button>
            {dirty && (
              <button
                className="btn btn-ghost"
                onClick={() => {
                  setForm(profile);
                  setDirty(false);
                }}
              >
                Discard
              </button>
            )}
          </div>

          <hr className="divider" />

          <h3 style={{ fontSize: 16, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="alert-triangle" size={18} className="text-orange" />
            Danger Zone
          </h3>
          <p className="text-muted" style={{ fontSize: 13.5, marginBottom: 14 }}>
            Resetting clears all locally stored progress, checklist items, answers, and profile
            details from this browser. This cannot be undone.
          </p>
          {!confirmReset ? (
            <button className="btn btn-danger-outline" onClick={() => setConfirmReset(true)}>
              <Icon name="trash" size={15} />
              Reset all progress
            </button>
          ) : (
            <div className="flex gap-12">
              <button
                className="btn btn-primary"
                onClick={() => {
                  resetAll();
                  setConfirmReset(false);
                  setForm({ name: '', studentId: '', email: '', cohort: '' });
                }}
              >
                Yes, reset everything
              </button>
              <button className="btn btn-ghost" onClick={() => setConfirmReset(false)}>
                Cancel
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
