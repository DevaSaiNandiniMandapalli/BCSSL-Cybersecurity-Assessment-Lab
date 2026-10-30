import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import Icon from '../components/Icon.jsx';
import Logo from '../components/Logo.jsx';
import ProgressBar from '../components/ProgressBar.jsx';
import TargetCard from '../components/TargetCard.jsx';
import StatCard from '../components/StatCard.jsx';
import { SkeletonCard } from '../components/States.jsx';
import { useProgress } from '../context/ProgressContext.jsx';
import { EXERCISES, COURSE, AUTHORIZATION } from '../data/exercises.js';
import { BADGES, MASTER_BADGE, TOTAL_BADGES, isBadgeUnlocked, isMasterUnlocked, unlockedBadgeCount } from '../data/achievements.js';

export default function Dashboard() {
  const [loading, setLoading] = useState(true);
  const { stats, profile, isCompleted, state } = useProgress();
  const navigate = useNavigate();

  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 650);
    return () => clearTimeout(t);
  }, []);

  const nextUp = EXERCISES.find((e) => !isCompleted(e.id)) || EXERCISES[EXERCISES.length - 1];
  const firstName = (profile.name || 'Student').split(' ')[0];

  if (loading) {
    return (
      <div className="grid grid-3">
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
      </div>
    );
  }

  return (
    <div>
      {/* Hero — clean laboratory control panel header */}
      <div className="lab-hero card-pad fade-in-up mb-24">
        <div className="flex-between" style={{ flexWrap: 'wrap', gap: 20 }}>
          <div style={{ flex: '1 1 420px', minWidth: 300 }}>
            <div className="flex-center gap-14" style={{ justifyContent: 'flex-start', marginBottom: 16 }}>
              <Logo size="lg" chip />
              <div>
                <div className="page-eyebrow" style={{ marginBottom: 5 }}>{COURSE.company}</div>
                <div className="text-small" style={{ color: 'var(--text-4)', fontWeight: 600, letterSpacing: '0.6px' }}>
                  {COURSE.tagline.toUpperCase()}
                </div>
              </div>
            </div>
            <h1 style={{ fontSize: 30, fontWeight: 800, letterSpacing: '-0.5px', lineHeight: 1.2, color: 'var(--text-1)' }}>
              {COURSE.product}
            </h1>
            <p className="mt-8" style={{ fontSize: 15.5, maxWidth: 600, color: 'var(--text-2)', lineHeight: 1.65 }}>
              A hands-on web application security scanner laboratory. Operate the Project #08 scanner
              against the authorized local target, verify observations with curl and Burp Suite, and
              learn to distinguish scanner observations from confirmed vulnerabilities.
            </p>
            <div className="flex gap-12 mt-16" style={{ flexWrap: 'wrap' }}>
              <button className="btn btn-primary btn-lg" onClick={() => navigate(`/exercises/${nextUp.slug}`)}>
                <Icon name="play" size={17} />
                Continue Lab Work
              </button>
              <button className="btn btn-outline btn-lg" onClick={() => navigate('/lab-target')}>
                <Icon name="target" size={17} />
                Lab Target
              </button>
            </div>
          </div>
          <div style={{ flex: '0 1 300px' }}>
            <div className="card card-pad" style={{ background: 'var(--bg-surface)' }}>
              <div className="flex-between" style={{ marginBottom: 10 }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-2)' }}>Course progress</span>
                <span className="badge badge-orange">{stats.done}/{stats.total} complete</span>
              </div>
              <ProgressBar value={stats.pct} size="lg" showLabel={false} />
              <div className="flex-between mt-16" style={{ marginTop: 14, fontSize: 12.5 }}>
                <span className="text-muted">{stats.pct}% finished</span>
                <span className="text-blue" style={{ fontWeight: 700 }}>
                  {stats.total - stats.done} remaining
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Lab status strip — control panel */}
      <div className="fade-in-up stagger-1 mb-24">
        <div className="lab-status-strip">
          <div className="lab-status-cell">
            <div className="cell-label">Authorized Target</div>
            <div className="cell-value mono">{COURSE.target}</div>
          </div>
          <div className="lab-status-cell">
            <div className="cell-label">Target Application</div>
            <div className="cell-value">{COURSE.targetName}</div>
          </div>
          <div className="lab-status-cell">
            <div className="cell-label">Scope</div>
            <div className="cell-value">
              <span className="status-pill lab">{AUTHORIZATION.scope}</span>
            </div>
          </div>
          <div className="lab-status-cell">
            <div className="cell-label">Lab Status</div>
            <div className="cell-value">
              <span className="status-pill active">
                <span className="dot" style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--orange-500)' }} />
                Ready
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-4 mb-24">
        <div className="fade-in-up stagger-1"><StatCard icon="blue" label="Exercises completed" value={`${stats.done}/${stats.total}`} sub="of 7 total" /></div>
        <div className="fade-in-up stagger-2"><StatCard icon="orange" label="Checklist items done" value={`${stats.checklistDone}/${stats.checklistTotal}`} sub="across all exercises" /></div>
        <div className="fade-in-up stagger-3"><StatCard icon="blue" label="Evidence items ready" value={`${stats.evidenceDone}/${stats.evidenceTotal}`} sub="for submission" /></div>
        <div className="fade-in-up stagger-4"><StatCard icon="orange" label="Course level" value={COURSE.level} sub={COURSE.duration} /></div>
      </div>

      {/* Lab achievements strip */}
      <div className="card card-pad fade-in-up stagger-2 mb-24">
        <div className="flex-between" style={{ flexWrap: 'wrap', gap: 16 }}>
          <div className="flex-center gap-16">
            <div className="stat-icon orange" style={{ width: 48, height: 48 }}>
              <Icon name="award" size={22} />
            </div>
            <div>
              <div style={{ fontWeight: 800, fontSize: 15.5, color: 'var(--text-1)', letterSpacing: '0.4px' }}>
                LAB ACHIEVEMENTS
              </div>
              <div className="text-small" style={{ color: 'var(--text-3)', marginTop: 2 }}>
                {unlockedBadgeCount(state.completed)} / {TOTAL_BADGES} badges unlocked
              </div>
            </div>
          </div>
          <div className="flex-center gap-8" style={{ flexWrap: 'wrap' }}>
            {BADGES.map((b) => {
              const unlocked = isBadgeUnlocked(b, state.completed);
              return (
                <div
                  key={b.id}
                  className={`mini-badge ${unlocked ? 'unlocked' : ''}`}
                  title={`${b.name} — ${unlocked ? 'Unlocked' : 'Locked'}`}
                >
                  <Icon name={unlocked ? b.icon : 'lock'} size={17} />
                </div>
              );
            })}
            <div
              className={`mini-badge master ${isMasterUnlocked(state.completed) ? 'unlocked' : ''}`}
              title={`${MASTER_BADGE.title} — ${isMasterUnlocked(state.completed) ? 'Unlocked' : 'Locked'}`}
            >
              <Icon name={isMasterUnlocked(state.completed) ? 'award' : 'lock'} size={19} />
            </div>
          </div>
          <button className="btn btn-outline btn-sm" onClick={() => navigate('/progress')}>
            View All Achievements
            <Icon name="arrow-right" size={14} />
          </button>
        </div>
      </div>

      {/* Target + next up */}
      <div className="grid grid-2">
        <div className="fade-in-up stagger-2">
          <TargetCard />
        </div>
        <div className="card card-pad fade-in-up stagger-3" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="flex-between mb-16">
            <h3 style={{ fontSize: 16 }}>Up next</h3>
            <Link to="/exercises" className="text-small" style={{ fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 5 }}>
              All exercises <Icon name="arrow-right" size={13} />
            </Link>
          </div>
          <div style={{ flex: 1 }}>
            <div className="exercise-number">EXERCISE {nextUp.number}</div>
            <h3 style={{ fontSize: 19, marginTop: 6 }}>{nextUp.title}</h3>
            <p className="text-muted" style={{ fontSize: 13.5, marginTop: 8 }}>{nextUp.tagline}</p>
            <div className="exercise-meta" style={{ marginTop: 14 }}>
              <span className="badge badge-blue">{nextUp.level}</span>
              <span className="badge badge-gray">
                <Icon name="clock" size={12} /> {nextUp.duration}
              </span>
              <span className="badge badge-gray">{nextUp.module}</span>
            </div>
          </div>
          <button className="btn btn-primary btn-block mt-16" onClick={() => navigate(`/exercises/${nextUp.slug}`)}>
            {stats.done === 0 && nextUp.id === 1 ? 'Start Exercise 01' : 'Open Exercise'}
            <Icon name="arrow-right" size={16} />
          </button>
        </div>
      </div>

      {/* Quick nav */}
      <div className="grid grid-3 mt-24">
        {[
          { to: '/exercises', icon: 'exercises', title: 'Exercises', desc: 'Browse all 7 lab exercises', tone: 'blue' },
          { to: '/evidence', icon: 'evidence', title: 'Evidence', desc: 'Track submission requirements', tone: 'orange' },
          { to: '/progress', icon: 'progress', title: 'Progress', desc: 'View your learning stats', tone: 'blue' },
        ].map((q, i) => (
          <Link key={q.to} to={q.to} style={{ textDecoration: 'none' }} className={`fade-in-up stagger-${i + 1}`}>
            <div className="card card-hover card-pad flex gap-12" style={{ alignItems: 'center' }}>
              <div className={`stat-icon ${q.tone}`} style={{ width: 48, height: 48 }}>
                <Icon name={q.icon} size={22} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 700, fontSize: 15 }}>{q.title}</div>
                <div className="text-small text-muted" style={{ marginTop: 2 }}>{q.desc}</div>
              </div>
              <Icon name="chevron-right" size={18} className="text-muted" />
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
