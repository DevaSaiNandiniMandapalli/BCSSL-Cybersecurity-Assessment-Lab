import { Link } from 'react-router-dom';
import Icon from '../components/Icon.jsx';
import ProgressBar from '../components/ProgressBar.jsx';
import { StatusBadge } from '../components/StatusBadge.jsx';
import { EmptyState } from '../components/States.jsx';
import { useProgress } from '../context/ProgressContext.jsx';
import { EXERCISES, COURSE } from '../data/exercises.js';
import {
  BADGES,
  MASTER_BADGE,
  TOTAL_BADGES,
  isBadgeUnlocked,
  isMasterUnlocked,
  unlockedBadgeCount,
  formatCompletionDate,
} from '../data/achievements.js';

function ProgressRing({ pct }) {
  const r = 52;
  const circ = 2 * Math.PI * r;
  const offset = circ - (pct / 100) * circ;
  return (
    <div style={{ position: 'relative', width: 130, height: 130 }}>
      <svg width="130" height="130" viewBox="0 0 130 130">
        <circle cx="65" cy="65" r={r} fill="none" stroke="var(--border)" strokeWidth="11" />
        <circle
          cx="65"
          cy="65"
          r={r}
          fill="none"
          stroke="url(#ringGrad)"
          strokeWidth="11"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          transform="rotate(-90 65 65)"
          style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.22, 1, 0.36, 1)' }}
        />
        <defs>
          <linearGradient id="ringGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="var(--orange-400)" />
            <stop offset="100%" stopColor="var(--orange-600)" />
          </linearGradient>
        </defs>
      </svg>
      <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <span style={{ fontSize: 26, fontWeight: 800, letterSpacing: '-0.5px', color: 'var(--text-1)' }}>{pct}%</span>
        <span style={{ fontSize: 12.5, color: 'var(--text-3)', fontWeight: 500 }}>complete</span>
      </div>
    </div>
  );
}

function ExerciseBadgeCard({ badge, completed, completedAt, index }) {
  const unlocked = isBadgeUnlocked(badge, completed);
  const date = formatCompletionDate(completedAt[badge.exerciseId]);

  return (
    <div
      className={`badge-item fade-in-up stagger-${Math.min((index % 4) + 1, 4)} ${unlocked ? 'unlocked' : 'locked'}`}
    >
      <div className="badge-item-icon">
        <Icon name={unlocked ? badge.icon : 'lock'} size={26} strokeWidth={1.7} />
      </div>
      <div className="badge-item-body">
        <div className="badge-item-number">EXERCISE {badge.number}</div>
        <div className="badge-item-name">{badge.name}</div>
        <div className="badge-item-status">
          {unlocked ? (
            <>
              <Icon name="check-circle" size={13} />
              EARNED{date ? ` · ${date}` : ''}
            </>
          ) : (
            <>
              <Icon name="lock" size={12} />
              LOCKED · Complete Exercise {badge.number}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function MasterBadgeCard({ completed, completedAt }) {
  const unlocked = isMasterUnlocked(completed);
  const lastDate = formatCompletionDate(completedAt[7]);

  return (
    <div className={`badge-item master fade-in-up ${unlocked ? 'unlocked' : 'locked'}`}>
      <div className="badge-item-icon">
        <Icon name={unlocked ? 'award' : 'lock'} size={34} strokeWidth={1.6} />
      </div>
      <div className="badge-item-body">
        <div className="badge-item-master-label">MASTER BADGE</div>
        <div className="badge-item-name">{MASTER_BADGE.name}</div>
        <div className="badge-item-status">
          {unlocked ? (
            <>
              <Icon name="check-circle" size={13} />
              EARNED{lastDate ? ` · ${lastDate}` : ''}
            </>
          ) : (
            <>
              <Icon name="lock" size={12} />
              LOCKED · Complete all 7 exercises
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default function Progress() {
  const { stats, state, isCompleted, isUnlocked } = useProgress();
  const { completed, completedAt } = state;

  const milestones = [
    { label: 'First Scan Completed', done: isCompleted(1), icon: 'scanner' },
    { label: 'Headers Analyzed', done: isCompleted(2), icon: 'shield' },
    { label: 'Paths Discovered', done: isCompleted(3), icon: 'radar' },
    { label: 'Injection Concepts Mastered', done: isCompleted(4), icon: 'syringe' },
    { label: 'Configuration Reviewed', done: isCompleted(5), icon: 'sliders' },
    { label: 'Burp Verification Done', done: isCompleted(6), icon: 'crosshair' },
    { label: 'Evidence Compiled', done: isCompleted(7), icon: 'folder' },
  ];

  const earned = unlockedBadgeCount(completed);

  return (
    <div>
      <div className="page-header fade-in-up">
        <div className="page-eyebrow">Your Learning Journey</div>
        <h1 className="page-title">Progress</h1>
        <p className="page-subtitle">
          Track your completion of the {COURSE.title} — exercises, milestones, achievements, and evidence.
        </p>
      </div>

      {/* Overview */}
      <div className="card card-pad mb-24 fade-in-up stagger-1">
        <div className="flex-center" style={{ flexWrap: 'wrap', justifyContent: 'space-around' }}>
          <ProgressRing pct={stats.pct} />
          <div style={{ flex: '1 1 300px', minWidth: 260, display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div className="flex-between">
              <span style={{ fontWeight: 600, color: 'var(--text-2)' }}>Exercises completed</span>
              <span style={{ fontWeight: 800, color: 'var(--text-1)' }}>{stats.done}/{stats.total}</span>
            </div>
            <ProgressBar value={stats.pct} showLabel={false} />
            <div className="flex-between">
              <span style={{ fontWeight: 600, color: 'var(--text-2)' }}>Checklist items</span>
              <span style={{ fontWeight: 800, color: 'var(--text-1)' }}>{stats.checklistDone}/{stats.checklistTotal}</span>
            </div>
            <ProgressBar
              value={stats.checklistTotal ? Math.round((stats.checklistDone / stats.checklistTotal) * 100) : 0}
              showLabel={false}
            />
            <div className="flex-between">
              <span style={{ fontWeight: 600, color: 'var(--text-2)' }}>Evidence items</span>
              <span style={{ fontWeight: 800, color: 'var(--text-1)' }}>{stats.evidenceDone}/{stats.evidenceTotal}</span>
            </div>
            <ProgressBar
              value={stats.evidenceTotal ? Math.round((stats.evidenceDone / stats.evidenceTotal) * 100) : 0}
              showLabel={false}
            />
          </div>
        </div>
      </div>

      {/* Achievements */}
      <div className="flex-between mb-16 fade-in-up stagger-2">
        <h3 style={{ fontSize: 18, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Icon name="award" size={20} className="text-orange" />
          Achievements
        </h3>
        <span className="badge badge-orange" style={{ fontSize: 13, padding: '6px 14px' }}>
          {earned} / {TOTAL_BADGES} unlocked
        </span>
      </div>
      <div className="grid grid-4 mb-24">
        {BADGES.map((badge, i) => (
          <ExerciseBadgeCard key={badge.id} badge={badge} completed={completed} completedAt={completedAt} index={i} />
        ))}
        <MasterBadgeCard completed={completed} completedAt={completedAt} />
      </div>

      {/* Milestones */}
      <h3 style={{ fontSize: 16, marginBottom: 14 }}>Milestones</h3>
      <div className="grid grid-4 mb-24">
        {milestones.map((m, i) => (
          <div
            key={m.label}
            className={`card card-pad milestone-card fade-in-up stagger-${Math.min(i + 1, 4)} ${m.done ? 'done' : ''}`}
            style={{ textAlign: 'center' }}
          >
            <div className="milestone-icon" key={m.done ? 'done' : 'locked'}>
              <Icon name={m.done ? 'check' : m.icon} size={22} />
            </div>
            <div className="milestone-label">{m.label}</div>
            <div className={`milestone-status ${m.done ? 'done' : ''}`}>
              {m.done ? 'COMPLETED' : 'LOCKED'}
            </div>
          </div>
        ))}
      </div>

      {/* Per-exercise status */}
      <h3 style={{ fontSize: 16, marginBottom: 14 }}>Exercise Status</h3>
      {stats.done === 0 ? (
        <EmptyState
          icon="progress"
          tone="blue"
          title="No progress yet"
          message="Start Exercise 01 to begin your learning journey. Your progress and achievements will appear here as you complete exercises."
          actionLabel="Start Exercise 01"
          onAction={() => (window.location.hash = '#/exercises/web-security-scanner')}
        />
      ) : (
        <div className="grid grid-2">
          {EXERCISES.map((ex) => {
            const done = isCompleted(ex.id);
            const unlocked = isUnlocked(ex.id);
            return (
              <Link
                to={unlocked ? `/exercises/${ex.slug}` : '#'}
                key={ex.id}
                style={{ textDecoration: 'none' }}
                onClick={(e) => {
                  if (!unlocked) e.preventDefault();
                }}
              >
                <div className="card card-hover card-pad flex-between" style={{ width: '100%' }}>
                  <div className="flex-center gap-12">
                    <div className={`stat-icon ${done ? 'blue' : unlocked ? 'orange' : 'gray'}`} style={{ width: 42, height: 42 }}>
                      <Icon name={done ? 'check-circle' : unlocked ? ex.icon : 'lock'} size={19} />
                    </div>
                    <div>
                      <div style={{ fontWeight: 700, fontSize: 14.5, color: 'var(--text-1)' }}>
                        {ex.number} — {ex.title}
                      </div>
                      <div className="text-small" style={{ marginTop: 2, color: 'var(--text-3)' }}>
                        {ex.module} · {ex.duration}
                      </div>
                    </div>
                  </div>
                  <StatusBadge status={done ? 'completed' : unlocked ? 'unlocked' : 'locked'} />
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
