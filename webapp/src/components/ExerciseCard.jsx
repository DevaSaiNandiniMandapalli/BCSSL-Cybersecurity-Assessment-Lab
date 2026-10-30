import { Link } from 'react-router-dom';
import Icon from './Icon.jsx';
import { StatusBadge, LevelBadge, DurationBadge } from './StatusBadge.jsx';
import { useProgress } from '../context/ProgressContext.jsx';
import { BADGES, isBadgeUnlocked } from '../data/achievements.js';

export default function ExerciseCard({ exercise, index = 0 }) {
  const { isUnlocked, isCompleted, state } = useProgress();
  const unlocked = isUnlocked(exercise.id);
  const completed = isCompleted(exercise.id);
  const status = completed ? 'completed' : unlocked ? 'unlocked' : 'locked';
  const badge = BADGES.find((b) => b.exerciseId === exercise.id);
  const badgeEarned = badge ? isBadgeUnlocked(badge, state.completed) : false;

  return (
    <div
      className={`card card-hover exercise-card fade-in-up stagger-${Math.min(index + 1, 4)} ${status}`}
    >
      {!unlocked && <div className="lock-ribbon">Locked</div>}

      <div className="exercise-card-top">
        <div style={{ flex: 1 }}>
          <div className="exercise-number">EXERCISE {exercise.number}</div>
          <h3>{exercise.title}</h3>
          <p className="exercise-tagline">{exercise.tagline}</p>
        </div>
        <div style={{ flexShrink: 0, marginTop: 4 }}>
          {completed ? (
            <span className="stat-icon blue" style={{ width: 42, height: 42 }}>
              <Icon name="check-circle" size={22} />
            </span>
          ) : unlocked ? (
            <span className="stat-icon orange" style={{ width: 42, height: 42 }}>
              <Icon name={exercise.icon} size={22} />
            </span>
          ) : (
            <span className="stat-icon gray" style={{ width: 42, height: 42 }}>
              <Icon name="lock" size={20} />
            </span>
          )}
        </div>
      </div>

      <div className="exercise-card-body">
        <div className="exercise-meta">
          <StatusBadge status={status} />
          <LevelBadge level={exercise.level} />
          <DurationBadge duration={exercise.duration} />
          <span className="badge badge-gray">{exercise.module}</span>
        </div>

        {completed && badgeEarned && (
          <div className="badge-earned-strip">
            <Icon name="award" size={14} />
            <span>BADGE EARNED</span>
            <strong>{badge.name}</strong>
          </div>
        )}

        <div className="exercise-card-actions">
          {unlocked ? (
            <Link to={`/exercises/${exercise.slug}`} className="btn btn-primary btn-sm" style={{ textDecoration: 'none' }}>
              {completed ? 'Review' : 'Open Exercise'}
              <Icon name="arrow-right" size={15} />
            </Link>
          ) : (
            <span className="text-small text-muted flex-center gap-8">
              <Icon name="lock" size={14} />
              Complete Exercise {String(exercise.id - 1).padStart(2, '0')} to unlock
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
