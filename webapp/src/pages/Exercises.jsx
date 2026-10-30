import Icon from '../components/Icon.jsx';
import ProgressBar from '../components/ProgressBar.jsx';
import ExerciseCard from '../components/ExerciseCard.jsx';
import { useProgress } from '../context/ProgressContext.jsx';
import { EXERCISES, COURSE } from '../data/exercises.js';

export default function Exercises() {
  const { stats } = useProgress();

  return (
    <div>
      <div className="page-header fade-in-up">
        <div className="page-eyebrow">{COURSE.title}</div>
        <h1 className="page-title">Exercises</h1>
        <p className="page-subtitle">
          Seven progressive exercises — from running your first scan to compiling a professional
          evidence submission. Each exercise unlocks when the previous one is marked complete.
        </p>
      </div>

      <div className="card card-pad mb-24 fade-in-up stagger-1">
        <div className="flex-between" style={{ marginBottom: 12, flexWrap: 'wrap', gap: 10 }}>
          <div>
            <div style={{ fontWeight: 700, fontSize: 15 }}>Overall progress</div>
            <div className="text-small text-muted" style={{ marginTop: 2 }}>
              {stats.done} of {stats.total} exercises complete
            </div>
          </div>
          <span className="badge badge-orange" style={{ fontSize: 13, padding: '7px 16px' }}>
            {stats.pct}%
          </span>
        </div>
        <ProgressBar value={stats.pct} size="lg" showLabel={false} />
      </div>

      <div className="grid grid-2">
        {EXERCISES.map((exercise, i) => (
          <ExerciseCard key={exercise.id} exercise={exercise} index={i} />
        ))}
      </div>

      <div className="callout callout-blue mt-24 fade-in-up">
        <Icon name="info" size={18} />
        <span>
          <strong>How unlocking works:</strong> Exercise 01 is unlocked by default. Complete an
          exercise by opening it and pressing <strong>Mark as Complete</strong> at the bottom —
          the next exercise in the sequence will unlock automatically. Your progress is saved
          locally in this browser.
        </span>
      </div>
    </div>
  );
}
