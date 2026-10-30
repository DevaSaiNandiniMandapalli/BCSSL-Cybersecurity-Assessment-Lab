import { useEffect, useMemo, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import Icon from '../components/Icon.jsx';
import CodeBlock from '../components/CodeBlock.jsx';
import BadgeModal from '../components/BadgeModal.jsx';
import ValidationDialog from '../components/ValidationDialog.jsx';
import { StatusBadge, LevelBadge, DurationBadge } from '../components/StatusBadge.jsx';
import { ErrorState } from '../components/States.jsx';
import { useProgress } from '../context/ProgressContext.jsx';
import { EXERCISES } from '../data/exercises.js';
import { BADGES, MASTER_BADGE, isMasterUnlocked } from '../data/achievements.js';
import QuestionField from '../components/QuestionField.jsx';

function Callout({ type = 'blue', children }) {
  const icons = { blue: 'info', orange: 'alert-triangle', danger: 'alert-octagon' };
  return (
    <div className={`callout callout-${type}`}>
      <Icon name={icons[type]} size={18} />
      <span>{children}</span>
    </div>
  );
}

function BackgroundSection({ section }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <h3>{section.heading}</h3>
      {section.paragraphs?.map((p, i) => <p key={i}>{p}</p>)}
      {section.list && (
        <ul>
          {section.list.map((item, i) => (
            <li key={i}>{item}</li>
          ))}
        </ul>
      )}
      {section.table && (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                {section.table.headers.map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {section.table.rows.map((row, i) => (
                <tr key={i}>
                  {row.map((cell, j) => (
                    <td key={j} className={j === 0 ? 'mono' : ''} style={j === 0 ? { fontWeight: 600, color: 'var(--blue-700)' } : {}}>
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {section.after?.map((p, i) => <p key={`a-${i}`}>{p}</p>)}
    </div>
  );
}

export default function ExerciseDetail() {
  const { slug } = useParams();
  const navigate = useNavigate();
  const {
    isUnlocked,
    isCompleted,
    completeExercise,
    uncompleteExercise,
    state,
    toggleChecklistItem,
    saveAnswer,
    checkAnswer,
    resetCheck,
    toggleEvidenceItem,
    showToast,
  } = useProgress();

  const exercise = useMemo(() => EXERCISES.find((e) => e.slug === slug), [slug]);
  const [validating, setValidating] = useState(false);
  const [unlockedBadge, setUnlockedBadge] = useState(null);

  useEffect(() => {
    window.scrollTo({ top: 0 });
    setValidating(false);
  }, [slug]);

  if (!exercise) {
    return (
      <ErrorState
        title="Exercise not found"
        message="The exercise you are looking for does not exist in this course."
        actionLabel="Back to Exercises"
        onAction={() => navigate('/exercises')}
      />
    );
  }

  const unlocked = isUnlocked(exercise.id);
  const completed = isCompleted(exercise.id);
  const prev = EXERCISES.find((e) => e.id === exercise.id - 1);
  const next = EXERCISES.find((e) => e.id === exercise.id + 1);

  if (!unlocked) {
    return (
      <ErrorState
        title={`Exercise ${exercise.number} is locked`}
        message={
          <>
            Complete <strong>Exercise {prev.number} — {prev.title}</strong> to unlock this exercise.
            The lab is designed as a progressive sequence.
          </>
        }
        actionLabel={`Go to Exercise ${prev.number}`}
        onAction={() => navigate(`/exercises/${prev.slug}`)}
      />
    );
  }

  const checklistState = state.checklist[exercise.id] || {};
  const checklistDone = exercise.checklist.filter((_, i) => checklistState[i]).length;
  const evidenceState = state.evidence[exercise.id] || {};
  const evidenceDone = exercise.evidence.filter((_, i) => evidenceState[i]).length;

  // Called ONLY by the validation dialog after requirements pass.
  const handleComplete = () => {
    completeExercise(exercise.id);
    setValidating(false);
    // Award the badge tied to this exercise's completion (derived state,
    // never fabricated). Exercise 07 also surfaces the Master Badge.
    if (exercise.id === 7 && isMasterUnlocked([...state.completed, exercise.id])) {
      setUnlockedBadge(MASTER_BADGE);
    } else {
      setUnlockedBadge(BADGES.find((b) => b.exerciseId === exercise.id) || null);
    }
  };

  return (
    <div>
      {/* Breadcrumb */}
      <div className="flex-center gap-8 mb-16 fade-in-up" style={{ justifyContent: 'flex-start' }}>
        <Link to="/exercises" className="text-small" style={{ fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 5 }}>
          <Icon name="chevron-left" size={14} /> All exercises
        </Link>
        <span className="text-muted text-small">/</span>
        <span className="text-small text-muted">Exercise {exercise.number}</span>
      </div>

      {/* Header */}
      <div className="card card-pad mb-24 fade-in-up">
        <div className="flex-between" style={{ flexWrap: 'wrap', gap: 14 }}>
          <div style={{ flex: '1 1 420px', minWidth: 280 }}>
            <div className="exercise-number">EXERCISE {exercise.number} — {exercise.module.toUpperCase()}</div>
            <h1 style={{ fontSize: 26, fontWeight: 800, letterSpacing: '-0.4px', marginTop: 8 }}>
              {exercise.title}
            </h1>
            <p className="text-muted" style={{ marginTop: 8, fontSize: 14.5 }}>{exercise.tagline}</p>
            <div className="exercise-meta" style={{ marginTop: 14 }}>
              <StatusBadge status={completed ? 'completed' : 'unlocked'} />
              <LevelBadge level={exercise.level} />
              <DurationBadge duration={exercise.duration} />
            </div>
          </div>
          <div style={{ flexShrink: 0 }}>
            <div className={`stat-icon ${completed ? 'blue' : 'orange'}`} style={{ width: 64, height: 64, borderRadius: 16 }}>
              <Icon name={completed ? 'check-circle' : exercise.icon} size={30} />
            </div>
          </div>
        </div>
      </div>

      {/* Authorization reminder */}
      <Callout type="orange">
        <span>
          <strong>Authorization reminder:</strong> you are authorized to test ONLY the local Juice
          Shop instance at <span className="mono" style={{ fontWeight: 600 }}>http://localhost:3001</span>.
          Do not scan, test, or inspect any other IP address, hostname, or URL.
        </span>
      </Callout>

      {/* Learning objectives */}
      <section className="content-section fade-in-up">
        <h2><span className="sec-num">01</span> Learning Objectives</h2>
        <div className="card card-pad">
          <ul style={{ margin: 0, paddingLeft: 20 }}>
            {exercise.objectives.map((obj, i) => (
              <li key={i} style={{ marginBottom: 8, fontSize: 14.5, color: 'var(--text-2)' }}>{obj}</li>
            ))}
          </ul>
        </div>
      </section>

      {/* Background */}
      <section className="content-section fade-in-up">
        <h2><span className="sec-num">02</span> Background</h2>
        <div className="card card-pad">
          {exercise.background.map((section, i) => (
            <BackgroundSection key={i} section={section} />
          ))}
        </div>
      </section>

      {/* Tasks */}
      <section className="content-section fade-in-up">
        <h2><span className="sec-num">03</span> Tasks</h2>
        {exercise.tasks.map((task, i) => (
          <div className="card card-pad mb-16" key={i}>
            <div className="flex-between">
              <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
                <span className="badge badge-blue" style={{ fontSize: 12 }}>Task {i + 1}</span>
                {task.title}
              </h3>
            </div>
            <ul style={{ marginTop: 12 }}>
              {task.steps.map((step, j) => (
                <li key={j} style={{ marginBottom: 6 }}>{step}</li>
              ))}
            </ul>
            {task.code?.map((block, k) => <CodeBlock key={k} code={block.code} label={block.label} />)}
          </div>
        ))}
      </section>

      {/* Questions */}
      <section className="content-section fade-in-up">
        <h2><span className="sec-num">04</span> Answer the questions below</h2>
        <div className="card card-pad">
          <p className="text-muted" style={{ fontSize: 13.5, marginBottom: 18 }}>
            Answer each question and click Check for immediate feedback. Your answers are saved
            locally in this browser.
          </p>
          {exercise.questions.map((q, i) => (
            <QuestionField
              key={i}
              id={exercise.id}
              index={i}
              question={q}
              answer={state.answers[exercise.id]?.[i] || ''}
              checked={state.checked[exercise.id]?.[i]}
              onSave={(value) => saveAnswer(exercise.id, i, value)}
              onCheck={(passed) => checkAnswer(exercise.id, i, passed)}
              onResetCheck={() => resetCheck(exercise.id, i)}
            />
          ))}
        </div>
      </section>

      {/* Evidence */}
      <section className="content-section fade-in-up">
        <h2><span className="sec-num">05</span> Evidence Acknowledgement</h2>
        <div className="card card-pad">
          <p className="text-muted" style={{ fontSize: 13.5, marginBottom: 16 }}>
            Confirm that you have captured each evidence item for your submission.
            The platform tracks your acknowledgement — you are responsible for creating the actual files.
          </p>
          <div className="flex-between mb-16">
            <span className="text-small text-muted" style={{ fontWeight: 600 }}>
              {evidenceDone}/{exercise.evidence.length} items acknowledged
            </span>
            {evidenceDone === exercise.evidence.length && exercise.evidence.length > 0 && (
              <span className="badge badge-blue">
                <Icon name="check" size={12} /> All required evidence acknowledged
              </span>
            )}
          </div>
          <ul className="checklist">
            {exercise.evidence.map((item, i) => {
              const acknowledged = !!evidenceState[i];
              return (
                <li key={i} className={acknowledged ? 'checked' : ''} onClick={() => toggleEvidenceItem(exercise.id, i)}>
                  <span className="check-box">
                    {acknowledged && <Icon name="check" size={13} strokeWidth={3} />}
                  </span>
                  <div style={{ flex: 1 }}>
                    <span className="text-small text-muted" style={{ fontWeight: 600 }}>E{i + 1}</span>
                    <div style={{ marginTop: 2 }}>{item}</div>
                  </div>
                  <span className={`badge ${acknowledged ? 'badge-blue' : 'badge-gray'}`} style={{ flexShrink: 0 }}>
                    {acknowledged ? '✓ Acknowledged' : 'Confirm evidence'}
                  </span>
                </li>
              );
            })}
          </ul>
          <p className="text-small text-muted" style={{ marginTop: 12 }}>
            Track your evidence on the <Link to="/evidence">Evidence page</Link>.
          </p>
        </div>
      </section>

      {/* Completion checklist */}
      <section className="content-section fade-in-up">
        <h2><span className="sec-num">06</span> Completion Checklist</h2>
        <div className="card card-pad">
          <div className="flex-between mb-16">
            <span className="text-small text-muted" style={{ fontWeight: 600 }}>
              {checklistDone}/{exercise.checklist.length} items checked
            </span>
            {checklistDone === exercise.checklist.length && exercise.checklist.length > 0 && (
              <span className="badge badge-blue">
                <Icon name="check" size={12} /> All items done
              </span>
            )}
          </div>
          <ul className="checklist">
            {exercise.checklist.map((item, i) => {
              const checked = !!checklistState[i];
              return (
                <li key={i} className={checked ? 'checked' : ''} onClick={() => toggleChecklistItem(exercise.id, i)}>
                  <span className="check-box">
                    {checked && <Icon name="check" size={13} strokeWidth={3} />}
                  </span>
                  {item}
                </li>
              );
            })}
          </ul>
        </div>
      </section>

      {/* Mark complete */}
      <section className="content-section fade-in-up">
        <div className="card card-pad" style={{ background: completed ? 'var(--callout-blue-bg)' : 'var(--bg-surface)', borderColor: completed ? 'var(--callout-blue-border)' : 'var(--border)' }}>
          <div className="flex-between" style={{ flexWrap: 'wrap', gap: 16 }}>
            <div>
              <h3 style={{ fontSize: 17, color: 'var(--text-1)' }}>{completed ? 'Exercise completed' : 'Finished this exercise?'}</h3>
              <p style={{ fontSize: 14, marginTop: 6, color: 'var(--text-2)' }}>
                {completed
                  ? `You marked this complete. ${next ? `Exercise ${next.number} is now unlocked.` : 'You have finished the entire course!'}`
                  : next
                    ? `Marking this complete will unlock Exercise ${next.number} — ${next.title}.`
                    : 'Marking this complete will finish the course. Well done!'}
              </p>
            </div>
            <div className="flex gap-12">
              {completed && (
                <button
                  className="btn btn-outline"
                  onClick={() => {
                    uncompleteExercise(exercise.id);
                    showToast(`Exercise ${exercise.number} marked as not completed`, 'info');
                  }}
                >
                  <Icon name="refresh" size={15} />
                  Reopen
                </button>
              )}
              {!completed && (
                <button className="btn btn-primary btn-lg" onClick={() => setValidating(true)}>
                  <Icon name="check-circle" size={17} />
                  Mark as Complete
                </button>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* Prev / next */}
      <div className="flex-between mt-24" style={{ flexWrap: 'wrap', gap: 12 }}>
        {prev ? (
          <Link to={`/exercises/${prev.slug}`} className="btn btn-outline" style={{ textDecoration: 'none' }}>
            <Icon name="chevron-left" size={16} />
            Exercise {prev.number} — {prev.title}
          </Link>
        ) : (
          <span />
        )}
        {next ? (
          <Link
            to={isUnlocked(next.id) ? `/exercises/${next.slug}` : '#'}
            className={`btn ${isUnlocked(next.id) ? 'btn-blue' : 'btn-outline'}`}
            style={{ textDecoration: 'none', opacity: isUnlocked(next.id) ? 1 : 0.85 }}
            onClick={(e) => {
              if (!isUnlocked(next.id)) {
                e.preventDefault();
                showToast(`Complete Exercise ${exercise.number} to unlock Exercise ${next.number}`, 'error');
              }
            }}
          >
            Next: Exercise {next.number} — {next.title}
            <Icon name="chevron-right" size={16} />
          </Link>
        ) : (
          <Link to="/evidence" className="btn btn-blue" style={{ textDecoration: 'none' }}>
            <Icon name="flag" size={16} />
            Finish course — go to Evidence
          </Link>
        )}
      </div>

      {validating && (
        <ValidationDialog
          exercise={exercise}
          onClose={() => setValidating(false)}
          onComplete={handleComplete}
        />
      )}

      {unlockedBadge && (
        <BadgeModal
          badge={unlockedBadge}
          isMaster={unlockedBadge.id === 'master'}
          nextExercise={next}
          onClose={() => setUnlockedBadge(null)}
        />
      )}
    </div>
  );
}
