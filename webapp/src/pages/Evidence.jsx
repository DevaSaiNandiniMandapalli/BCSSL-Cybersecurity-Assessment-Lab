import { Link } from 'react-router-dom';
import Icon from '../components/Icon.jsx';
import ProgressBar from '../components/ProgressBar.jsx';
import { EmptyState } from '../components/States.jsx';
import { useProgress } from '../context/ProgressContext.jsx';
import { EXERCISES } from '../data/exercises.js';

export default function Evidence() {
  const { state, toggleEvidenceItem, isCompleted, stats } = useProgress();

  const allDone = stats.evidenceDone === stats.evidenceTotal && stats.evidenceTotal > 0;

  return (
    <div>
      <div className="page-header fade-in-up">
        <div className="page-eyebrow">Submission Area</div>
        <h1 className="page-title">Evidence & Submissions</h1>
        <p className="page-subtitle">
          Track the evidence you must capture for each exercise. All evidence must come from your
          own testing of the authorized target at{' '}
          <span className="mono" style={{ fontWeight: 600 }}>http://localhost:3001</span> — never
          fabricate output or screenshots.
        </p>
      </div>

      {/* Summary */}
      <div className="card card-pad mb-24 fade-in-up stagger-1">
        <div className="flex-between" style={{ flexWrap: 'wrap', gap: 16 }}>
          <div style={{ flex: '1 1 320px', minWidth: 260 }}>
            <div className="flex-between" style={{ marginBottom: 10 }}>
              <span style={{ fontWeight: 700, fontSize: 15 }}>Evidence readiness</span>
              <span className="badge badge-orange">
                {stats.evidenceDone}/{stats.evidenceTotal} items
              </span>
            </div>
            <ProgressBar value={stats.evidenceTotal ? Math.round((stats.evidenceDone / stats.evidenceTotal) * 100) : 0} size="lg" showLabel={false} />
          </div>
          <div className="flex gap-16" style={{ flexWrap: 'wrap' }}>
            <div className="stat-icon blue" style={{ width: 52, height: 52 }}>
              <Icon name="camera" size={24} />
            </div>
            <div>
              <div style={{ fontWeight: 800, fontSize: 20 }}>{stats.evidenceDone}</div>
              <div className="text-small text-muted">evidence items captured</div>
            </div>
            <div className="stat-icon orange" style={{ width: 52, height: 52 }}>
              <Icon name="award" size={24} />
            </div>
            <div>
              <div style={{ fontWeight: 800, fontSize: 20 }}>{stats.done}/7</div>
              <div className="text-small text-muted">exercises completed</div>
            </div>
          </div>
        </div>
        {allDone && (
          <div className="callout callout-blue mt-16" style={{ marginTop: 18, marginBottom: 0 }}>
            <Icon name="check-circle" size={18} />
            <span>
              <strong>All evidence requirements tracked.</strong> Organize your files using the{' '}
              <span className="mono">exercise&lt;NN&gt;-&lt;description&gt;-&lt;sequence&gt;.png</span>{' '}
              naming pattern and compile your lab report — see Exercise 07.
            </span>
          </div>
        )}
      </div>

      {/* Per-exercise evidence */}
      {EXERCISES.map((exercise, ei) => {
        const evState = state.evidence[exercise.id] || {};
        const done = exercise.evidence.filter((_, i) => evState[i]).length;
        const complete = isCompleted(exercise.id);

        return (
          <div className="card mb-16 fade-in-up" key={exercise.id} style={{ animationDelay: `${ei * 0.04}s` }}>
            <div className="card-header">
              <div className="flex-center gap-12">
                <div className={`stat-icon ${complete ? 'blue' : 'orange'}`} style={{ width: 40, height: 40 }}>
                  <Icon name={complete ? 'check-circle' : exercise.icon} size={19} />
                </div>
                <div>
                  <div className="card-title">
                    Exercise {exercise.number} — {exercise.title}
                  </div>
                  <div className="card-subtitle">
                    {done}/{exercise.evidence.length} evidence items captured
                  </div>
                </div>
              </div>
              <div className="flex-center gap-12">
                <div style={{ width: 110 }}>
                  <ProgressBar
                    value={exercise.evidence.length ? Math.round((done / exercise.evidence.length) * 100) : 0}
                    size="sm"
                    showLabel={false}
                  />
                </div>
                <Link to={`/exercises/${exercise.slug}`} className="btn btn-outline btn-sm" style={{ textDecoration: 'none' }}>
                  Open
                </Link>
              </div>
            </div>
            <div style={{ padding: '18px 24px' }}>
              <ul className="checklist">
                {exercise.evidence.map((item, i) => {
                  const checked = !!evState[i];
                  return (
                    <li key={i} className={checked ? 'checked' : ''} onClick={() => toggleEvidenceItem(exercise.id, i)}>
                      <span className="check-box">
                        {checked && <Icon name="check" size={13} strokeWidth={3} />}
                      </span>
                      {item}
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>
        );
      })}

      {/* Naming conventions */}
      <div className="card card-pad mt-24 fade-in-up">
        <h3 style={{ fontSize: 16, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="file-text" size={18} className="text-blue" />
          Naming Conventions
        </h3>
        <p className="text-muted" style={{ fontSize: 13.5, marginBottom: 14 }}>
          Use the pattern <span className="mono" style={{ fontWeight: 600 }}>exercise&lt;NN&gt;-&lt;description&gt;-&lt;sequence&gt;.png</span>:
        </p>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Filename</th>
                <th>Contents</th>
              </tr>
            </thead>
            <tbody>
              {[
                ['exercise01-console-output-01.png', 'Full scan console output'],
                ['exercise02-curl-headers-01.png', 'curl response headers'],
                ['exercise02-comparison-table-01.png', 'Header comparison table'],
                ['exercise03-browser-verification-01.png', 'Discovered path in browser'],
                ['exercise04-page-source-01.png', 'Root page HTML source'],
                ['exercise06-burp-intercept-01.png', 'Burp intercepted request'],
                ['exercise06-burp-response-headers-01.png', 'Burp response headers'],
              ].map(([name, desc]) => (
                <tr key={name}>
                  <td className="mono" style={{ fontWeight: 600, color: 'var(--blue-700)' }}>{name}</td>
                  <td>{desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="callout callout-orange mt-24 fade-in-up">
        <Icon name="alert-triangle" size={18} />
        <span>
          <strong>Evidence honesty:</strong> every screenshot must be clear, readable, show the
          target URL, be complete and unedited. Fabricating evidence is academic dishonesty and may
          result in failing the course and further disciplinary action.
        </span>
      </div>

      {stats.evidenceDone === 0 && (
        <div className="mt-24">
          <EmptyState
            icon="camera"
            tone="orange"
            title="No evidence tracked yet"
            message="Open each exercise, capture the required screenshots and files, then check them off here to build your submission."
            actionLabel="Go to Exercises"
            onAction={() => (window.location.hash = '#/exercises')}
          />
        </div>
      )}
    </div>
  );
}
