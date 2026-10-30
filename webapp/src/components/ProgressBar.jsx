export default function ProgressBar({ value = 0, size = '', showLabel = true, label }) {
  const clamped = Math.max(0, Math.min(100, value));
  return (
    <div style={{ width: '100%' }}>
      {showLabel && (
        <div className="flex-between mb-16" style={{ marginBottom: 8 }}>
          <span className="text-small text-muted" style={{ fontWeight: 600 }}>
            {label || 'Progress'}
          </span>
          <span className="text-small text-orange" style={{ fontWeight: 700 }}>
            {clamped}%
          </span>
        </div>
      )}
      <div className={`progress-track ${size}`} role="progressbar" aria-valuenow={clamped} aria-valuemin={0} aria-valuemax={100}>
        <div className="progress-fill" style={{ width: `${clamped}%` }} />
      </div>
    </div>
  );
}
