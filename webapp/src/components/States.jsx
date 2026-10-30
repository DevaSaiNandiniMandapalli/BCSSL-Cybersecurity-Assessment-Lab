import Icon from './Icon.jsx';

export function EmptyState({ icon = 'folder', title, message, actionLabel, onAction, tone = 'blue' }) {
  return (
    <div className="state-box">
      <div className={`state-icon ${tone}`}>
        <Icon name={icon} size={30} />
      </div>
      <h3>{title}</h3>
      <p>{message}</p>
      {actionLabel && onAction && (
        <button className="btn btn-primary" onClick={onAction}>
          {actionLabel}
        </button>
      )}
    </div>
  );
}

export function ErrorState({ title, message, actionLabel, onAction }) {
  return (
    <div className="state-box" style={{ borderColor: '#fecaca', background: '#fff' }}>
      <div className="state-icon" style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fecaca' }}>
        <Icon name="alert-octagon" size={30} />
      </div>
      <h3>{title}</h3>
      <p>{message}</p>
      {actionLabel && onAction && (
        <button className="btn btn-outline" onClick={onAction}>
          {actionLabel}
        </button>
      )}
    </div>
  );
}

export function SkeletonCard() {
  return (
    <div className="card card-pad">
      <div className="skeleton" style={{ height: 14, width: '30%', marginBottom: 14 }} />
      <div className="skeleton" style={{ height: 20, width: '70%', marginBottom: 10 }} />
      <div className="skeleton" style={{ height: 12, width: '100%', marginBottom: 8 }} />
      <div className="skeleton" style={{ height: 12, width: '85%', marginBottom: 20 }} />
      <div className="skeleton" style={{ height: 36, width: '45%', borderRadius: 10 }} />
    </div>
  );
}

export function SkeletonList({ count = 3 }) {
  return (
    <>
      {Array.from({ length: count }).map((_, i) => (
        <div className="card card-pad" key={i} style={{ marginBottom: 14 }}>
          <div className="skeleton" style={{ height: 16, width: '55%', marginBottom: 10 }} />
          <div className="skeleton" style={{ height: 12, width: '90%' }} />
        </div>
      ))}
    </>
  );
}
