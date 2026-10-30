import Icon from './Icon.jsx';

export default function StatCard({ icon = 'blue', label, value, sub }) {
  return (
    <div className="card card-hover stat-card">
      <div className={`stat-icon ${icon}`}>
        <Icon name={icon === 'blue' ? 'zap' : 'flag'} size={22} />
      </div>
      <div>
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
        {sub && <div className="text-small text-muted" style={{ marginTop: 2 }}>{sub}</div>}
      </div>
    </div>
  );
}
