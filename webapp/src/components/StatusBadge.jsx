import Icon from './Icon.jsx';

export function StatusBadge({ status }) {
  if (status === 'completed') {
    return (
      <span className="badge badge-blue">
        <Icon name="check-circle" size={13} />
        Completed
      </span>
    );
  }
  if (status === 'locked') {
    return (
      <span className="badge badge-gray">
        <Icon name="lock" size={12} />
        Locked
      </span>
    );
  }
  return (
    <span className="badge badge-orange">
      <Icon name="unlock" size={12} />
      Unlocked
    </span>
  );
}

export function LevelBadge({ level }) {
  return <span className="badge badge-blue">{level}</span>;
}

export function DurationBadge({ duration }) {
  return (
    <span className="badge badge-gray">
      <Icon name="clock" size={12} />
      {duration}
    </span>
  );
}
