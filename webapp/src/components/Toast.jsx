import Icon from './Icon.jsx';

export default function Toast({ toast }) {
  if (!toast) return null;
  return (
    <div className="toast-stack">
      <div className={`toast toast-${toast.type}`} role="status">
        <span className="toast-icon">
          <Icon
            name={toast.type === 'error' ? 'alert-octagon' : toast.type === 'info' ? 'info' : 'check-circle'}
            size={20}
          />
        </span>
        <span>{toast.message}</span>
      </div>
    </div>
  );
}
