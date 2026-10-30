import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Icon from './Icon.jsx';

// Polished exercise completion celebration modal.
//
// Shows a confetti/sparkle animation, the earned badge with reveal animation,
// and a continue button. The badge is derived from exercise completion
// state — nothing is fabricated here.
//
// variant="master" renders the prominent Master Badge celebration
// (awarded after Exercise 07 when all 7 exercises are complete).

function Confetti() {
  const pieces = Array.from({ length: 40 }, (_, i) => {
    const colors = ['#f97316', '#3b82f6', '#10b981', '#fbbf24', '#8b5cf6', '#ef4444'];
    const color = colors[i % colors.length];
    const left = Math.random() * 100;
    const delay = Math.random() * 0.8;
    const duration = 2 + Math.random() * 2;
    const size = 6 + Math.random() * 8;
    const rotation = Math.random() * 360;
    return (
      <div
        key={i}
        className="confetti-piece"
        style={{
          left: `${left}%`,
          animationDelay: `${delay}s`,
          animationDuration: `${duration}s`,
          width: size,
          height: size * 0.4,
          background: color,
          transform: `rotate(${rotation}deg)`,
        }}
      />
    );
  });
  return <div className="confetti-container">{pieces}</div>;
}

function Sparkles() {
  const sparkles = Array.from({ length: 12 }, (_, i) => {
    const angle = (i / 12) * 360;
    const distance = 80 + Math.random() * 60;
    const x = Math.cos((angle * Math.PI) / 180) * distance;
    const y = Math.sin((angle * Math.PI) / 180) * distance;
    const delay = 0.3 + Math.random() * 0.5;
    return (
      <div
        key={i}
        className="sparkle-piece"
        style={{
          '--sx': `${x}px`,
          '--sy': `${y}px`,
          animationDelay: `${delay}s`,
        }}
      />
    );
  });
  return <div className="sparkles-container">{sparkles}</div>;
}

export default function BadgeModal({ badge, isMaster = false, nextExercise, onClose }) {
  const navigate = useNavigate();
  const [showConfetti, setShowConfetti] = useState(true);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  useEffect(() => {
    const timer = setTimeout(() => setShowConfetti(false), 4000);
    return () => clearTimeout(timer);
  }, []);

  if (!badge) return null;

  const handleContinue = () => {
    onClose();
    if (isMaster) {
      navigate('/progress');
    } else if (nextExercise) {
      navigate(`/exercises/${nextExercise.slug}`);
    } else {
      navigate('/progress');
    }
  };

  return (
    <div className="badge-modal-overlay" onClick={onClose} role="dialog" aria-modal="true" aria-label="Exercise complete">
      <div
        className={`badge-modal ${isMaster ? 'badge-modal-master' : ''}`}
        onClick={(e) => e.stopPropagation()}
      >
        {showConfetti && <Confetti />}
        <Sparkles />

        <button className="badge-modal-close" onClick={onClose} aria-label="Close">
          <Icon name="x" size={18} />
        </button>

        <div className="badge-modal-icon-wrap">
          <div className="badge-modal-ring" />
          <div className={`badge-modal-icon ${isMaster ? 'master' : ''}`}>
            <Icon name={badge.icon} size={isMaster ? 44 : 38} strokeWidth={1.7} />
          </div>
        </div>

        <div className="badge-modal-eyebrow">
          {isMaster ? 'MASTER BADGE EARNED' : `EXERCISE ${badge.number} COMPLETE!`}
        </div>
        <h2 className="badge-modal-name">{isMaster ? 'LAB COMPLETE!' : badge.name}</h2>
        <p className="badge-modal-desc">
          {isMaster
            ? 'Congratulations! You completed all 7 exercises.'
            : badge.description}
        </p>

        {isMaster && (
          <div className="master-summary">
            <div className="master-summary-item">
              <Icon name="check-circle" size={16} />
              <span>7/7 exercises completed</span>
            </div>
            <div className="master-summary-item">
              <Icon name="check-circle" size={16} />
              <span>Questions completed</span>
            </div>
            <div className="master-summary-item">
              <Icon name="check-circle" size={16} />
              <span>Checklists completed</span>
            </div>
            <div className="master-summary-item">
              <Icon name="check-circle" size={16} />
              <span>Evidence acknowledged</span>
            </div>
            <div className="master-summary-item">
              <Icon name="check-circle" size={16} />
              <span>All exercise badges earned</span>
            </div>
          </div>
        )}

        <button className={`btn btn-lg ${isMaster ? 'btn-primary' : 'btn-blue'} btn-block`} onClick={handleContinue}>
          {isMaster ? 'View Your Achievements' : `Continue to Exercise ${nextExercise ? nextExercise.number : ''}`}
          <Icon name="arrow-right" size={17} />
        </button>
      </div>
    </div>
  );
}
