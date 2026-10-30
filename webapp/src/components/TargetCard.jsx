import Icon from './Icon.jsx';
import { COURSE, AUTHORIZATION } from '../data/exercises.js';

// Prominent authorized-target card shown on the dashboard and lab target page.
export default function TargetCard({ detailed = false }) {
  return (
    <div className="target-card">
      <div className="target-name">
        <Icon name="target" size={26} />
        {COURSE.targetName}
      </div>
      <div>
        <span className="target-url">{COURSE.target}</span>
      </div>
      <div>
        <span className="target-scope">{AUTHORIZATION.scope}</span>
      </div>
      <p>
        This is the only authorized target for the BCSSL Web Application Security Lab — a local
        Docker container running on your own machine. All scanning, inspection, and verification
        activity in this course must be directed exclusively at this URL.
      </p>
      {detailed && (
        <div className="flex gap-16 mt-16" style={{ flexWrap: 'wrap' }}>
          <div>
            <div className="text-small" style={{ color: 'rgba(255,255,255,0.65)', fontWeight: 600 }}>Container</div>
            <div className="mono" style={{ color: '#fff', fontSize: 13, marginTop: 2 }}>bcssl-juice-shop</div>
          </div>
          <div>
            <div className="text-small" style={{ color: 'rgba(255,255,255,0.65)', fontWeight: 600 }}>Port map</div>
            <div className="mono" style={{ color: '#fff', fontSize: 13, marginTop: 2 }}>127.0.0.1:3001 → 3000/tcp</div>
          </div>
          <div>
            <div className="text-small" style={{ color: 'rgba(255,255,255,0.65)', fontWeight: 600 }}>Version</div>
            <div className="mono" style={{ color: '#fff', fontSize: 13, marginTop: 2 }}>v19.2.1</div>
          </div>
          <div>
            <div className="text-small" style={{ color: 'rgba(255,255,255,0.65)', fontWeight: 600 }}>Access</div>
            <div className="mono" style={{ color: '#fff', fontSize: 13, marginTop: 2 }}>Loopback only</div>
          </div>
        </div>
      )}
    </div>
  );
}
