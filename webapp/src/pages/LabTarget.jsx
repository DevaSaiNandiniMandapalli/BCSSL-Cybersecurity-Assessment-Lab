import Icon from '../components/Icon.jsx';
import CodeBlock from '../components/CodeBlock.jsx';
import TargetCard from '../components/TargetCard.jsx';
import { AUTHORIZATION, COURSE } from '../data/exercises.js';

export default function LabTarget() {
  return (
    <div>
      <div className="page-header fade-in-up">
        <div className="page-eyebrow">Authorized Environment</div>
        <h1 className="page-title">Lab Target</h1>
        <p className="page-subtitle">
          The BCSSL Web Application Security Lab runs against a single, deliberately vulnerable
          target hosted in a local Docker container on your own machine.
        </p>
      </div>

      <div className="fade-in-up stagger-1 mb-24">
        <TargetCard detailed />
      </div>

      <div className="grid grid-2">
        {/* Starting the target */}
        <div className="card card-pad fade-in-up stagger-2">
          <h3 style={{ fontSize: 16, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="server" size={18} className="text-blue" />
            Starting the Target
          </h3>
          <p className="text-muted" style={{ fontSize: 13.5, marginBottom: 8 }}>
            The target runs via Docker Compose from the lab's <span className="mono">target/</span> directory:
          </p>
          <CodeBlock
            label="PowerShell"
            code={`cd C:\\Users\\devas\\Documents\\Cybersecurity\\BCSSL-Student-Web-Security-Lab\\target\ndocker compose up -d\ndocker compose ps`}
          />
          <p className="text-muted" style={{ fontSize: 13.5 }}>
            You should see <span className="mono" style={{ fontWeight: 600 }}>bcssl-juice-shop</span> with
            status <span className="mono" style={{ fontWeight: 600 }}>Up</span> and port mapping{' '}
            <span className="mono" style={{ fontWeight: 600 }}>127.0.0.1:3001-&gt;3000/tcp</span>.
            The healthcheck may take up to 30 seconds to report <span className="mono" style={{ fontWeight: 600 }}>healthy</span>.
          </p>
        </div>

        {/* Verifying the target */}
        <div className="card card-pad fade-in-up stagger-3">
          <h3 style={{ fontSize: 16, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="check-circle" size={18} className="text-orange" />
            Verifying the Target
          </h3>
          <p className="text-muted" style={{ fontSize: 13.5, marginBottom: 8 }}>
            Confirm the application responds before starting any exercise:
          </p>
          <CodeBlock label="PowerShell" code={`curl.exe -I --max-time 10 http://localhost:3001`} />
          <p className="text-muted" style={{ fontSize: 13.5 }}>
            Expect <span className="mono" style={{ fontWeight: 600 }}>HTTP/1.1 200 OK</span>. To check
            container health:
          </p>
          <CodeBlock label="PowerShell" code={`docker inspect --format "{{.Health.Status}}" bcssl-juice-shop`} />
        </div>
      </div>

      {/* Authorization scope */}
      <div className="card card-pad mt-24 fade-in-up">
        <h3 style={{ fontSize: 16, marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="shield" size={18} className="text-blue" />
          Authorization Scope
        </h3>
        <div className="grid grid-2" style={{ gap: 24 }}>
          <div>
            <div className="badge badge-blue mb-16" style={{ marginBottom: 10 }}>You ARE authorized to test</div>
            <ul style={{ paddingLeft: 20, margin: 0 }}>
              {AUTHORIZATION.authorized.map((item, i) => (
                <li key={i} style={{ marginBottom: 8, fontSize: 14, color: 'var(--text-2)', display: 'flex', gap: 8 }}>
                  <Icon name="check" size={15} className="text-blue" style={{ flexShrink: 0, marginTop: 3 }} />
                  {item}
                </li>
              ))}
            </ul>
          </div>
          <div>
            <div className="badge badge-danger mb-16" style={{ marginBottom: 10 }}>Strictly prohibited</div>
            <ul style={{ paddingLeft: 20, margin: 0 }}>
              {AUTHORIZATION.prohibited.map((item, i) => (
                <li key={i} style={{ marginBottom: 8, fontSize: 14, color: 'var(--text-2)', display: 'flex', gap: 8 }}>
                  <Icon name="x" size={15} style={{ color: 'var(--danger-500)', flexShrink: 0, marginTop: 3 }} />
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      <div className="callout callout-danger mt-24 fade-in-up">
        <Icon name="alert-octagon" size={18} />
        <span>
          <strong>When in doubt, ask.</strong> If you are unsure whether a target or activity is
          authorized, stop and ask your instructor before proceeding. Unauthorized scanning may
          violate applicable law and institutional policy, and may result in criminal charges and
          academic disciplinary action.
        </span>
      </div>

      <div className="callout callout-blue mt-16 fade-in-up">
        <Icon name="info" size={18} />
        <span>
          <strong>Stopping the lab:</strong> when you are finished, run{' '}
          <span className="mono" style={{ fontWeight: 600 }}>docker compose down</span> in the target
          directory. Do not leave the container running when you are not working on the lab.
        </span>
      </div>
    </div>
  );
}
