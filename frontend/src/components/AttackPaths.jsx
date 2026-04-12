import { useState } from 'react';

export default function AttackPaths({ paths }) {
  if (!paths || paths.length === 0) {
    return (
      <div className="glass-card fade-in">
        <div className="card-header">
          <div className="card-title">
            <span className="icon">⚡</span>
            Attack Paths
          </div>
          <span className="card-badge badge-info">0 PATHS</span>
        </div>
        <div style={{
          textAlign: 'center',
          padding: '40px',
          color: 'var(--text-muted)',
          fontSize: '0.9rem',
        }}>
          No attack paths generated — no exploitable service+exploit combinations found.
          <br />
          <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
            This is correct if no real exploits were matched by Searchsploit.
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="glass-card fade-in">
      <div className="card-header">
        <div className="card-title">
          <span className="icon">⚡</span>
          Attack Paths
        </div>
        <span className="card-badge badge-critical">{paths.length} PATHS</span>
      </div>
      {paths.map((path, idx) => (
        <AttackPathCard key={path.id} path={path} index={idx} />
      ))}
    </div>
  );
}

function AttackPathCard({ path, index }) {
  const [expanded, setExpanded] = useState(index === 0);

  const riskScore = path.riskScore || 0;
  const stepCount = path.steps?.length || 0;

  const scoreColor = riskScore >= 8 ? 'var(--severity-critical)'
    : riskScore >= 6 ? 'var(--severity-high)'
    : riskScore >= 4 ? 'var(--severity-medium)'
    : 'var(--severity-low)';

  return (
    <div className="attack-path-card" id={`attack-path-${index}`}>
      <div
        className="attack-path-header"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="attack-path-name">
          <span style={{ color: scoreColor, fontSize: '1.1rem' }}>
            {expanded ? '▾' : '▸'}
          </span>
          <span>#{index + 1} {path.name}</span>
        </div>
        <div className="attack-path-meta">
          <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
            {stepCount} steps
          </span>
          <span className="attack-path-score" style={{ color: scoreColor }}>
            {riskScore}
          </span>
        </div>
      </div>

      {expanded && (
        <div className="attack-path-steps fade-in">
          {(path.steps || []).map((step, i) => (
            <div key={i} className="step-item slide-in" style={{ animationDelay: `${i * 80}ms` }}>
              <div className="step-dot" style={{
                borderColor: getStepColor(step),
                color: getStepColor(step),
              }}>
                {step.step || i + 1}
              </div>
              <div className="step-content">
                <div className="step-stage">{step.action || step.stage || `Step ${i + 1}`}</div>
                <div className="step-desc">{step.finding || step.description || ''}</div>
                <div className="step-meta">
                  {step.confidence && (
                    <span className="step-confidence" style={{
                      color: step.confidence === 'Confirmed' || step.confidence === 'Real' ? 'var(--neon-lime)'
                        : step.confidence === 'Matched' || step.confidence === 'Database' ? 'var(--neon-amber)'
                        : 'var(--text-muted)',
                    }}>
                      ◉ {step.confidence}
                    </span>
                  )}
                  {step.severity && (
                    <span style={{
                      color: step.severity === 'Critical' ? 'var(--severity-critical)' : 'var(--neon-amber)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.7rem',
                    }}>
                      {step.severity}
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))}

          {/* Data source */}
          {path.dataSource && (
            <div style={{
              marginTop: '12px',
              padding: '8px 12px',
              fontSize: '0.7rem',
              fontFamily: 'var(--font-mono)',
              color: 'var(--neon-lime)',
              background: 'rgba(57, 255, 20, 0.05)',
              borderRadius: '6px',
              borderLeft: '2px solid var(--neon-lime)',
            }}>
              ✓ {path.dataSource}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function getStepColor(step) {
  const confidence = step.confidence;
  if (confidence === 'Confirmed' || confidence === 'Real') return 'var(--neon-lime)';
  if (confidence === 'Matched' || confidence === 'Database') return 'var(--neon-amber)';
  if (confidence === 'Theoretical') return 'var(--text-muted)';
  return 'var(--neon-cyan)';
}
