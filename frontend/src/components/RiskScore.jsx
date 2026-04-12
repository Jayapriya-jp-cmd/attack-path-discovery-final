export default function RiskScore({ data }) {
  if (!data || !data.summary) return null;

  const { summary } = data;
  const score = summary.highestRisk || 0;
  const severity = summary.overallSeverity || 'Info';

  // SVG circle parameters
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 10) * circumference;

  const getColor = () => {
    if (score >= 9) return 'var(--severity-critical)';
    if (score >= 7) return 'var(--severity-high)';
    if (score >= 4) return 'var(--severity-medium)';
    return 'var(--severity-low)';
  };

  return (
    <div className="glass-card fade-in">
      <div className="card-header">
        <div className="card-title">
          <span className="icon">🎯</span>
          Risk Score
        </div>
      </div>
      <div className="risk-score-display">
        <div className="risk-gauge">
          <svg viewBox="0 0 140 140">
            <circle
              className="risk-gauge-bg"
              cx="70"
              cy="70"
              r={radius}
            />
            <circle
              className="risk-gauge-fill"
              cx="70"
              cy="70"
              r={radius}
              stroke={getColor()}
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              style={{ filter: `drop-shadow(0 0 8px ${getColor()})` }}
            />
          </svg>
          <div className="risk-gauge-value">
            <span className="risk-gauge-number" style={{ color: getColor() }}>
              {score}
            </span>
            <span className="risk-gauge-label">{severity}</span>
          </div>
        </div>

        <div style={{ marginTop: '20px' }}>
          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '12px',
            textAlign: 'left',
          }}>
            <MiniStat label="Ports" value={summary.totalPorts} icon="🔌" />
            <MiniStat label="Vulns" value={summary.totalVulnerabilities} icon="🛡️" />
            <MiniStat label="Exploits" value={summary.totalExploits} icon="💀" />
            <MiniStat label="Paths" value={summary.totalAttackPaths} icon="⚡" />
          </div>
        </div>
      </div>
    </div>
  );
}

function MiniStat({ label, value, icon }) {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: '10px',
      padding: '10px 12px',
      background: 'rgba(255,255,255,0.02)',
      borderRadius: '8px',
      border: '1px solid var(--border-subtle)',
    }}>
      <span style={{ fontSize: '1rem' }}>{icon}</span>
      <div>
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontWeight: 700,
          fontSize: '1.1rem',
          color: 'var(--text-primary)',
        }}>
          {value}
        </div>
        <div style={{
          fontSize: '0.65rem',
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '1px',
        }}>
          {label}
        </div>
      </div>
    </div>
  );
}
