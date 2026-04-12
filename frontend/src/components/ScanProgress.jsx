export default function ScanProgress({ progress }) {
  if (!progress) return null;

  const { phase, progress: pct, message } = progress;

  return (
    <div className="progress-container glass-card fade-in">
      <div className="progress-header">
        <span className="progress-phase">⟡ {phase}</span>
        <span className="progress-pct">{pct}%</span>
      </div>
      <div className="progress-track">
        <div className="progress-fill" style={{ width: `${pct}%` }} />
      </div>
      <div className="progress-message">{message}</div>
    </div>
  );
}
