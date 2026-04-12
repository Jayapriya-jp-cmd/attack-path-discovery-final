import { useState } from 'react';

export default function ReportView({ data }) {
  const [copied, setCopied] = useState(false);

  if (!data) return null;

  const reportJson = JSON.stringify(formatReport(data), null, 2);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(reportJson);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
      const textarea = document.createElement('textarea');
      textarea.value = reportJson;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = () => {
    const blob = new Blob([reportJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `attack-path-report-${data.scanId || 'scan'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="glass-card fade-in">
      <div className="card-header">
        <div className="card-title">
          <span className="icon">📋</span>
          JSON Report
        </div>
      </div>
      <div className="report-actions">
        <button className="report-btn" onClick={handleCopy} id="copy-report-btn">
          {copied ? '✓ Copied!' : '📋 Copy JSON'}
        </button>
        <button className="report-btn" onClick={handleDownload} id="download-report-btn">
          💾 Download
        </button>
      </div>
      <div className="report-json" id="report-content">
        <SyntaxHighlightedJson json={reportJson} />
      </div>
    </div>
  );
}

function SyntaxHighlightedJson({ json }) {
  // Simple JSON syntax highlighting
  const highlighted = json
    .replace(/("(?:[^"\\]|\\.)*")(\s*:)?/g, (match, key, colon) => {
      if (colon) {
        return `<span style="color:#00f0ff">${key}</span>${colon}`;
      }
      // Check if it's a value string
      return `<span style="color:#39ff14">${key}</span>`;
    })
    .replace(/\b(\d+\.?\d*)\b/g, '<span style="color:#ffaa00">$1</span>')
    .replace(/\b(true|false|null)\b/g, '<span style="color:#ff00e5">$1</span>');

  return <div dangerouslySetInnerHTML={{ __html: highlighted }} />;
}

function formatReport(data) {
  return {
    target: data.target,
    scanId: data.scanId,
    scanTime: data.scanTime,
    duration: data.duration,
    ports: data.ports,
    services: data.services,
    vulnerabilities: (data.vulnerabilities || []).map(v => ({
      cve: v.cve,
      description: v.description,
      severity: v.severity,
      cvss: v.cvss,
    })),
    exploits: (data.exploits || []).map(e => ({
      title: e.title,
      type: e.type,
      platform: e.platform,
    })),
    attackPaths: (data.attackPaths || []).map(p => ({
      id: p.id,
      steps: (p.steps || []).map(s => ({
        step: s.step,
        action: s.action,
        finding: s.finding,
        confidence: s.confidence,
      })),
      riskScore: p.riskScore,
      name: p.name,
    })),
  };
}
