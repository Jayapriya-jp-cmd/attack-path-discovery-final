import { useState } from 'react';

export default function Dashboard({ data }) {
  const [activeTab, setActiveTab] = useState('ports');

  if (!data) return null;

  const tabs = [
    { key: 'ports', label: '🔌 Ports', count: data.ports?.length || 0 },
    { key: 'services', label: '⚙️ Services', count: data.services?.length || 0 },
    { key: 'vulns', label: '🛡️ Vulnerabilities', count: data.vulnerabilities?.length || 0 },
    { key: 'exploits', label: '💀 Exploits', count: data.exploits?.length || 0 },
    { key: 'privesc', label: '⬆️ PrivEsc', count: data.privEscVectors?.length || 0 },
  ];

  return (
    <div className="glass-card fade-in">
      <div className="card-header">
        <div className="card-title">
          <span className="icon">📊</span>
          Scan Results
        </div>
        <span className="card-badge badge-info" style={{ fontFamily: 'var(--font-mono)' }}>
          {data.target}
        </span>
      </div>

      <div className="tabs">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            className={`tab-btn ${activeTab === tab.key ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.key)}
            id={`tab-${tab.key}`}
          >
            {tab.label}
            <span style={{
              background: 'rgba(0,240,255,0.1)',
              padding: '2px 8px',
              borderRadius: '10px',
              fontSize: '0.7rem',
              fontFamily: 'var(--font-mono)',
            }}>
              {tab.count}
            </span>
          </button>
        ))}
      </div>

      {activeTab === 'ports' && <PortsTable ports={data.ports} />}
      {activeTab === 'services' && <ServicesTable services={data.services} />}
      {activeTab === 'vulns' && <VulnsTable vulns={data.vulnerabilities} />}
      {activeTab === 'exploits' && <ExploitsTable exploits={data.exploits} />}
      {activeTab === 'privesc' && <PrivEscTable vectors={data.privEscVectors} />}
    </div>
  );
}

function PortsTable({ ports }) {
  // ports can be either an array of numbers (new format) or objects (old/history format)
  if (!ports || ports.length === 0) return <EmptyState text="No open ports found" />;

  // Check if ports are just numbers (new API format) — render simply
  const isSimple = typeof ports[0] === 'number';

  if (isSimple) {
    return (
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Port</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            {ports.map((port, i) => (
              <tr key={i} className="slide-in" style={{ animationDelay: `${i * 50}ms` }}>
                <td style={{ color: 'var(--neon-cyan)', fontWeight: 600 }}>{port}</td>
                <td>
                  <span style={{ color: 'var(--neon-lime)', fontWeight: 600 }}>open</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  // Object format (from history)
  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="data-table">
        <thead>
          <tr>
            <th>Port</th>
            <th>Protocol</th>
            <th>State</th>
            <th>Service</th>
            <th>Version</th>
          </tr>
        </thead>
        <tbody>
          {ports.map((port, i) => (
            <tr key={i} className="slide-in" style={{ animationDelay: `${i * 50}ms` }}>
              <td style={{ color: 'var(--neon-cyan)', fontWeight: 600 }}>{port.number || port.port || port}</td>
              <td>{port.protocol || 'tcp'}</td>
              <td>
                <span style={{
                  color: (port.state === 'open') ? 'var(--neon-lime)' : 'var(--text-muted)',
                  fontWeight: 600,
                }}>
                  {port.state || 'open'}
                </span>
              </td>
              <td>{port.service || port.name || '—'}</td>
              <td>{port.version || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ServicesTable({ services }) {
  if (!services || services.length === 0) return <EmptyState text="No services detected" />;

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="data-table">
        <thead>
          <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Version / Banner</th>
          </tr>
        </thead>
        <tbody>
          {services.map((svc, i) => (
            <tr key={i} className="slide-in" style={{ animationDelay: `${i * 50}ms` }}>
              <td style={{ color: 'var(--neon-cyan)', fontWeight: 600 }}>{svc.port}</td>
              <td style={{ color: 'var(--neon-lime)', fontWeight: 600 }}>{svc.name || '—'}</td>
              <td style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                {svc.version || svc.fullVersion || '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function VulnsTable({ vulns }) {
  if (!vulns || vulns.length === 0) return <EmptyState text="No vulnerabilities found" />;

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="data-table">
        <thead>
          <tr>
            <th>CVE</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>Service</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {vulns.map((vuln, i) => (
            <tr key={i} className="slide-in" style={{ animationDelay: `${i * 50}ms` }}>
              <td style={{ color: 'var(--neon-amber)', fontWeight: 600 }}>{vuln.cve}</td>
              <td>
                <span className={`severity-tag severity-${vuln.severity.toLowerCase()}`}>
                  {vuln.severity}
                </span>
              </td>
              <td style={{ fontWeight: 700, color: getCvssColor(vuln.cvss) }}>
                {vuln.cvss}
              </td>
              <td>{vuln.service}:{vuln.port}</td>
              <td style={{ maxWidth: '300px', fontSize: '0.75rem', lineHeight: 1.5 }}>
                {vuln.description}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ExploitsTable({ exploits }) {
  if (!exploits || exploits.length === 0) return <EmptyState text="No exploits found" />;

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="data-table">
        <thead>
          <tr>
            <th>Title</th>
            <th>Type</th>
            <th>Platform</th>
            <th>Service</th>
            <th>Path</th>
          </tr>
        </thead>
        <tbody>
          {exploits.map((exp, i) => (
            <tr key={i} className="slide-in" style={{ animationDelay: `${i * 50}ms` }}>
              <td style={{ color: 'var(--neon-red)', maxWidth: '280px' }}>{exp.title}</td>
              <td>
                <span className={`severity-tag ${exp.type === 'remote' ? 'severity-critical' : 'severity-medium'}`}>
                  {exp.type}
                </span>
              </td>
              <td>{exp.platform}</td>
              <td>{exp.service}:{exp.port}</td>
              <td style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{exp.path}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PrivEscTable({ vectors }) {
  if (!vectors || vectors.length === 0) return <EmptyState text="No privilege escalation vectors found" />;

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="data-table">
        <thead>
          <tr>
            <th>Type</th>
            <th>Name</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {vectors.map((vec, i) => (
            <tr key={i} className="slide-in" style={{ animationDelay: `${i * 50}ms` }}>
              <td style={{ color: 'var(--neon-magenta)' }}>{vec.type}</td>
              <td style={{ fontWeight: 600 }}>{vec.name}</td>
              <td>
                <span className={`severity-tag severity-${vec.severity.toLowerCase()}`}>
                  {vec.severity}
                </span>
              </td>
              <td>{vec.confidence}</td>
              <td style={{ maxWidth: '280px', fontSize: '0.75rem', lineHeight: 1.5 }}>
                {vec.description}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EmptyState({ text }) {
  return (
    <div style={{
      textAlign: 'center',
      padding: '40px',
      color: 'var(--text-muted)',
      fontSize: '0.9rem',
    }}>
      {text}
    </div>
  );
}

function getCvssColor(cvss) {
  if (cvss >= 9) return 'var(--severity-critical)';
  if (cvss >= 7) return 'var(--severity-high)';
  if (cvss >= 4) return 'var(--severity-medium)';
  return 'var(--severity-low)';
}
