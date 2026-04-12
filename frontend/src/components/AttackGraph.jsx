import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';

const NODE_COLORS = {
  target: '#00f0ff',
  port: '#4d7cff',
  service: '#39ff14',
  vulnerability: '#ffaa00',
  exploit: '#ff3366',
  accesslevel: '#ff00e5',
  privescvector: '#ff6633',
  adentity: '#9945ff',
};

const NODE_SHAPES = {
  target: 'diamond',
  port: 'round-rectangle',
  service: 'round-rectangle',
  vulnerability: 'barrel',
  exploit: 'star',
  accesslevel: 'hexagon',
  privescvector: 'triangle',
  adentity: 'pentagon',
};

export default function AttackGraph({ data }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  useEffect(() => {
    if (!data || !data.graph || !containerRef.current) return;

    const { nodes, edges } = data.graph;

    const elements = [
      ...nodes.map((n) => ({
        data: {
          id: n.id,
          label: n.label.length > 30 ? n.label.substring(0, 28) + '…' : n.label,
          fullLabel: n.label,
          type: n.type.toLowerCase(),
          nodeType: n.type,
        },
        classes: n.type.toLowerCase(),
      })),
      ...edges.map((e, i) => ({
        data: {
          id: `edge_${i}`,
          source: e.source,
          target: e.target,
          label: e.type.replace(/_/g, ' '),
        },
      })),
    ];

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'font-size': '9px',
            'font-family': '"JetBrains Mono", monospace',
            'color': '#94a3b8',
            'text-margin-y': 8,
            'text-wrap': 'ellipsis',
            'text-max-width': '120px',
            'width': 40,
            'height': 40,
            'border-width': 2,
            'border-opacity': 0.8,
            'text-outline-color': '#0a0e1a',
            'text-outline-width': 2,
            'transition-property': 'border-width, width, height',
            'transition-duration': '0.2s',
          },
        },
        // Node type styles
        ...Object.entries(NODE_COLORS).map(([type, color]) => ({
          selector: `node.${type}`,
          style: {
            'background-color': hexToRgba(color, 0.25),
            'border-color': color,
            'shape': NODE_SHAPES[type] || 'ellipse',
          },
        })),
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': 'rgba(0, 240, 255, 0.25)',
            'target-arrow-color': 'rgba(0, 240, 255, 0.5)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8,
            'label': 'data(label)',
            'font-size': '7px',
            'font-family': '"JetBrains Mono", monospace',
            'color': 'rgba(148, 163, 184, 0.4)',
            'text-rotation': 'autorotate',
            'text-margin-y': -8,
            'text-outline-color': '#0a0e1a',
            'text-outline-width': 2,
          },
        },
        {
          selector: 'node:active, node:selected',
          style: {
            'border-width': 4,
            'width': 50,
            'height': 50,
          },
        },
        {
          selector: 'edge:active, edge:selected',
          style: {
            'width': 3,
            'line-color': 'rgba(0, 240, 255, 0.6)',
          },
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        spacingFactor: 1.2,
        padding: 50,
        avoidOverlap: true,
      },
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
      minZoom: 0.2,
      maxZoom: 3,
    });

    // Tooltip on hover
    cy.on('mouseover', 'node', (e) => {
      const node = e.target;
      node.style('border-width', 4);
      node.style('width', 50);
      node.style('height', 50);
      containerRef.current.style.cursor = 'pointer';
    });

    cy.on('mouseout', 'node', (e) => {
      const node = e.target;
      node.style('border-width', 2);
      node.style('width', 40);
      node.style('height', 40);
      containerRef.current.style.cursor = 'default';
    });

    cyRef.current = cy;

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [data]);

  const handleFit = () => {
    if (cyRef.current) cyRef.current.fit(undefined, 50);
  };

  const handleCenter = () => {
    if (cyRef.current) cyRef.current.center();
  };

  const handleRelayout = (layoutName) => {
    if (!cyRef.current) return;
    cyRef.current.layout({
      name: layoutName,
      directed: true,
      spacingFactor: 1.2,
      padding: 50,
      avoidOverlap: true,
      animate: true,
      animationDuration: 500,
    }).run();
  };

  if (!data || !data.graph) return null;

  const legendItems = [
    { type: 'Target', color: NODE_COLORS.target },
    { type: 'Port', color: NODE_COLORS.port },
    { type: 'Service', color: NODE_COLORS.service },
    { type: 'Vulnerability', color: NODE_COLORS.vulnerability },
    { type: 'Exploit', color: NODE_COLORS.exploit },
    { type: 'Access Level', color: NODE_COLORS.accesslevel },
    { type: 'PrivEsc', color: NODE_COLORS.privescvector },
  ];

  return (
    <div className="glass-card fade-in">
      <div className="card-header">
        <div className="card-title">
          <span className="icon">🕸️</span>
          Attack Graph
        </div>
        <span style={{
          fontSize: '0.75rem',
          color: 'var(--text-muted)',
          fontFamily: 'var(--font-mono)',
        }}>
          {data.graph.nodes.length} nodes · {data.graph.edges.length} edges
        </span>
      </div>
      <div className="graph-container" id="attack-graph">
        <div ref={containerRef} style={{ width: '100%', height: '100%' }} />
        <div className="graph-controls">
          <button className="graph-btn" onClick={handleFit} title="Fit to view">⊞ Fit</button>
          <button className="graph-btn" onClick={handleCenter} title="Center">◎ Center</button>
          <button className="graph-btn" onClick={() => handleRelayout('breadthfirst')} title="Tree layout">⊟ Tree</button>
          <button className="graph-btn" onClick={() => handleRelayout('circle')} title="Circle layout">◯ Circle</button>
          <button className="graph-btn" onClick={() => handleRelayout('cose')} title="Force layout">✧ Force</button>
        </div>
        <div className="graph-legend">
          {legendItems.map((item) => (
            <div key={item.type} className="legend-item">
              <div className="legend-dot" style={{ background: item.color }} />
              {item.type}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function hexToRgba(hex, alpha) {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}
