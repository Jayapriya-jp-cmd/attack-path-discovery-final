// ═══════════════════════════════════════════════════════════
//  Reconnaissance Engine — REAL Nmap Execution ONLY
//  NO MOCK DATA. NO HARDCODED RESULTS. REAL SCANS ONLY.
// ═══════════════════════════════════════════════════════════
const { execFile, exec } = require('child_process');
const { XMLParser } = require('fast-xml-parser');
const fs = require('fs');
const path = require('path');
const os = require('os');
const config = require('../config');

/**
 * Check if Nmap is installed and accessible in PATH.
 * @returns {Promise<{available: boolean, version: string|null}>}
 */
async function checkNmapInstalled() {
  return new Promise((resolve) => {
    exec('nmap --version', { timeout: 5000 }, (err, stdout) => {
      if (err) {
        resolve({ available: false, version: null });
      } else {
        const match = stdout.match(/Nmap version ([\d.]+)/);
        resolve({ available: true, version: match ? match[1] : 'unknown' });
      }
    });
  });
}

/**
 * Run a REAL Nmap scan against the target.
 * NEVER returns mock/hardcoded data. Returns real results or throws an error.
 *
 * @param {string} target - IP or domain to scan
 * @returns {Promise<Object>} Parsed scan results from real Nmap XML output
 * @throws {Error} If Nmap is not installed, scan fails, or output can't be parsed
 */
async function runNmapScan(target) {
  console.log(`\n[Recon] ══════════════════════════════════════`);
  console.log(`[Recon] STARTING REAL NMAP SCAN: ${target}`);
  console.log(`[Recon] ══════════════════════════════════════`);

  // Step 1: Verify Nmap is installed
  console.log('[Recon] Checking Nmap installation...');
  const nmapCheck = await checkNmapInstalled();
  if (!nmapCheck.available) {
    throw new Error(
      'NMAP NOT INSTALLED: Nmap is not found in system PATH. ' +
      'Install Nmap from https://nmap.org/download.html and ensure it is in PATH.'
    );
  }
  console.log(`[Recon] ✓ Nmap ${nmapCheck.version} found`);

  // Step 2: Sanitize target
  const safeTarget = sanitizeTarget(target);
  if (!safeTarget) {
    throw new Error(`INVALID TARGET: "${target}" is not a valid IP address or domain name.`);
  }

  // Step 3: Prepare output file
  const tmpFile = path.join(os.tmpdir(), `nmap_scan_${Date.now()}.xml`);
  const nmapArgs = ['-sC', '-sV', '-T4', '-oX', tmpFile, safeTarget];
  const cmdString = `nmap ${nmapArgs.join(' ')}`;

  console.log(`[Recon] Running: ${cmdString}`);
  console.log(`[Recon] Output file: ${tmpFile}`);
  console.log(`[Recon] Timeout: ${config.scanTimeoutMs}ms`);

  // Step 4: Execute real Nmap scan
  return new Promise((resolve, reject) => {
    const startTime = Date.now();

    const child = execFile('nmap', nmapArgs, {
      timeout: config.scanTimeoutMs,
      maxBuffer: 20 * 1024 * 1024,
      windowsHide: true,
    }, (err, stdout, stderr) => {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

      if (err) {
        // Clean up temp file
        try { fs.unlinkSync(tmpFile); } catch {}

        if (err.killed) {
          return reject(new Error(
            `NMAP TIMEOUT: Scan timed out after ${elapsed}s (limit: ${config.scanTimeoutMs / 1000}s). ` +
            `Try a simpler scan or increase SCAN_TIMEOUT_MS.`
          ));
        }
        return reject(new Error(
          `NMAP EXECUTION FAILED: ${err.message}. ` +
          `Elapsed: ${elapsed}s. Stderr: ${stderr || 'none'}`
        ));
      }

      console.log(`[Recon] ✓ Nmap scan completed in ${elapsed}s`);

      // Step 5: Read and parse the XML output
      try {
        if (!fs.existsSync(tmpFile)) {
          return reject(new Error('NMAP OUTPUT MISSING: XML output file was not created.'));
        }

        const xmlData = fs.readFileSync(tmpFile, 'utf8');
        console.log(`[Recon] Parsing XML output (${xmlData.length} bytes)...`);

        // Clean up temp file
        try { fs.unlinkSync(tmpFile); } catch {}

        const result = parseNmapXml(xmlData, safeTarget);

        console.log(`[Recon] ✓ Parsed: ${result.ports.length} open ports found`);
        result.ports.forEach(p => {
          console.log(`[Recon]   Port ${p.number}/${p.protocol} → ${p.service.name} ${p.service.product || ''} ${p.service.version || ''}`);
        });

        resolve(result);
      } catch (parseErr) {
        reject(new Error(`NMAP PARSE FAILED: ${parseErr.message}`));
      }
    });

    // Log progress from stdout
    if (child.stdout) {
      child.stdout.on('data', (data) => {
        const lines = data.toString().split('\n').filter(l => l.trim());
        lines.forEach(l => console.log(`[Recon/nmap] ${l}`));
      });
    }
    if (child.stderr) {
      child.stderr.on('data', (data) => {
        const lines = data.toString().split('\n').filter(l => l.trim());
        lines.forEach(l => console.log(`[Recon/nmap/err] ${l}`));
      });
    }
  });
}

/**
 * Parse REAL Nmap XML output into structured data.
 * Extracts ONLY what the XML contains — no defaults, no assumptions.
 */
function parseNmapXml(xml, target) {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    allowBooleanAttributes: true,
  });

  const doc = parser.parse(xml);
  const nmaprun = doc.nmaprun || {};
  const host = nmaprun.host;

  if (!host) {
    return {
      target,
      scanTime: new Date().toISOString(),
      scanType: 'REAL',
      os: { name: 'Unknown', accuracy: 0, family: 'Unknown', vendor: 'Unknown' },
      ports: [],
      _warning: 'Host appears to be down or no ports found. Nmap returned no host data.',
    };
  }

  // Handle array or single host
  const hosts = Array.isArray(host) ? host : [host];
  const h = hosts[0];

  // Extract OS from REAL detection
  let os = { name: 'Unknown', accuracy: 0, family: 'Unknown', vendor: 'Unknown' };
  if (h.os && h.os.osmatch) {
    const matches = Array.isArray(h.os.osmatch) ? h.os.osmatch : [h.os.osmatch];
    const best = matches[0];
    os = {
      name: best['@_name'] || 'Unknown',
      accuracy: parseInt(best['@_accuracy'] || '0', 10),
      family: best.osclass ? (Array.isArray(best.osclass) ? best.osclass[0] : best.osclass)['@_osfamily'] || 'Unknown' : 'Unknown',
      vendor: best.osclass ? (Array.isArray(best.osclass) ? best.osclass[0] : best.osclass)['@_vendor'] || 'Unknown' : 'Unknown',
    };
  }

  // Extract REAL open ports from XML
  const ports = [];
  const portsNode = h.ports && h.ports.port;
  if (portsNode) {
    const portList = Array.isArray(portsNode) ? portsNode : [portsNode];
    for (const p of portList) {
      const state = p.state ? p.state['@_state'] : null;
      if (state !== 'open') continue;

      ports.push({
        number: parseInt(p['@_portid'], 10),
        protocol: p['@_protocol'] || 'tcp',
        state: 'open',
        service: {
          name: p.service ? (p.service['@_name'] || 'unknown') : 'unknown',
          version: p.service ? (p.service['@_version'] || '') : '',
          product: p.service ? (p.service['@_product'] || '') : '',
          extraInfo: p.service ? (p.service['@_extrainfo'] || '') : '',
        },
      });
    }
  }

  // Extract scripts output (real NSE script results)
  const scripts = [];
  if (portsNode) {
    const portList = Array.isArray(portsNode) ? portsNode : [portsNode];
    for (const p of portList) {
      const scriptArr = p.script || [];
      const scriptList = Array.isArray(scriptArr) ? scriptArr : [scriptArr];
      for (const s of scriptList) {
        if (s && s['@_id']) {
          scripts.push({
            port: parseInt(p['@_portid'], 10),
            id: s['@_id'],
            output: s['@_output'] || '',
          });
        }
      }
    }
  }

  return {
    target,
    scanTime: new Date().toISOString(),
    scanType: 'REAL',
    os,
    ports,
    scripts,
  };
}

/**
 * Sanitize target to prevent command injection.
 * Returns null if the target is invalid.
 */
function sanitizeTarget(target) {
  if (!target || typeof target !== 'string') return null;
  const t = target.trim();
  // Allow: IPv4, IPv6, hostnames, CIDR ranges — nothing else
  if (!/^[a-zA-Z0-9.\-:/\[\]_]+$/.test(t)) return null;
  if (t.length > 253) return null;
  // Block obvious injection attempts
  if (t.includes('&&') || t.includes('||') || t.includes(';') || t.includes('`') || t.includes('$')) return null;
  return t;
}

module.exports = { runNmapScan, checkNmapInstalled };
