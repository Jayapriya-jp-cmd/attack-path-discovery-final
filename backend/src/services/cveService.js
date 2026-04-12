// ============================================================
//  PHASE 2: VULNERABILITY MAPPING — CVE Service
//  Maps detected services to known CVEs from local database.
// ============================================================

const cveDb = require('../data/cve_db.json');
const axios = require('axios');

// Service keyword normalization map
const SERVICE_KEY_MAP = {
  'http': 'apache',
  'apache': 'apache',
  'apache httpd': 'apache',
  'apache http server': 'apache',
  'https': 'apache',
  'ssl/http': 'apache',
  'ssh': 'ssh',
  'openssh': 'ssh',
  'ftp': 'ftp',
  'vsftpd': 'ftp',
  'proftpd': 'ftp',
  'filezilla': 'ftp',
  'smb': 'smb',
  'microsoft-ds': 'smb',
  'netbios-ssn': 'smb',
  'netbios': 'smb',
  'samba': 'smb',
  'microsoft smb': 'smb',
  'rdp': 'rdp',
  'ms-wbt-server': 'rdp',
  'microsoft rdp': 'rdp',
  'remote desktop': 'rdp',
  'mysql': 'mysql',
  'mariadb': 'mysql',
  'redis': 'redis',
  'tomcat': 'tomcat',
  'apache tomcat': 'tomcat',
  'http-proxy': 'tomcat',
  'jboss': 'jboss',
  'jenkins': 'jenkins',
  'jenkins ci': 'jenkins',
  'jetty': 'jenkins',
  'weblogic': 'weblogic',
  'oracle weblogic': 'weblogic',
  'mongodb': 'mongodb',
  'mongo': 'mongodb',
  'telnet': 'telnet',
  'snmp': 'snmp',
  'php': 'php',
  'php-fpm': 'php',
  'php-cgi': 'php',
  'nginx': 'php',
  'drupal': 'drupal',
  'wordpress': 'wordpress',
  'exchange': 'exchange',
  'microsoft exchange': 'exchange',
  'owa': 'exchange',
  'outlook': 'exchange',
  'struts': 'struts',
  'struts2': 'struts2',
  'openssl': 'openssl',
  'ssl': 'openssl',
  'tls': 'openssl',
  'vnc': 'vnc',
  'unrealircd': 'unrealircd',
  'ircd': 'unrealircd',
  'nexus': 'nexus',
  'sonatype': 'nexus',
  'vcenter': 'vmware',
  'vmware': 'vmware',
  'vbulletin': 'vbulletin',
  'netlogon': 'netlogon',
  'ldap': 'netlogon',
  'kerberos': 'netlogon',
};

/**
 * Map services to vulnerabilities from local CVE database.
 * @param {Array} services - From nmapService
 * @param {function} onProgress
 * @returns {Promise<Array>} vulnerabilities
 */
async function mapVulnerabilities(services, onProgress = () => {}) {
  onProgress('Mapping services to CVE database...');
  const vulnerabilities = [];
  const seen = new Set();

  for (const svc of services) {
    const matches = findCVEsForService(svc);
    for (const cve of matches) {
      if (!seen.has(cve.id)) {
        seen.add(cve.id);
        vulnerabilities.push({
          ...cve,
          affectedService: svc.name,
          affectedPort: svc.port,
          detectedVersion: svc.fullVersion,
          source: 'local_db',
        });
      }
    }
  }

  // Sort by CVSS score descending
  vulnerabilities.sort((a, b) => (b.cvss_v3 || 0) - (a.cvss_v3 || 0));

  onProgress(`Vulnerability mapping complete. Found ${vulnerabilities.length} CVE(s).`);

  // Optional: enrich with NVD API if key is set
  if (process.env.NVD_API_KEY && vulnerabilities.length > 0) {
    await enrichWithNVD(vulnerabilities, onProgress).catch(() => {});
  }

  return vulnerabilities;
}

/**
 * Find CVEs matching a service from the local DB.
 */
function findCVEsForService(svc) {
  const { name, product, version, fullVersion, banner } = svc;
  const matched = [];

  // Get normalized service key
  const serviceKey = resolveServiceKey(name, product, fullVersion);

  for (const entry of cveDb.entries) {
    // Check service key match
    const entryKeys = entry.service_key.split('|').map(k => k.trim());
    const keyMatches = entryKeys.some(k => {
      if (serviceKey && serviceKey === k) return true;
      // Try matching against full version string
      const vk = (fullVersion || '').toLowerCase();
      if (vk.includes(k.toLowerCase())) return true;
      return false;
    });

    if (!keyMatches) continue;

    // Check version pattern if present
    if (entry.version_pattern && fullVersion) {
      try {
        const re = new RegExp(entry.version_pattern, 'i');
        if (!re.test(fullVersion)) continue;
      } catch {
        // If regex fails, skip version check
      }
    }

    matched.push({
      id: entry.id,
      cve: entry.id,
      description: entry.description,
      cvss_v3: entry.cvss_v3,
      severity: entry.severity,
      cwe: entry.cwe,
      exploit_available: entry.exploit_available,
      exploit_title: entry.exploit_title || null,
      tags: entry.tags || [],
      attack_vector: entry.attack_vector,
      initial_access: entry.initial_access || false,
      privesc: entry.privesc || false,
      escalates_to: entry.escalates_to || null,
    });
  }

  return matched;
}

/**
 * Resolve normalized service key from raw nmap output.
 */
function resolveServiceKey(name, product, fullVersion) {
  const candidates = [
    (product || '').toLowerCase().trim(),
    (name || '').toLowerCase().trim(),
    (fullVersion || '').toLowerCase().trim(),
  ];

  for (const candidate of candidates) {
    for (const [pattern, key] of Object.entries(SERVICE_KEY_MAP)) {
      if (candidate.includes(pattern.toLowerCase())) return key;
    }
  }
  return null;
}

/**
 * Optional: Enrich CVEs with live NVD data (if API key set).
 */
async function enrichWithNVD(vulnerabilities, onProgress) {
  onProgress('Enriching with NVD API data...');
  const key = process.env.NVD_API_KEY;

  for (const vuln of vulnerabilities) {
    if (!vuln.cve.startsWith('CVE-')) continue;
    try {
      const resp = await axios.get(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${vuln.cve}`,
        { headers: { apiKey: key }, timeout: 5000 }
      );
      const nvdEntry = resp.data?.vulnerabilities?.[0]?.cve;
      if (nvdEntry) {
        vuln.nvd_description = nvdEntry.descriptions?.find(d => d.lang === 'en')?.value;
        vuln.source = 'nvd_enriched';
      }
    } catch {
      // Silently fail — local data is sufficient
    }
  }
}

module.exports = { mapVulnerabilities };
