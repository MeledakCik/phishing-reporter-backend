import { chromium } from 'playwright';
import dns from 'dns/promises';
import net from 'net';
import tls from 'tls';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { getDb } from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Known registrar abuse email dictionary for high accuracy
const REGISTRAR_ABUSE_MAP = [
  { keywords: ['digital registra', 'digitalregistra'], email: 'info@digitalregistra.co.id', name: 'PT Digital Registra Indonesia' },
  { keywords: ['dynadot'], email: 'abuse@dynadot.com', name: 'Dynadot Inc' },
  { keywords: ['namecheap'], email: 'abuse@namecheap.com', name: 'Namecheap, Inc.' },
  { keywords: ['cloudflare'], email: 'registrar-abuse@cloudflare.com', name: 'Cloudflare, Inc.' },
  { keywords: ['godaddy'], email: 'abuse@godaddy.com', name: 'GoDaddy.com, LLC' },
  { keywords: ['hostinger'], email: 'abuse@hostinger.com', name: 'Hostinger, UAB' },
  { keywords: ['markmonitor'], email: 'abusecomplaints@markmonitor.com', name: 'MarkMonitor Inc.' },
  { keywords: ['namesilo'], email: 'abuse@namesilo.com', name: 'NameSilo, LLC' },
  { keywords: ['publicdomainregistry', 'public domain registry', 'pdr'], email: 'abuse-contact@publicdomainregistry.com', name: 'Public Domain Registry' },
  { keywords: ['tucows', 'hover'], email: 'domainabuse@tucows.com', name: 'Tucows Domains Inc.' },
  { keywords: ['csc corporate', 'cscglobal'], email: 'domainabuse@cscglobal.com', name: 'CSC Corporate Domains, Inc.' },
  { keywords: ['porkbun'], email: 'abuse@porkbun.com', name: 'Porkbun LLC' },
  { keywords: ['rumahweb'], email: 'abuse@rumahweb.com', name: 'PT Rumahweb Indonesia' },
  { keywords: ['niagahoster'], email: 'abuse@niagahoster.co.id', name: 'PT Niagahoster' },
  { keywords: ['idwebhost'], email: 'abuse@idwebhost.com', name: 'IDwebhost' }
];

function getMainDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  
  const len = parts.length;
  const secondToLast = parts[len - 2];
  const last = parts[len - 1];
  const commonDoubleTlds = ['com', 'co', 'net', 'org', 'ac', 'sch', 'go', 'web', 'my', 'biz'];
  
  if (commonDoubleTlds.includes(secondToLast) && last.length === 2) {
    return parts.slice(len - 3).join('.');
  }
  return parts.slice(len - 2).join('.');
}

// --- Real security checks (replaces previously hardcoded/simulated data) ---

// Check the live TLS/SSL certificate by opening a real TLS socket to port 443
function checkSSL(hostname) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    try {
      const socket = tls.connect(
        { host: hostname, port: 443, servername: hostname, timeout: 6000, rejectUnauthorized: false },
        () => {
          const cert = socket.getPeerCertificate();
          socket.end();
          if (cert && Object.keys(cert).length > 0 && cert.valid_to) {
            const now = new Date();
            const validTo = new Date(cert.valid_to);
            const daysLeft = Math.round((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
            finish({
              status: daysLeft <= 0 ? 'CRITICAL' : daysLeft < 14 ? 'WARNING' : 'PASSED',
              issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown Issuer',
              expiry: cert.valid_to,
              daysLeft
            });
          } else {
            finish({ status: 'UNKNOWN', issuer: null, expiry: null, daysLeft: null });
          }
        }
      );
      socket.on('error', (err) => {
        finish({ status: 'CRITICAL', issuer: null, expiry: null, daysLeft: null, error: err.message });
      });
      socket.on('timeout', () => {
        socket.destroy();
        finish({ status: 'UNKNOWN', issuer: null, expiry: null, daysLeft: null, error: 'Connection timeout' });
      });
    } catch (err) {
      finish({ status: 'UNKNOWN', issuer: null, expiry: null, daysLeft: null, error: err.message });
    }
  });
}

// Check whether a single TCP port is open via a real connection attempt
function checkPort(hostname, port, timeout = 1500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let open = false;
    socket.setTimeout(timeout);
    socket.once('connect', () => {
      open = true;
      socket.destroy();
    });
    socket.once('timeout', () => socket.destroy());
    socket.once('error', () => socket.destroy());
    socket.once('close', () => resolve(open));
    socket.connect(port, hostname);
  });
}

// Scan a short list of commonly abused ports (real TCP connect, not simulated)
async function checkOpenPorts(hostname) {
  const portsToCheck = [
    { port: 21, label: 'FTP' },
    { port: 22, label: 'SSH' },
    { port: 80, label: 'HTTP' },
    { port: 443, label: 'HTTPS' },
    { port: 3306, label: 'MySQL' },
    { port: 3389, label: 'RDP' }
  ];
  const results = await Promise.all(
    portsToCheck.map(async (p) => ({ ...p, open: await checkPort(hostname, p.port) }))
  );
  return results;
}

// Check the hostname against abuse.ch URLhaus, a public malware/phishing
// URL database. As of their updated policy, this requires a free Auth-Key
// (get one at https://auth.abuse.ch/) sent via the "Auth-Key" header.
async function checkBlacklist(hostname) {
  const authKey = process.env.URLHAUS_AUTH_KEY;
  if (!authKey) {
    return {
      status: 'UNKNOWN',
      detail: 'URLHAUS_AUTH_KEY not configured - get a free key at auth.abuse.ch'
    };
  }
  try {
    const res = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Auth-Key': authKey
      },
      body: `host=${encodeURIComponent(hostname)}`
    });
    if (!res.ok) {
      return { status: 'UNKNOWN', detail: `URLhaus lookup returned HTTP ${res.status}` };
    }
    const data = await res.json();
    if (data.query_status === 'ok') {
      const urlCount = Array.isArray(data.urls) ? data.urls.length : 0;
      return {
        status: 'CRITICAL',
        detail: `Listed on URLhaus: ${urlCount} malicious URL(s) reported for this host`
      };
    }
    return { status: 'PASSED', detail: 'Not found on URLhaus abuse database' };
  } catch (err) {
    return { status: 'UNKNOWN', detail: `Blacklist check failed: ${err.message}` };
  }
}

// Check a URL against the real Google Safe Browsing Lookup API (v4).
// This is a genuine verification check (is the URL already known-malicious
// to Google), NOT a submission - Google does not offer a public API to
// submit new URLs, only a manual report form. Requires a free API key from
// Google Cloud Console (Safe Browsing API) set as GOOGLE_SAFE_BROWSING_API_KEY.
async function checkGoogleSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) {
    return { status: 'UNKNOWN', threatTypes: null, detail: 'GOOGLE_SAFE_BROWSING_API_KEY not configured' };
  }
  try {
    const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'phishing-reporter-backend', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      })
    });
    if (!res.ok) {
      return { status: 'UNKNOWN', threatTypes: null, detail: `Safe Browsing API returned HTTP ${res.status}` };
    }
    const data = await res.json();
    if (Array.isArray(data.matches) && data.matches.length > 0) {
      const types = [...new Set(data.matches.map(m => m.threatType))].join(', ');
      return { status: 'FLAGGED', threatTypes: types, detail: `Already flagged by Google Safe Browsing: ${types}` };
    }
    return { status: 'CLEAN', threatTypes: null, detail: 'Not currently flagged by Google Safe Browsing' };
  } catch (err) {
    return { status: 'UNKNOWN', threatTypes: null, detail: `Safe Browsing check failed: ${err.message}` };
  }
}

// Detect CDN/WAF providers from real HTTP response headers
async function detectCDN(url) {
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'follow' });
    const server = (res.headers.get('server') || '').toLowerCase();
    const via = (res.headers.get('via') || '').toLowerCase();
    const servedBy = (res.headers.get('x-served-by') || '').toLowerCase();
    const combined = `${server} ${via} ${servedBy}`;

    if (res.headers.get('cf-ray') || combined.includes('cloudflare')) return 'Cloudflare';
    if (combined.includes('akamai')) return 'Akamai';
    if (combined.includes('fastly')) return 'Fastly';
    if (combined.includes('cloudfront')) return 'Amazon CloudFront';
    if (combined.includes('sucuri')) return 'Sucuri';
    if (combined.includes('imperva') || combined.includes('incapsula')) return 'Imperva';
    if (combined.includes('vercel')) return 'Vercel Edge Network';
    return null;
  } catch (err) {
    return null;
  }
}

export async function processForensicJob(jobData) {
  const { reportId, url } = jobData;
  console.log(`[Worker] Starting forensic processing for Report ID: ${reportId}, URL: ${url}`);

  const db = await getDb();

  // Initialize fields
  let ipAddress = 'Unknown';
  let hostingProvider = 'Unknown';
  let abuseEmail = 'abuse@domain-registrar.com'; // Default fallback
  let registrarName = 'Unknown';
  let registrarAbuseEmail = null;
  let ipHostingProvider = 'Unknown';
  let ipAbuseEmail = null;
  let domainRegisteredAt = null;
  let domainAgeDays = null;

  const parsedUrl = new URL(url);
  const hostname = parsedUrl.hostname;
  const isDirectIp = net.isIP(hostname) !== 0;

  if (isDirectIp) {
    ipAddress = hostname;
    console.log(`[Worker] Hostname is direct IP address: ${ipAddress}`);
  } else {
    const mainDomain = getMainDomain(hostname);

    // 1. Query Domain RDAP for Registrar Info
    try {
      console.log(`[Worker] Querying Domain RDAP for: ${mainDomain}`);
      const domainRes = await fetch(`https://rdap.org/domain/${mainDomain}`, {
        headers: { 'Accept': 'application/json' }
      });
      if (domainRes.ok) {
        const rdapData = await domainRes.json();
        
        // Extract registrar name
        if (Array.isArray(rdapData.entities)) {
          const registrarEntity = rdapData.entities.find(e => Array.isArray(e.roles) && (e.roles.includes('registrar') || e.roles.includes('registrant')));
          if (registrarEntity) {
            if (registrarEntity.vcardArray && registrarEntity.vcardArray[1]) {
              const fnItem = registrarEntity.vcardArray[1].find(item => item[0] === 'fn');
              if (fnItem && fnItem[3]) registrarName = fnItem[3];
            }
            if (registrarName === 'Unknown' && registrarEntity.handle) {
              registrarName = registrarEntity.handle;
            }
          }
        }
        
        // Extract registrar abuse email
        registrarAbuseEmail = extractAbuseEmail(rdapData);
        console.log(`[Worker] Domain RDAP - Registrar: ${registrarName}, Abuse Email: ${registrarAbuseEmail}`);

        // Extract domain registration date for real domain-age calculation
        if (Array.isArray(rdapData.events)) {
          const regEvent = rdapData.events.find(e => e.eventAction === 'registration');
          if (regEvent && regEvent.eventDate) {
            domainRegisteredAt = regEvent.eventDate;
            const now = new Date();
            const registeredDate = new Date(regEvent.eventDate);
            domainAgeDays = Math.round((now.getTime() - registeredDate.getTime()) / (1000 * 60 * 60 * 24));
            console.log(`[Worker] Domain registered ${domainAgeDays} days ago (${domainRegisteredAt})`);
          }
        }
      }
    } catch (err) {
      console.error(`[Worker] Domain RDAP query failed:`, err.message);
    }

    // Match against Registrar Abuse Map dictionary if missing email or name clean-up
    for (const item of REGISTRAR_ABUSE_MAP) {
      const match = item.keywords.some(k => 
        (registrarName && registrarName.toLowerCase().includes(k)) ||
        (mainDomain && mainDomain.toLowerCase().includes(k))
      );
      if (match) {
        if (registrarName === 'Unknown' || !registrarName) {
          registrarName = item.name;
        }
        if (!registrarAbuseEmail) {
          registrarAbuseEmail = item.email;
          console.log(`[Worker] Matched Registrar Dictionary - ${item.name} (${item.email})`);
        }
        break;
      }
    }

    // 2. Resolve DNS IP Address (Try dns.lookup first, then dns.resolve4, then DoH)
    try {
      const lookupRes = await dns.lookup(hostname);
      if (lookupRes && lookupRes.address) {
        ipAddress = lookupRes.address;
        console.log(`[Worker] Resolved IP via OS DNS Lookup: ${ipAddress} for ${hostname}`);
      }
    } catch (err) {
      console.warn(`[Worker] OS DNS lookup failed: ${err.message}. Trying dns.resolve4...`);
      try {
        const ips = await dns.resolve4(hostname);
        if (ips && ips.length > 0) {
          ipAddress = ips[0];
          console.log(`[Worker] Resolved IP via Node dns.resolve4: ${ipAddress} for ${hostname}`);
        }
      } catch (resErr) {
        console.warn(`[Worker] Node dns.resolve4 failed: ${resErr.message}. Trying Cloudflare DoH fallback...`);
        try {
          const dohRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`, {
            headers: { 'Accept': 'application/dns-json' }
          });
          if (dohRes.ok) {
            const dohData = await dohRes.json();
            if (Array.isArray(dohData.Answer)) {
              const aRecord = dohData.Answer.find(ans => ans.type === 1); // 1 = A record
              if (aRecord && aRecord.data) {
                ipAddress = aRecord.data;
                console.log(`[Worker] Resolved IP via DoH: ${ipAddress} for ${hostname}`);
              }
            }
          }
        } catch (dohErr) {
          console.error(`[Worker] DoH resolution fallback failed:`, dohErr.message);
        }
      }
    }
  }

  // 3. Query IP RDAP for Hosting Provider Info
  if (ipAddress !== 'Unknown') {
    try {
      console.log(`[Worker] Querying IP RDAP for: ${ipAddress}`);
      const ipRes = await fetch(`https://rdap.org/ip/${ipAddress}`, {
        headers: { 'Accept': 'application/json' }
      });
      if (ipRes.ok) {
        const rdapData = await ipRes.json();
        
        // Extract hosting provider name
        if (rdapData.name) {
          ipHostingProvider = rdapData.name;
        } else if (Array.isArray(rdapData.remarks) && rdapData.remarks[0]?.title) {
          ipHostingProvider = rdapData.remarks[0].title;
        }
        
        // Extract hosting provider abuse email
        ipAbuseEmail = extractAbuseEmail(rdapData);
        console.log(`[Worker] IP RDAP - Hosting Provider: ${ipHostingProvider}, Abuse Email: ${ipAbuseEmail}`);
      }
    } catch (err) {
      console.error(`[Worker] IP RDAP query failed:`, err.message);
    }
  }

  // Combine results
  if (registrarName !== 'Unknown' && ipHostingProvider !== 'Unknown') {
    hostingProvider = `${registrarName} (Hosting: ${ipHostingProvider})`;
  } else if (registrarName !== 'Unknown') {
    hostingProvider = registrarName;
  } else if (ipHostingProvider !== 'Unknown') {
    hostingProvider = ipHostingProvider;
  }

  if (registrarAbuseEmail) {
    abuseEmail = registrarAbuseEmail;
  } else if (ipAbuseEmail) {
    abuseEmail = ipAbuseEmail;
  }

  // 3b. Run real security checks in parallel: SSL cert, open ports,
  // blacklist status, and CDN detection. None of these are simulated.
  console.log(`[Worker] Running SSL / port scan / blacklist / CDN checks for ${hostname}`);
  const [sslResult, portsResult, blacklistResult, cdnProvider, gsbResult] = await Promise.all([
    checkSSL(hostname),
    checkOpenPorts(hostname),
    checkBlacklist(hostname),
    detectCDN(url),
    checkGoogleSafeBrowsing(url)
  ]);
  console.log(`[Worker] SSL: ${sslResult.status}, Blacklist: ${blacklistResult.status}, CDN: ${cdnProvider || 'None detected'}, Google Safe Browsing: ${gsbResult.status}`);

  // 4. Playwright browser setup (Mobile Spoofing & Screenshot & Outgoing Links)
  let browser = null;
  let screenshotPath = '';
  let screenshotUrl = '';
  let crossDomainLinks = [];

  try {
    // Ensure public/screenshots folder exists
    const publicScreenshotsDir = path.join(__dirname, '../public/screenshots');
    if (!fs.existsSync(publicScreenshotsDir)) {
      fs.mkdirSync(publicScreenshotsDir, { recursive: true });
    }

    browser = await chromium.launch({ headless: true });
    
    // Create mobile context
    const context = await browser.newContext({
      userAgent: 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
      viewport: { width: 390, height: 844 },
      deviceScaleFactor: 3,
      isMobile: true,
      hasTouch: true
    });

    const page = await context.newPage();
    console.log(`[Worker] Browser visiting URL: ${url}`);
    
    // Navigate with 15s timeout
    await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });

    // Capture screenshot (JPG format)
    const screenshotFilename = `${reportId}.jpg`;
    screenshotPath = path.join(publicScreenshotsDir, screenshotFilename);
    
    await page.screenshot({
      path: screenshotPath,
      type: 'jpeg',
      quality: 80,
      fullPage: true
    });

    screenshotUrl = `/screenshots/${screenshotFilename}`;
    console.log(`[Worker] Screenshot saved to ${screenshotPath}`);

    // Extract outgoing links
    const baseDomain = new URL(url).hostname.replace('www.', '');
    
    const pageLinks = await page.evaluate(() => {
      const links = [];
      document.querySelectorAll('a, area').forEach(el => {
        if (el.href) links.push({ url: el.href, tag: 'link' });
      });
      document.querySelectorAll('form').forEach(el => {
        if (el.action) links.push({ url: el.action, tag: 'form' });
      });
      return links;
    });

    for (const link of pageLinks) {
      try {
        const targetUrl = new URL(link.url);
        const targetDomain = targetUrl.hostname.replace('www.', '');
        
        // Match only cross-domains
        if (targetDomain !== baseDomain && (targetUrl.protocol.startsWith('http') || targetUrl.protocol.startsWith('mailto') || targetUrl.protocol === 'whatsapp:' || targetUrl.protocol === 'tel:')) {
          if (!crossDomainLinks.some(l => l.url === link.url)) {
            let type = 'other';
            if (targetDomain.includes('wa.me') || targetDomain.includes('whatsapp.com')) {
              type = 'whatsapp';
            } else if (targetDomain.includes('t.me') || targetDomain.includes('telegram.me') || targetDomain.includes('telegram.org')) {
              type = 'telegram';
            } else if (targetDomain.includes('forms.gle') || targetDomain.includes('docs.google.com/forms')) {
              type = 'google_form';
            } else if (link.url.endsWith('.apk') || link.url.includes('.apk?')) {
              type = 'apk';
            }
            
            crossDomainLinks.push({
              url: link.url,
              domain: targetDomain,
              type
            });
          }
        }
      } catch (err) {
        // Ignore invalid URLs
      }
    }
    console.log(`[Worker] Harvested ${crossDomainLinks.length} outgoing cross-domain links.`);

  } catch (err) {
    console.error(`[Worker] Playwright session error:`, err.message);
  } finally {
    if (browser) {
      await browser.close();
      console.log(`[Worker] Browser closed.`);
    }
  }

  // 5. Update the report in the database
  try {
    await db.run(
      `UPDATE reports 
       SET ip_address = ?, 
           hosting_provider = ?, 
           abuse_email = ?, 
           screenshot_url = ?, 
           outgoing_links = ?,
           ssl_status = ?,
           ssl_issuer = ?,
           ssl_expiry = ?,
           ssl_days_left = ?,
           domain_registered_at = ?,
           domain_age_days = ?,
           registrar_name = ?,
           open_ports = ?,
           blacklist_status = ?,
           blacklist_detail = ?,
           cdn_provider = ?,
           gsb_status = ?,
           gsb_threat_types = ?,
           last_checked_at = datetime('now'),
           updated_at = datetime('now')
       WHERE id = ?`,
      ipAddress,
      hostingProvider,
      abuseEmail,
      screenshotUrl || null,
      JSON.stringify(crossDomainLinks),
      sslResult.status,
      sslResult.issuer,
      sslResult.expiry,
      sslResult.daysLeft,
      domainRegisteredAt,
      domainAgeDays,
      registrarName !== 'Unknown' ? registrarName : null,
      JSON.stringify(portsResult),
      blacklistResult.status,
      blacklistResult.detail,
      cdnProvider,
      gsbResult.status,
      gsbResult.threatTypes,
      reportId
    );
    console.log(`[Worker] Database record updated successfully for Report ID: ${reportId}`);
  } catch (err) {
    console.error(`[Worker] Database write error:`, err.message);
  }
}

// Helper: Extract abuse email from RDAP JSON
function extractAbuseEmail(rdapData) {
  if (!rdapData) return null;
  
  let foundEmails = [];
  
  function searchEntities(entities) {
    if (!Array.isArray(entities)) return;
    
    for (const entity of entities) {
      let isAbuseRole = Array.isArray(entity.roles) && entity.roles.includes('abuse');
      
      if (Array.isArray(entity.vcardArray) && entity.vcardArray[1]) {
        const vc = entity.vcardArray[1];
        for (const item of vc) {
          if (Array.isArray(item) && item[0] === 'email') {
            const email = item[3];
            if (email) {
              const isAbuseEmail = isAbuseRole || email.toLowerCase().includes('abuse');
              foundEmails.push({ email, isAbuse: isAbuseEmail });
            }
          }
        }
      }
      
      if (entity.entities) {
        searchEntities(entity.entities);
      }
    }
  }
  
  if (rdapData.entities) {
    searchEntities(rdapData.entities);
  }
  
  // Fallback: search JSON string for abuse emails
  if (foundEmails.length === 0) {
    try {
      const jsonStr = JSON.stringify(rdapData);
      const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
      const matches = jsonStr.match(emailRegex);
      if (matches) {
        for (const email of matches) {
          const isAbuse = email.toLowerCase().includes('abuse');
          foundEmails.push({ email, isAbuse });
        }
      }
    } catch (e) {
      // Ignore stringify errors
    }
  }
  
  const abuseEmails = foundEmails.filter(e => e.isAbuse);
  if (abuseEmails.length > 0) {
    return abuseEmails[0].email;
  }
  
  if (foundEmails.length > 0) {
    return foundEmails[0].email;
  }
  
  return null;
}