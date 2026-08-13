import { chromium } from 'playwright';
import dns from 'dns/promises';
import net from 'net';
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
           updated_at = datetime('now')
       WHERE id = ?`,
      ipAddress,
      hostingProvider,
      abuseEmail,
      screenshotUrl || null,
      JSON.stringify(crossDomainLinks),
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
