import { chromium } from 'playwright';
import dns from 'dns/promises';
import { getDb } from './db.js';

export async function runJanitorCheck() {
  console.log('[Janitor] Starting scheduled site death checks...');
  const db = await getDb();
  
  // Fetch top 50 oldest checked APPROVED reports
  const reports = await db.all(
    `SELECT * FROM reports 
     WHERE status = 'APPROVED' 
     ORDER BY last_checked_at ASC, id ASC 
     LIMIT 50`
  );
  
  if (reports.length === 0) {
    console.log('[Janitor] No APPROVED websites found to verify.');
    return;
  }
  
  console.log(`[Janitor] Verifying ${reports.length} websites...`);
  
  let browser = null;
  try {
    browser = await chromium.launch({ headless: true });
    
    for (const report of reports) {
      console.log(`[Janitor] Checking website: ${report.reported_url}`);
      let isTakenDown = false;
      let reason = '';
      
      // 1. DNS Check
      try {
        const parsedUrl = new URL(report.reported_url);
        let hasIp = false;
        try {
          const lookupRes = await dns.lookup(parsedUrl.hostname);
          if (lookupRes && lookupRes.address) hasIp = true;
        } catch (_) {
          const ips = await dns.resolve4(parsedUrl.hostname);
          if (ips && ips.length > 0) hasIp = true;
        }

        if (!hasIp) {
          isTakenDown = true;
          reason = 'DNS returned no IP addresses';
        }
      } catch (err) {
        if (err.code === 'ENOTFOUND' || err.code === 'ENODATA' || err.code === 'ETIMEOUT') {
          isTakenDown = true;
          reason = `DNS Resolution failed (${err.code} / NXDOMAIN)`;
        }
      }
      
      // 2. HTTP Check (if DNS succeeded)
      if (!isTakenDown) {
        const page = await browser.newPage();
        try {
          const response = await page.goto(report.reported_url, { 
            waitUntil: 'domcontentloaded', 
            timeout: 10000 
          });
          
          if (response) {
            const status = response.status();
            if (status === 404 || status === 410) {
              isTakenDown = true;
              reason = `HTTP Status code is ${status}`;
            } else {
              // Check for browser security warnings / red screen
              const content = await page.content();
              if (content.toLowerCase().includes('deceptive site ahead') || 
                  content.toLowerCase().includes('dangerous site') || 
                  content.toLowerCase().includes('phishing site') || 
                  content.toLowerCase().includes('situs berbahaya')) {
                isTakenDown = true;
                reason = 'Safe Browsing Interstitial warning page detected';
              }
            }
          } else {
            isTakenDown = true;
            reason = 'HTTP response was null (connection reset/refused)';
          }
        } catch (err) {
          const errMsg = err.message.toLowerCase();
          if (errMsg.includes('net::err_connection_refused') || 
              errMsg.includes('net::err_name_not_resolved') || 
              errMsg.includes('timeout') || 
              errMsg.includes('net::err_connection_timed_out')) {
            isTakenDown = true;
            reason = `Connection error: ${err.message}`;
          }
        } finally {
          await page.close();
        }
      }
      
      if (isTakenDown) {
        console.log(`[Janitor] SUCCESS: Site ${report.reported_url} is DOWN. Reason: ${reason}`);
        await db.run(
          `UPDATE reports 
           SET status = 'COMPLETED', 
               last_checked_at = datetime('now'),
               updated_at = datetime('now')
           WHERE id = ?`,
          report.id
        );
      } else {
        console.log(`[Janitor] ACTIVE: Site ${report.reported_url} is still online.`);
        await db.run(
          `UPDATE reports 
           SET last_checked_at = datetime('now'),
               updated_at = datetime('now')
           WHERE id = ?`,
          report.id
        );
      }
    }
  } catch (err) {
    console.error('[Janitor] Fatal error during checking process:', err);
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

export function initJanitor() {
  // Run every 1 hour (3600000 ms)
  const INTERVAL = 60 * 60 * 1000;
  setInterval(() => {
    runJanitorCheck().catch(err => console.error('[Janitor Interval Error]', err));
  }, INTERVAL);
  console.log('[Janitor] Scheduler started (verifies sites every 1 hour).');
}
