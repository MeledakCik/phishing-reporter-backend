import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { sendAbuseReport, sendKominfoReport, reportToVercelAbuse, sendApwgReport } from './mailer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function dispatchMultiChannelThreatReport(report) {
  const targetUrl = report.reported_url;

  console.log(`\n==================================================`);
  console.log(`[Multi-Channel Dispatcher] INITIATING MULTI-VECTOR REPORT FOR: ${targetUrl}`);
  console.log(`==================================================`);

  const results = {
    registrar_abuse: null,
    apwg: null,
    kominfo_aduan_konten: null,
    google_safe_browsing: null,
    vercel_abuse: null,
    dispatched_at: new Date().toISOString()
  };

  // 1. Registrar & Hosting Provider Email Abuse Report (real send via Resend)
  try {
    const mailResult = await sendAbuseReport(report);
    results.registrar_abuse = {
      status: mailResult.status,
      target: mailResult.to,
      subject: mailResult.subject,
      message_id: mailResult.message_id || null
    };
  } catch (err) {
    results.registrar_abuse = { status: 'FAILED', error: err.message };
  }

  // 1b. APWG (Anti-Phishing Working Group) eCrime Exchange - real send via
  // Resend, feeds the shared threat-intelligence clearinghouse used by many
  // browsers/security vendors.
  try {
    const apwgResult = await sendApwgReport(report);
    results.apwg = {
      status: apwgResult.status,
      target: apwgResult.to,
      subject: apwgResult.subject,
      message_id: apwgResult.message_id || null
    };
  } catch (err) {
    results.apwg = { status: 'FAILED', error: err.message };
  }

  // 2. Kominfo Aduan Konten - real email intake for Indonesian content
  // takedowns (aduankonten.id itself requires a manual account + CAPTCHA
  // and cannot be automated; the email intake is the legitimate channel).
  try {
    const kominfoResult = await sendKominfoReport(report);
    results.kominfo_aduan_konten = {
      status: kominfoResult.status,
      target: kominfoResult.to,
      subject: kominfoResult.subject,
      message_id: kominfoResult.message_id || null
    };
  } catch (err) {
    results.kominfo_aduan_konten = { status: 'FAILED', error: err.message };
  }

  // 3b. Vercel abuse desk - only fired when the CDN/host fingerprint from
  // the forensic scan actually identified Vercel infrastructure. Vercel has
  // no public "report abuse" API, so this emails abuse@vercel.com directly.
  if ((report.cdn_provider || '').toLowerCase().includes('vercel')) {
    try {
      const vercelResult = await reportToVercelAbuse(targetUrl);
      results.vercel_abuse = {
        status: vercelResult.status,
        target: vercelResult.to,
        subject: vercelResult.subject,
        message_id: vercelResult.id || vercelResult.message_id || null,
        error: vercelResult.error || null
      };
    } catch (err) {
      results.vercel_abuse = { status: 'FAILED', error: err.message };
    }
  } else {
    results.vercel_abuse = {
      status: 'SKIPPED',
      note: 'CDN fingerprint did not match Vercel - no report sent.'
    };
  }

  // 3. Google Safe Browsing - this is a VERIFICATION check (was this URL
  // already run against Google's real threat lists during forensic
  // processing), not a submission. Google has no public API to submit new
  // URLs - only a manual report form (https://safebrowsing.google.com/safebrowsing/report_phish/).
  results.google_safe_browsing = {
    status: report.gsb_status || 'UNKNOWN',
    threat_types: report.gsb_threat_types || null,
    note: report.gsb_status
      ? 'Verification result from Google Safe Browsing Lookup API (checked during forensic scan).'
      : 'Not checked yet - GOOGLE_SAFE_BROWSING_API_KEY may not be configured.',
    manual_submission_url: 'https://safebrowsing.google.com/safebrowsing/report_phish/'
  };

  // Save dispatch report log locally
  try {
    const dispatchDir = path.join(__dirname, '../dispatched_threat_reports');
    if (!fs.existsSync(dispatchDir)) {
      fs.mkdirSync(dispatchDir, { recursive: true });
    }
    const logFile = path.join(dispatchDir, `${report.id}_channels.json`);
    fs.writeFileSync(logFile, JSON.stringify(results, null, 2), 'utf8');
    console.log(`[Multi-Channel Dispatcher] Threat report log saved: ${logFile}`);
  } catch (e) {
    console.error(`[Multi-Channel Dispatcher] Failed to save log file:`, e.message);
  }

  return results;
}
