import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { getDb } from './db.js';
import { getQueue } from './queue.js';
import { initJanitor, runJanitorCheck } from './janitor.js';
import { sendAbuseReport } from './mailer.js';
import { dispatchMultiChannelThreatReport } from './threat_dispatcher.js';
import { verifyTurnstileToken } from './turnstile.js';

dotenv.config();

// Bump this string whenever you deploy a change you want to visually verify
// in the logs (e.g. after fixing the Kominfo Gmail SMTP routing). Printed at
// startup so you can immediately confirm the running process is on the new
// build and not a stale/cached one.
const BUILD_TAG = 'verify-deploy-2026-08-15-12-30';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 5000;

// Trust the first proxy hop (Railway/Vercel-style reverse proxies) so
// req.ip reflects the real client IP instead of the proxy's address.
app.set('trust proxy', 1);

// Enable CORS for frontend and JSON request parsing
// CORS_ORIGIN can be a comma-separated list of allowed origins.
// If unset, all origins are allowed (useful for local dev).
const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map((o) => o.trim())
  : true;
app.use(cors({ origin: allowedOrigins }));
app.use(express.json());

// Serve static screenshots folder (e.g. localhost:5000/screenshots/uuid.jpg)
app.use('/screenshots', express.static(path.join(__dirname, '../public/screenshots')));

// 1. Submit Phishing URL (Deduplication Layer)
app.post('/api/reports', async (req, res) => {
  const { reported_url, target_brand_raw, captcha_token } = req.body;

  if (!reported_url || !target_brand_raw) {
    return res.status(400).json({ success: false, message: 'URL and target brand are required.' });
  }

  // Verify the Cloudflare Turnstile token server-side before doing anything
  // else. This is the real anti-bot gate; the frontend widget alone is not
  // trustworthy since a POST can bypass the UI entirely.
  const turnstileResult = await verifyTurnstileToken(captcha_token, req.ip);
  if (!turnstileResult.success) {
    console.warn('[API] Turnstile verification failed:', turnstileResult.errorCodes);
    return res.status(400).json({ success: false, message: 'CAPTCHA verification failed. Please try again.' });
  }

  // Validate URL format
  let normalizedUrl = '';
  try {
    const parsed = new URL(reported_url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return res.status(400).json({ success: false, message: 'Only HTTP and HTTPS URLs are accepted.' });
    }
    // Normalize URL: remove trailing slash and trim
    normalizedUrl = parsed.origin + parsed.pathname.replace(/\/$/, '') + parsed.search;
  } catch (err) {
    return res.status(400).json({ success: false, message: 'Invalid URL format.' });
  }

  try {
    const db = await getDb();
    
    // Increment brand suggestion hits dynamically or insert
    await db.run(
      `INSERT INTO brand_suggestions (brand_name, hit_count) 
       VALUES (?, 1) 
       ON CONFLICT(brand_name) DO UPDATE SET hit_count = hit_count + 1`,
      target_brand_raw.trim()
    );

    // Check database for duplicates
    let existingReport = await db.get('SELECT * FROM reports WHERE reported_url = ?', normalizedUrl);

    if (existingReport) {
      // Increment hit count
      const newHitCount = existingReport.hit_count + 1;
      await db.run("UPDATE reports SET hit_count = ?, updated_at = datetime('now') WHERE id = ?", newHitCount, existingReport.id);
      
      // Fetch updated record
      existingReport = await db.get('SELECT * FROM reports WHERE id = ?', existingReport.id);

      let statusMsg = '';
      switch (existingReport.status) {
        case 'PENDING':
          statusMsg = `This site has already been reported ${newHitCount} times. Our analyst team is currently gathering forensic evidence.`;
          break;
        case 'APPROVED':
          statusMsg = `This site has been verified as dangerous and reported to its hosting provider. The takedown process is underway.`;
          break;
        case 'COMPLETED':
          statusMsg = `Success! This dangerous site has been successfully taken down.`;
          break;
        case 'REJECTED':
          statusMsg = `This site has been reviewed by our analyst team and marked as safe or not matching phishing criteria.`;
          break;
        default:
          statusMsg = `This site is already in our threat intelligence hub.`;
      }

      return res.json({
        success: true,
        is_duplicate: true,
        message: statusMsg,
        data: existingReport
      });
    }

    // Insert new report (Case 1: Brand New URL)
    const reportId = crypto.randomUUID();
    await db.run(
      `INSERT INTO reports (id, reported_url, target_brand_raw, status, hit_count) 
       VALUES (?, ?, ?, 'PENDING', 1)`,
      reportId,
      normalizedUrl,
      target_brand_raw.trim()
    );

    const newReport = await db.get('SELECT * FROM reports WHERE id = ?', reportId);

    // Push task to queue
    const queue = await getQueue();
    await queue.add('forensic_scan', { reportId, url: normalizedUrl });

    return res.status(201).json({
      success: true,
      is_duplicate: false,
      message: 'Thank you, your report has been received and queued for forensic analysis.',
      data: newReport
    });

  } catch (err) {
    console.error('[API] Error in /api/reports:', err);
    return res.status(500).json({ success: false, message: 'Internal server database error.' });
  }
});

// 2. Check Submission Status via URL query
app.get('/api/reports/status', async (req, res) => {
  const { url } = req.query;
  if (!url) {
    return res.status(400).json({ success: false, message: 'URL query parameter is required.' });
  }

  try {
    let normalizedUrl = url.trim();
    try {
      const parsed = new URL(url);
      normalizedUrl = parsed.origin + parsed.pathname.replace(/\/$/, '') + parsed.search;
    } catch (_) {}

    const db = await getDb();
    const report = await db.get('SELECT * FROM reports WHERE reported_url = ?', normalizedUrl);
    if (!report) {
      return res.status(404).json({ success: false, message: 'No report found for this URL.' });
    }

    return res.json({ success: true, data: report });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error retrieving status.' });
  }
});

// 3. Admin Get Pending Cases for review (Sorted by hit_count DESC)
app.get('/api/reports/pending', async (req, res) => {
  try {
    const db = await getDb();
    const reports = await db.all(
      `SELECT * FROM reports 
       WHERE status = 'PENDING' 
       ORDER BY hit_count DESC, created_at DESC`
    );
    
    // Parse outgoing_links JSON string for each report
    const formattedReports = reports.map(r => ({
      ...r,
      outgoing_links: JSON.parse(r.outgoing_links || '[]')
    }));

    return res.json(formattedReports);
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server database query error.' });
  }
});

// 4. Admin Approve & Send Takedown Report
app.post('/api/reports/:id/approve', async (req, res) => {
  const { id } = req.params;

  try {
    const db = await getDb();
    const report = await db.get('SELECT * FROM reports WHERE id = ?', id);

    if (!report) {
      return res.status(404).json({ success: false, message: 'Report not found.' });
    }

    // Call Multi-Channel Threat Dispatcher (Registrar/Hosting abuse email,
    // Kominfo Aduan Konten, Google Safe Browsing verification)
    const multiChannelResults = await dispatchMultiChannelThreatReport(report);

    // Update status to APPROVED
    await db.run(
      `UPDATE reports 
       SET status = 'APPROVED', 
           last_checked_at = datetime('now'),
           updated_at = datetime('now')
       WHERE id = ?`,
      id
    );

    return res.json({
      success: true,
      message: `Report approved. Abuse email dispatched to hosting/registrar and Kominfo Aduan Konten; Google Safe Browsing status included from forensic scan.`,
      dispatched_channels: multiChannelResults
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error during approval process.' });
  }
});

// 5. Admin Reject Report
app.post('/api/reports/:id/reject', async (req, res) => {
  const { id } = req.params;

  try {
    const db = await getDb();
    const report = await db.get('SELECT * FROM reports WHERE id = ?', id);

    if (!report) {
      return res.status(404).json({ success: false, message: 'Report not found.' });
    }

    // Update status to REJECTED
    await db.run(
      `UPDATE reports 
       SET status = 'REJECTED', 
           updated_at = datetime('now')
       WHERE id = ?`,
      id
    );

    return res.json({
      success: true,
      message: 'Report rejected.'
    });

  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error during rejection.' });
  }
});

// 5b. Admin Delete All Pending Reports
app.delete('/api/reports/pending', async (req, res) => {
  try {
    const db = await getDb();
    const result = await db.run("DELETE FROM reports WHERE status = 'PENDING'");
    return res.json({
      success: true,
      message: `Deleted ${result.changes || 0} pending report(s) from the platform.`
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error deleting pending reports.' });
  }
});

// 5c. Admin Delete Single Report by ID
app.delete('/api/reports/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const db = await getDb();
    const result = await db.run('DELETE FROM reports WHERE id = ?', id);
    if (result.changes === 0) {
      return res.status(404).json({ success: false, message: 'Report not found.' });
    }
    return res.json({ success: true, message: `Report ${id} deleted.` });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error deleting report.' });
  }
});

// 6. Get Brand Suggestions autocomplete
app.get('/api/brands', async (req, res) => {
  const { q } = req.query;
  try {
    const db = await getDb();
    let suggestions;
    if (q) {
      suggestions = await db.all(
        'SELECT brand_name FROM brand_suggestions WHERE brand_name LIKE ? ORDER BY hit_count DESC LIMIT 10',
        `%${q}%`
      );
    } else {
      suggestions = await db.all(
        'SELECT brand_name FROM brand_suggestions ORDER BY hit_count DESC LIMIT 10'
      );
    }
    return res.json(suggestions.map(s => s.brand_name));
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error querying brand suggestions.' });
  }
});

// 7. Manual Janitor Trigger (For Testing/Verification)
app.post('/api/janitor/run', async (req, res) => {
  try {
    await runJanitorCheck();
    return res.json({ success: true, message: 'Janitor run completed.' });
  } catch (err) {
    return res.status(500).json({ success: false, message: `Janitor manual trigger failed: ${err.message}` });
  }
});

// Serve compiled React frontend assets in production mode
const clientDistPath = path.join(__dirname, '../../client/dist');
if (fs.existsSync(clientDistPath)) {
  console.log(`[Static] Serving client assets from: ${clientDistPath}`);
  app.use(express.static(clientDistPath));
  app.get('*', (req, res, next) => {
    // Let API routes bypass this SPA fallback
    if (req.url.startsWith('/api') || req.url.startsWith('/screenshots')) {
      return next();
    }
    res.sendFile(path.join(clientDistPath, 'index.html'));
  });
} else {
  console.log(`[Static] Production assets not found at ${clientDistPath}. Dev proxy expected.`);
}

// Start Server and Janitor Cron Job Scheduler
async function start() {
  try {
    console.log(`[Build] Running build tag: ${BUILD_TAG}`);
    console.log(`[Build] GMAIL_USER configured: ${process.env.GMAIL_USER ? 'yes' : 'NO - Kominfo emails will be SIMULATED_NOT_SENT'}`);
    console.log(`[Build] GMAIL_APP_PASSWORD configured: ${process.env.GMAIL_APP_PASSWORD ? 'yes' : 'NO - Kominfo emails will be SIMULATED_NOT_SENT'}`);

    // Warm up database
    await getDb();
    console.log('[Database] Database initialized and seeded.');

    // Warm up queue
    await getQueue();

    // Start Janitor cron job
    initJanitor();

    app.listen(PORT, () => {
      console.log(`[API Server] Running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('Fatal initialization error:', err);
    process.exit(1);
  }
}

start();
