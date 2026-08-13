import { getDb } from './db.js';
import { processForensicJob } from './worker.js';
import { runJanitorCheck } from './janitor.js';
import { sendAbuseReport } from './mailer.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function runTest() {
  console.log('=== STARTING WORKFLOW PIPELINE INTEGRATION TEST ===');

  try {
    // 1. Database Initialization
    const db = await getDb();
    console.log('[Test] SQLite initialized successfully.');

    // Clear existing test reports to have clean state
    await db.run('DELETE FROM reports WHERE reported_url LIKE ?', '%example.com%');

    // 2. Simulate User Submission
    const testUrl = 'https://example.com/test-phish-' + Math.random().toString(36).substring(7);
    const testBrand = 'BCA';
    const reportId = 'test-uuid-1234567890';

    console.log(`[Test] Submitting new report: URL="${testUrl}", Brand="${testBrand}"`);
    await db.run(
      `INSERT INTO reports (id, reported_url, target_brand_raw, status, hit_count) 
       VALUES (?, ?, ?, 'PENDING', 1)`,
      reportId,
      testUrl,
      testBrand
    );

    const checkRecord = await db.get('SELECT * FROM reports WHERE id = ?', reportId);
    console.log('[Test] Record successfully created in database:', checkRecord);

    // 3. Run Forensic Scraper Job on target URL
    // To make it run fast and reliably locally, we scan https://example.com
    console.log('[Test] Running Playwright Forensic Worker on https://example.com...');
    await processForensicJob({ reportId, url: 'https://example.com' });

    // 4. Retrieve database results
    const forensicResult = await db.get('SELECT * FROM reports WHERE id = ?', reportId);
    console.log('[Test] Forensic worker output in database:');
    console.log(`- Status: ${forensicResult.status}`);
    console.log(`- Resolved IP: ${forensicResult.ip_address}`);
    console.log(`- Hosting Provider: ${forensicResult.hosting_provider}`);
    console.log(`- Abuse Email Contact: ${forensicResult.abuse_email}`);
    console.log(`- Screenshot URL: ${forensicResult.screenshot_url}`);
    console.log(`- Harvested Links: ${forensicResult.outgoing_links}`);

    // Verify screenshot file exists
    if (forensicResult.screenshot_url) {
      const screenshotLocalPath = path.join(__dirname, '../public', forensicResult.screenshot_url);
      if (fs.existsSync(screenshotLocalPath)) {
        console.log(`[Test] SUCCESS: Screenshot file verified at ${screenshotLocalPath}`);
      } else {
        console.error(`[Test] FAILURE: Screenshot file missing at ${screenshotLocalPath}`);
      }
    } else {
      console.error('[Test] FAILURE: Screenshot URL not saved in database.');
    }

    // 5. Simulate Admin Approval & Email Dispatcher
    console.log('[Test] Simulating Admin Approval & Takedown dispatch...');
    const mailOutput = await sendAbuseReport(forensicResult);
    console.log('[Test] Email generated:', mailOutput.subject);

    // Update status to APPROVED
    await db.run("UPDATE reports SET status = 'APPROVED', last_checked_at = datetime('now') WHERE id = ?", reportId);
    const approvedResult = await db.get('SELECT * FROM reports WHERE id = ?', reportId);
    console.log(`[Test] Report status changed to: ${approvedResult.status}`);

    // 6. Run Janitor Site Death Verification
    console.log('[Test] Simulating Janitor Checker. Since the URL was randomized, it should detect a DNS/NXDOMAIN failure and mark it COMPLETED...');
    await runJanitorCheck();

    const finalResult = await db.get('SELECT * FROM reports WHERE id = ?', reportId);
    console.log(`[Test] Final Report status after Janitor check: ${finalResult.status}`);
    
    if (finalResult.status === 'COMPLETED') {
      console.log('[Test] SUCCESS: Phishing takedown pipeline successfully completed!');
    } else {
      console.error(`[Test] FAILURE: Status remains ${finalResult.status}`);
    }

    // Clean up test records
    await db.run('DELETE FROM reports WHERE id = ?', reportId);
    console.log('[Test] Cleanup complete.');

  } catch (err) {
    console.error('[Test] Integration test threw a fatal error:', err);
  }

  console.log('=== INTEGRATION TEST FINISHED ===');
}

runTest();
