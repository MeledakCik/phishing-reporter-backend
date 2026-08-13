import { chromium } from 'playwright';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const artifactDir = 'C:/Users/ZGG/.gemini/antigravity/brain/6fa37f61-bc51-459a-b6a2-b959e3ef6de3';

async function capture() {
  console.log('[Capture] Launching browser to capture UI...');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 }
  });
  const page = await context.newPage();

  try {
    // Navigate to public form view
    console.log('[Capture] Navigating to http://localhost:5000 (Public Form)...');
    await page.goto('http://localhost:5000', { waitUntil: 'networkidle', timeout: 10000 });
    await page.waitForTimeout(2000); // Wait for fonts and styling to fully render

    const formPath = path.join(artifactDir, 'actual_public_form.png');
    await page.screenshot({ path: formPath });
    console.log(`[Capture] Public Form screenshot saved to ${formPath}`);

    // Click on Admin Console button to switch views
    console.log('[Capture] Switching to Admin Console...');
    // The button has text "Admin Console"
    await page.click('button:has-text("Admin Console")');
    await page.waitForTimeout(1000); // Wait for transition

    const adminPath = path.join(artifactDir, 'actual_admin_dashboard.png');
    await page.screenshot({ path: adminPath });
    console.log(`[Capture] Admin Console screenshot saved to ${adminPath}`);

  } catch (err) {
    console.error('[Capture] Error capturing screenshots:', err.message);
  } finally {
    await browser.close();
    console.log('[Capture] Browser closed.');
  }
}

capture();
