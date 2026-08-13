import { getDb } from './db.js';

async function run() {
  const db = await getDb();
  const reports = await db.all('SELECT * FROM reports ORDER BY created_at DESC LIMIT 20');
  console.log('=== LATEST 20 REPORTS IN DATABASE ===');
  console.log(JSON.stringify(reports, null, 2));
}

run();
