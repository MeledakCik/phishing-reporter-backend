import { getDb } from './db.js';
import { processForensicJob } from './worker.js';

async function test() {
  console.log('=== RUNNING REAL-WORLD WORKER RDAP TEST ===');
  const db = await getDb();
  
  // Clear any existing test case
  await db.run('DELETE FROM reports WHERE id = ?', 'real-world-test');
  
  // Insert initial pending report
  await db.run(
    `INSERT INTO reports (id, reported_url, target_brand_raw, status)
     VALUES (?, ?, ?, ?)`,
    'real-world-test',
    'https://shopee.co.id',
    'Shopee',
    'PENDING'
  );

  console.log('Running worker process for Shopee.co.id...');
  await processForensicJob({ reportId: 'real-world-test', url: 'https://shopee.co.id' });

  // Query and print database state
  const record = await db.get('SELECT * FROM reports WHERE id = ?', 'real-world-test');
  console.log('\nResult in Database:');
  console.log(JSON.stringify(record, null, 2));

  // Clean up
  await db.run('DELETE FROM reports WHERE id = ?', 'real-world-test');
  console.log('\nTest finished.');
}

test();
