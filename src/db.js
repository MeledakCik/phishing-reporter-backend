import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(__dirname, '../database.sqlite');

let dbConnection = null;

export async function getDb() {
  if (dbConnection) {
    return dbConnection;
  }

  // Ensure database folder exists
  const dbDir = path.dirname(dbPath);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }

  dbConnection = await open({
    filename: dbPath,
    driver: sqlite3.Database
  });

  // Enable foreign keys
  await dbConnection.run('PRAGMA foreign_keys = ON');

  // Create tables if they do not exist
  await dbConnection.exec(`
    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      reported_url TEXT NOT NULL UNIQUE,
      target_brand_raw TEXT NOT NULL,
      status TEXT DEFAULT 'PENDING',
      hit_count INTEGER DEFAULT 1,
      screenshot_url TEXT,
      ip_address TEXT,
      hosting_provider TEXT,
      abuse_email TEXT,
      outgoing_links TEXT DEFAULT '[]',
      last_checked_at TEXT,
      ssl_status TEXT,
      ssl_issuer TEXT,
      ssl_expiry TEXT,
      ssl_days_left INTEGER,
      domain_registered_at TEXT,
      domain_age_days INTEGER,
      registrar_name TEXT,
      open_ports TEXT,
      blacklist_status TEXT,
      blacklist_detail TEXT,
      cdn_provider TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS brand_suggestions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      brand_name TEXT UNIQUE NOT NULL,
      hit_count INTEGER DEFAULT 1
    );

    CREATE INDEX IF NOT EXISTS idx_reported_url ON reports(reported_url);
    CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
  `);

  // Migration: add new analysis columns to pre-existing databases that
  // were created before these columns existed. ALTER TABLE ADD COLUMN
  // fails harmlessly if the column is already there.
  const newColumns = [
    'ssl_status TEXT',
    'ssl_issuer TEXT',
    'ssl_expiry TEXT',
    'ssl_days_left INTEGER',
    'domain_registered_at TEXT',
    'domain_age_days INTEGER',
    'registrar_name TEXT',
    'open_ports TEXT',
    'blacklist_status TEXT',
    'blacklist_detail TEXT',
    'cdn_provider TEXT'
  ];
  for (const columnDef of newColumns) {
    try {
      await dbConnection.run(`ALTER TABLE reports ADD COLUMN ${columnDef}`);
    } catch (err) {
      // Column already exists - ignore
    }
  }

  // Seed default Indonesian brands if table is empty
  const countResult = await dbConnection.get('SELECT COUNT(*) as count FROM brand_suggestions');
  if (countResult.count === 0) {
    const seedBrands = [
      'BCA',
      'Bank Mandiri',
      'BRI',
      'BNI',
      'Tokopedia',
      'Shopee',
      'Gojek',
      'Grab',
      'J&T Express',
      'Indomaret',
      'Telkomsel',
      'OVO',
      'DANA'
    ];
    for (const brand of seedBrands) {
      await dbConnection.run(
        'INSERT OR IGNORE INTO brand_suggestions (brand_name, hit_count) VALUES (?, 1)',
        brand
      );
    }
  }

  return dbConnection;
}