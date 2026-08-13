import { getDb } from './db.js';

async function seed() {
  console.log('=== SEEDING REALISTIC PHISHING INCIDENTS ===');
  try {
    const db = await getDb();

    // Clear existing mock reports
    await db.run('DELETE FROM reports WHERE id LIKE ?', 'mock-case-%');

    const cases = [
      {
        id: 'mock-case-bca',
        reported_url: 'http://bca-klik-auth.secure-banking.info/login.html',
        target_brand_raw: 'BCA',
        status: 'PENDING',
        hit_count: 42,
        ip_address: '23.227.38.32',
        hosting_provider: 'Shopify, Inc.',
        abuse_email: 'abuse@shopify.com',
        screenshot_url: '/screenshots/test-uuid-1234567890.jpg',
        outgoing_links: JSON.stringify([
          { url: 'https://wa.me/628123456789', type: 'whatsapp' },
          { url: 'https://t.me/bcapromobot', type: 'telegram' }
        ])
      },
      {
        id: 'mock-case-shopee',
        reported_url: 'http://shopee-promo-indonesia.tokocare.net/login',
        target_brand_raw: 'Shopee',
        status: 'PENDING',
        hit_count: 19,
        ip_address: '104.21.32.18',
        hosting_provider: 'Cloudflare, Inc.',
        abuse_email: 'registrar-abuse@cloudflare.com',
        screenshot_url: '/screenshots/test-uuid-1234567890.jpg',
        outgoing_links: JSON.stringify([
          { url: 'https://forms.gle/shopeeclaims2026', type: 'google_form' },
          { url: 'https://scam-storage.com/app-install.apk', type: 'apk' }
        ])
      },
      {
        id: 'mock-case-tokopedia',
        reported_url: 'http://tokopedia-giveaway-2026.com/auth',
        target_brand_raw: 'Tokopedia',
        status: 'PENDING',
        hit_count: 7,
        ip_address: '192.64.119.141',
        hosting_provider: 'Namecheap, Inc.',
        abuse_email: 'abuse@namecheap.com',
        screenshot_url: '/screenshots/test-uuid-1234567890.jpg',
        outgoing_links: JSON.stringify([
          { url: 'https://some-other-vector.com', type: 'other' }
        ])
      }
    ];

    for (const c of cases) {
      await db.run(
        `INSERT INTO reports (id, reported_url, target_brand_raw, status, hit_count, ip_address, hosting_provider, abuse_email, screenshot_url, outgoing_links)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        c.id,
        c.reported_url,
        c.target_brand_raw,
        c.status,
        c.hit_count,
        c.ip_address,
        c.hosting_provider,
        c.abuse_email,
        c.screenshot_url,
        c.outgoing_links
      );
      console.log(`[Seed] Injected mock case: ${c.id} (${c.reported_url})`);
    }

    console.log('[Seed] Seeding completed successfully!');
  } catch (err) {
    console.error('[Seed] Seeding failed with error:', err);
  }
}

seed();
