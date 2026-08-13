import dns from 'dns/promises';

async function test() {
  const hostname = 'shopee.co.id';
  console.log(`Testing dns.resolve4 for ${hostname}...`);
  try {
    const start = Date.now();
    const res = await dns.resolve4(hostname);
    console.log(`dns.resolve4 succeeded in ${Date.now() - start}ms:`, res);
  } catch (err) {
    console.log(`dns.resolve4 failed: ${err.message}`);
  }

  console.log(`Testing dns.lookup for ${hostname}...`);
  try {
    const start = Date.now();
    const res = await dns.lookup(hostname);
    console.log(`dns.lookup succeeded in ${Date.now() - start}ms:`, res);
  } catch (err) {
    console.log(`dns.lookup failed: ${err.message}`);
  }

  console.log(`Testing DoH fallback for ${hostname}...`);
  try {
    const start = Date.now();
    const dohRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    if (dohRes.ok) {
      const dohData = await dohRes.json();
      console.log(`DoH succeeded in ${Date.now() - start}ms:`, dohData.Answer);
    } else {
      console.log(`DoH failed with status ${dohRes.status}`);
    }
  } catch (err) {
    console.log(`DoH failed: ${err.message}`);
  }
}

test();
