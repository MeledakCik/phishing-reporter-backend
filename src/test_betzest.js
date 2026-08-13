import dns from 'dns/promises';

async function test() {
  const hostname = 'betzest.net';
  const mainDomain = 'betzest.net';

  console.log(`=== Testing for ${hostname} ===`);

  // 1. Domain RDAP
  try {
    const domainUrl = `https://rdap.org/domain/${mainDomain}`;
    console.log(`Querying Domain RDAP: ${domainUrl}`);
    const res = await fetch(domainUrl, { headers: { 'Accept': 'application/json' } });
    console.log('Domain RDAP Status:', res.status);
    if (res.ok) {
      const data = await res.json();
      console.log('Domain RDAP data keys:', Object.keys(data));
      // Let's print out the entities to see if registrar or abuse is there
      console.log('Entities:', JSON.stringify(data.entities, null, 2));
    } else {
      console.log('Domain RDAP body:', await res.text());
    }
  } catch (err) {
    console.error('Domain RDAP failed:', err.message);
  }

  // 2. DNS
  let ipAddress = 'Unknown';
  try {
    const ips = await dns.resolve4(hostname);
    ipAddress = ips[0];
    console.log('Resolved via Node DNS:', ipAddress);
  } catch (err) {
    console.warn('Node DNS failed, trying DoH:', err.message);
    try {
      const dohRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`, {
        headers: { 'Accept': 'application/dns-json' }
      });
      if (dohRes.ok) {
        const dohData = await dohRes.json();
        console.log('DoH Data Answer:', dohData.Answer);
        if (Array.isArray(dohData.Answer)) {
          const aRecord = dohData.Answer.find(ans => ans.type === 1);
          if (aRecord) ipAddress = aRecord.data;
        }
      }
    } catch (dohErr) {
      console.error('DoH fallback failed:', dohErr.message);
    }
  }

  console.log('Final IP Address:', ipAddress);

  // 3. IP RDAP
  if (ipAddress !== 'Unknown') {
    try {
      const ipUrl = `https://rdap.org/ip/${ipAddress}`;
      console.log(`Querying IP RDAP: ${ipUrl}`);
      const res = await fetch(ipUrl, { headers: { 'Accept': 'application/json' } });
      console.log('IP RDAP Status:', res.status);
      if (res.ok) {
        const data = await res.json();
        console.log('IP RDAP keys:', Object.keys(data));
        console.log('IP RDAP name/remarks:', data.name, data.remarks);
      }
    } catch (err) {
      console.error('IP RDAP failed:', err.message);
    }
  }
}

test();
