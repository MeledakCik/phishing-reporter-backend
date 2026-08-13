async function testRdap(target) {
  console.log(`\n=== Testing RDAP for: ${target} ===`);
  try {
    const domainUrl = `https://rdap.org/domain/${target}`;
    console.log(`Querying Domain RDAP: ${domainUrl}`);
    const res = await fetch(domainUrl, { headers: { 'Accept': 'application/json' } });
    if (res.ok) {
      const data = await res.json();
      
      // Extract registrar name
      let registrarName = 'Unknown';
      if (Array.isArray(data.entities)) {
        const registrarEntity = data.entities.find(e => Array.isArray(e.roles) && e.roles.includes('registrar'));
        if (registrarEntity) {
          if (registrarEntity.vcardArray && registrarEntity.vcardArray[1]) {
            const fnItem = registrarEntity.vcardArray[1].find(item => item[0] === 'fn');
            if (fnItem) registrarName = fnItem[3];
          }
          if (registrarName === 'Unknown' && registrarEntity.handle) {
            registrarName = registrarEntity.handle;
          }
        }
      }
      
      console.log(`Detected Registrar Name: ${registrarName}`);
      
      // Search for emails
      const emails = [];
      function searchEntities(entities) {
        if (!Array.isArray(entities)) return;
        for (const entity of entities) {
          const isAbuseRole = Array.isArray(entity.roles) && entity.roles.includes('abuse');
          const isRegistrar = Array.isArray(entity.roles) && entity.roles.includes('registrar');
          
          if (Array.isArray(entity.vcardArray) && entity.vcardArray[1]) {
            const vc = entity.vcardArray[1];
            for (const item of vc) {
              if (Array.isArray(item) && item[0] === 'email') {
                emails.push({
                  email: item[3],
                  role: entity.roles?.join(',') || 'none',
                  isAbuse: isAbuseRole,
                  isRegistrar
                });
              }
            }
          }
          if (entity.entities) {
            searchEntities(entity.entities);
          }
        }
      }
      if (data.entities) searchEntities(data.entities);
      
      console.log('Found Emails:', emails);
    } else {
      console.log(`Domain RDAP failed: status ${res.status}`);
    }
  } catch (err) {
    console.error('Domain RDAP error:', err.message);
  }
}

async function run() {
  await testRdap('tokopedia.com');
  await testRdap('shopee.co.id');
  await testRdap('github.com');
}

run();
