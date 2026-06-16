const https = require('https');

function fetchData() {
  return new Promise((resolve, reject) => {
    https.get('https://httpbin.org/ip', (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          console.log(`Origin IP: ${parsed.origin}`);
          resolve(parsed);
        } catch (e) {
          // httpbin intermittently returns an HTML error page — don't crash the demo.
          console.log(`Note: response was not JSON (status ${res.statusCode}); skipping parse.`);
          resolve({ origin: null, raw: data.slice(0, 200) });
        }
      });
    }).on('error', reject);
  });
}

if (require.main === module) {
  fetchData().catch((err) => {
    console.log(`Note: network call failed (${err.message}); continuing.`);
  });
}

module.exports = { fetchData };
