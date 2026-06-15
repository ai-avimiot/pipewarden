const https = require('https');

function fetchData() {
  return new Promise((resolve, reject) => {
    https.get('https://httpbin.org/ip', (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        const parsed = JSON.parse(data);
        console.log(`Origin IP: ${parsed.origin}`);
        resolve(parsed);
      });
    }).on('error', reject);
  });
}

if (require.main === module) {
  fetchData();
}

module.exports = { fetchData };
