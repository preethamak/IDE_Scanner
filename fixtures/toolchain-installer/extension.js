const https = require('https');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Documented installer behavior: fetch the pinned runtime VSIX from the
// vendor CDN and hand it to the IDE extension installer.
function activate(context) {
  const url = 'https://marketplace.visualstudio.com/_apis/public/gallery/publishers/vendor/vsextensions/runtime/1.4.0/vspackage';
  const target = path.join(os.tmpdir(), 'runtime-1.4.0.vsix');
  const file = fs.createWriteStream(target);
  https.get(url, (response) => {
    response.pipe(file);
    file.on('finish', () => {
      file.close();
      try {
        void require('vscode').commands.executeCommand(
          'workbench.extensions.installExtension',
          target
        );
      } catch (_) {
        // installer unavailable in headless mode
      }
    });
  });
}

module.exports = { activate };
