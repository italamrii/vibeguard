// vg-expect: secrets/provider-key
const GITHUB_TOKEN = '{{FAKE:github_fine:release}}';

fetch('https://api.github.com/repos/acme/api/releases', {
  method: 'POST',
  headers: { Authorization: `Bearer ${GITHUB_TOKEN}` },
});
