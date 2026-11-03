const { Octokit } = require('@octokit/rest');

// vg-expect: secrets/provider-key
const octokit = new Octokit({ auth: '{{FAKE:github_classic:bot}}' });

module.exports = { octokit };
