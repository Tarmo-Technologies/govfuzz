// SPDX-License-Identifier: Apache-2.0
// Upsert a sticky govfuzz summary comment on the pull request. Keyed by an
// HTML marker so repeat runs edit one comment instead of piling up new ones.
const MARKER = '<!-- govfuzz-pr -->';

module.exports = async ({ github, context, core, ciJsonPath }) => {
  const fs = require('fs');

  let data = {};
  try {
    data = JSON.parse(fs.readFileSync(ciJsonPath, 'utf8'));
  } catch (e) {
    core.info(`govfuzz: no ci-json at ${ciJsonPath} (${e}); skipping comment`);
    return;
  }

  const issue_number = context.payload.pull_request && context.payload.pull_request.number;
  if (!issue_number) {
    core.info('govfuzz: not a pull_request event; skipping comment');
    return;
  }
  const { owner, repo } = context.repo;

  let body;
  if (data.nothing_to_do) {
    body = `${MARKER}
### 🎯 govfuzz — PR fuzz

No fuzzable source files changed in this PR. Nothing to fuzz. ✅`;
  } else {
    const sev = data.by_severity || {};
    const rows = Object.entries(sev)
      .filter(([, v]) => v > 0)
      .map(([k, v]) => `| ${k} | ${v} |`)
      .join('\n');
    const confirmed = data.confirmed_findings || 0;
    const verdict = confirmed > 0 ? '⚠️ confirmed finding(s) in changed code' : '✅ no confirmed findings';
    body = `${MARKER}
### 🎯 govfuzz — PR fuzz results

**${data.total_findings || 0}** finding(s) across **${data.scoped_files || 0}** changed file(s); **${confirmed}** fuzz-confirmed — ${verdict}.

| severity | count |
|---|---|
${rows || '| _none_ | 0 |'}

<sub>Scoped to this PR's diff under a bounded time budget — inline annotations are in the **Files changed** tab. Absence of findings is not proof of safety.</sub>`;
  }

  const existing = await github.paginate(github.rest.issues.listComments, {
    owner,
    repo,
    issue_number,
    per_page: 100,
  });
  const mine = existing.find((c) => c.body && c.body.includes(MARKER));
  if (mine) {
    await github.rest.issues.updateComment({ owner, repo, comment_id: mine.id, body });
    core.info(`govfuzz: updated PR comment ${mine.id}`);
  } else {
    await github.rest.issues.createComment({ owner, repo, issue_number, body });
    core.info('govfuzz: created PR comment');
  }
};
