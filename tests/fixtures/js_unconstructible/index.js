// SPDX-License-Identifier: Apache-2.0
// A class whose constructor demands an environment that is not here — the shape
// gstack's `BrowseClient` has (it wants a live daemon port and token). The
// harness BUILDS: the module loads, the export resolves. It dies in the driver's
// load path when the receiver is constructed, so the engine used to record a
// harness that ran zero inputs and the run said `built, no fuzz pass ran` — a
// row naming nothing.
class BrowseClient {
  constructor() {
    if (!process.env.GOVFUZZ_FIXTURE_DAEMON_PORT) {
      throw new Error('browse-client: cannot find daemon port + token');
    }
    this.ready = true;
  }

  command(input) {
    return String(input).toUpperCase();
  }
}

// A sibling that IS fuzzable, with a planted crash. The gate must not touch it:
// a finding halts the driver with a nonzero code, so gating on "run one input
// and see if it exits cleanly" would have skipped exactly this.
function parseThing(s) {
  if (s.length > 3 && s[0] === 'A') {
    throw new Error('boom');
  }
  return s.toUpperCase();
}

module.exports = { BrowseClient, parseThing };
