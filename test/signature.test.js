'use strict';

/**
 * The core security suite: build SAML Responses in every shape (Response-signed,
 * Assertion-signed, both, unsigned, tampered, wrong-key, two signature-wrapping
 * variants, and a comment-injection) and assert this branch accepts exactly the
 * legitimately-signed cases and rejects every attack — while keeping a
 * comment-injected but validly-signed identity intact.
 *
 * Requires `openssl` on PATH to mint a throwaway key/cert. If it is missing the
 * suite skips rather than fails.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');

const { setupKeys, buildCases } = require('./helpers/saml');
const { runPostResponse } = require('./helpers/run-strategy');
const ubcshib = require('../index');

let opensslAvailable = true;
try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' });
} catch {
  opensslAvailable = false;
}

function makeStrategy(keys, attributeConfig) {
  return new ubcshib.Strategy(
    {
      cert: keys.idp.certBase64,
      issuer: 'http://test-sp',
      callbackUrl: 'http://test-sp/acs',
      entryPoint: 'http://test-idp/sso',
      validateInResponseTo: false,
      attributeConfig,
    },
    (profile, done) => done(null, profile)
  );
}

test('SAML signature acceptance matrix', { skip: !opensslAvailable && 'openssl not available' }, async (t) => {
  const keys = setupKeys();
  const { legit, attacks } = buildCases(keys);
  const fullConfig = [
    'ubcEduCwlPuid',
    'mail',
    'eduPersonAffiliation',
    'uid',
    'eduPersonPrincipalName',
    'givenName',
    'sn',
  ];

  for (const c of legit) {
    await t.test(`accepts: ${c.name}`, async () => {
      const r = await runPostResponse(makeStrategy(keys, fullConfig), c.samlResponse);
      assert.equal(r.outcome, 'success', `expected success, got ${r.outcome} ${r.err && r.err.message}`);
      // Every requested attribute present in the fixture must have resolved.
      for (const [friendly, value] of Object.entries(c.attributes)) {
        if (fullConfig.includes(friendly)) {
          assert.equal(
            r.user.attributes[friendly],
            Array.isArray(value) ? value[0] : value,
            `attribute ${friendly} should resolve for ${c.name}`
          );
        }
      }
    });
  }

  for (const c of attacks) {
    await t.test(`handles attack: ${c.name}`, async () => {
      const r = await runPostResponse(makeStrategy(keys, ['ubcEduCwlPuid', 'mail', 'eduPersonAffiliation']), c.samlResponse);
      if (c.expectAccept === 'nameid-intact') {
        // Comment-injection: must never yield a modified identity.
        if (r.outcome === 'success') {
          assert.equal(r.user.nameID, c.expectedNameID, 'signed identity must be intact');
        } else {
          assert.equal(r.outcome, 'error', 'otherwise it must be rejected');
        }
      } else {
        assert.notEqual(r.outcome, 'success', `${c.name} must not be accepted`);
        assert.equal(r.outcome, 'error', `${c.name} should be rejected with an error`);
      }
    });
  }
});

test('bug #1 end-to-end: MACE-named PUID reaches the verify callback', { skip: !opensslAvailable && 'openssl not available' }, async () => {
  const keys = setupKeys();
  const { legit } = buildCases(keys);
  const mace = legit.find((c) => c.style === 'mace');
  const r = await runPostResponse(makeStrategy(keys, ['ubcEduCwlPuid']), mace.samlResponse);
  assert.equal(r.outcome, 'success');
  assert.equal(r.user.attributes.ubcEduCwlPuid, mace.attributes.ubcEduCwlPuid);
});
