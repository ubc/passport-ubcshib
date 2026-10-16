'use strict';

/**
 * The profile the verify callback receives, as the README describes it:
 *
 * - `profile.attributes` holds ONLY the friendly names listed in
 *   `attributeConfig`; every attribute also stays at the profile ROOT under the
 *   name the IdP sent (an OID from UBC, a friendly name from docker-simple-saml);
 * - an attribute with one value arrives as a string, with several as an array;
 * - with no `attributeConfig` (or an empty one) the library maps nothing:
 *   `profile.attributes` is @node-saml's own map, keyed by the names the IdP
 *   sent (OIDs from UBC), not friendly names.
 *
 * Requires `openssl` on PATH; skips rather than fails without it.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');

const { setupKeys, signedResponse, OID } = require('./helpers/saml');
const { runPostResponse } = require('./helpers/run-strategy');
const ubcshib = require('../index');

let opensslAvailable = true;
try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' });
} catch {
  opensslAvailable = false;
}
const skip = !opensslAvailable && 'openssl not available';
const keys = opensslAvailable ? setupKeys() : null;

const RELEASED = {
  ubcEduCwlPuid: '12345678',
  mail: 'person@ubc.ca',
  eduPersonAffiliation: ['member', 'faculty'],
};

async function profileFor(attributeConfig, style = 'oid') {
  const options = {
    cert: keys.idp.certBase64,
    issuer: 'http://test-sp',
    callbackUrl: 'http://test-sp/acs',
    entryPoint: 'http://test-idp/sso',
    validateInResponseTo: false,
  };
  if (attributeConfig !== undefined) options.attributeConfig = attributeConfig;
  const strategy = new ubcshib.Strategy(options, (profile, done) => done(null, profile));
  const r = await runPostResponse(strategy, signedResponse(keys.idp.key, { attributes: RELEASED, style }));
  assert.equal(r.outcome, 'success', `got ${r.outcome}${r.err ? `: ${r.err.message}` : ''}`);
  return r.user;
}

test('profile.attributes holds only the names in attributeConfig', { skip }, async () => {
  const profile = await profileFor(['ubcEduCwlPuid', 'eduPersonAffiliation', 'displayName']);
  assert.deepEqual(Object.keys(profile.attributes).sort(), ['eduPersonAffiliation', 'ubcEduCwlPuid']);
  assert.equal(profile.attributes.mail, undefined, 'released, but not asked for');
  assert.equal('displayName' in profile.attributes, false, 'asked for, but not released: absent, not undefined');
});

test('every attribute also stays at the profile root, under the name the IdP sent', { skip }, async () => {
  const profile = await profileFor(['ubcEduCwlPuid']);
  assert.equal(profile[OID.ubcEduCwlPuid], '12345678');
  assert.equal(profile[OID.mail], 'person@ubc.ca', 'not in attributeConfig, still at the root');
  assert.equal(profile.ubcEduCwlPuid, undefined, 'the root is not renamed to friendly names');
});

test('one value arrives as a string, several as an array', { skip }, async () => {
  const profile = await profileFor(['ubcEduCwlPuid', 'eduPersonAffiliation']);
  assert.equal(profile.attributes.ubcEduCwlPuid, '12345678');
  assert.deepEqual(profile.attributes.eduPersonAffiliation, ['member', 'faculty']);
});

test('with no attributeConfig nothing is mapped: profile.attributes is keyed by the names the IdP sent', { skip }, async (t) => {
  for (const [name, config] of [['omitted', undefined], ['empty', []]]) {
    await t.test(name, async () => {
      const profile = await profileFor(config);
      assert.deepEqual(profile.attributes, {
        [OID.ubcEduCwlPuid]: '12345678',
        [OID.mail]: 'person@ubc.ca',
        [OID.eduPersonAffiliation]: ['member', 'faculty'],
      });
      assert.equal(profile[OID.ubcEduCwlPuid], '12345678');
      assert.equal(profile.ubcEduCwlPuid, undefined);
    });
  }
});

test('an IdP that sends friendly names (docker-simple-saml) resolves the same way', { skip }, async () => {
  const profile = await profileFor(['ubcEduCwlPuid', 'mail'], 'friendly');
  assert.deepEqual(profile.attributes, { ubcEduCwlPuid: '12345678', mail: 'person@ubc.ca' });
  assert.equal(profile.ubcEduCwlPuid, '12345678', 'and at the root, under the friendly name it was sent as');
});
