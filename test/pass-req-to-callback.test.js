'use strict';

/**
 * `passReqToCallback`: the passport convention. When true, the verify callback
 * (and the logout verify) is called as `(req, profile, done)`; otherwise as
 * `(profile, done)`. @node-saml/passport-saml honours the option, so the
 * wrapper's own verify must accept the same arity and call the consumer's
 * verify with it, still handing over the attribute-mapped profile.
 *
 * 0.1.7-rc.1 passed the option through to @node-saml but its wrapper verify
 * was always `(profile, done)`, so with `passReqToCallback: true` it mapped
 * `req` as though it were the profile and handed the consumer no `done`.
 *
 * Requires `openssl` on PATH; skips rather than fails without it.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');

const {
  setupKeys,
  buildCases,
  buildLogoutRequest,
  redirectLogoutRequest,
  decodeLogoutResponse,
} = require('./helpers/saml');
const { runRequest, makePassportReq } = require('./helpers/run-strategy');
const ubcshib = require('../index');

const SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

let opensslAvailable = true;
try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' });
} catch {
  opensslAvailable = false;
}
const skip = !opensslAvailable && 'openssl not available';
const keys = opensslAvailable ? setupKeys() : null;
// An assertion-signed Response carrying OID-named attributes
// (ubcEduCwlPuid 12345678, mail person@ubc.ca), NameID test-nameid.
const signedResponse = opensslAvailable
  ? buildCases(keys).legit.find((c) => c.name === 'assertion-signed (OID names)').samlResponse
  : null;

function options(extra) {
  return {
    cert: keys.idp.certBase64,
    issuer: 'http://test-sp',
    callbackUrl: 'http://test-sp/acs',
    entryPoint: 'http://test-idp/sso',
    logoutUrl: 'http://test-idp/slo',
    validateInResponseTo: false,
    attributeConfig: ['ubcEduCwlPuid', 'mail'],
    ...extra,
  };
}

function assertMappedProfile(profile) {
  assert.equal(profile.nameID, 'test-nameid', 'the SAML profile, not the request');
  assert.deepEqual(profile.attributes, { ubcEduCwlPuid: '12345678', mail: 'person@ubc.ca' });
}

test('passReqToCallback unset: verify gets (profile, done) with the mapped profile', { skip }, async () => {
  const calls = [];
  const strategy = new ubcshib.Strategy(options(), function (profile, done) {
    calls.push([...arguments]);
    done(null, { id: profile.attributes.ubcEduCwlPuid });
  });
  const req = makePassportReq({ body: { SAMLResponse: signedResponse } });
  const r = await runRequest(strategy, req);
  assert.equal(r.outcome, 'success', `got ${r.outcome}${r.err ? `: ${r.err.message}` : ''}`);
  assert.deepEqual(r.user, { id: '12345678' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].length, 2, 'called with two arguments');
  assertMappedProfile(calls[0][0]);
  assert.equal(typeof calls[0][1], 'function');
});

test('passReqToCallback false: verify gets (profile, done) with the mapped profile', { skip }, async () => {
  const calls = [];
  const strategy = new ubcshib.Strategy(options({ passReqToCallback: false }), function (profile, done) {
    calls.push([...arguments]);
    done(null, { id: profile.attributes.ubcEduCwlPuid });
  });
  const r = await runRequest(strategy, makePassportReq({ body: { SAMLResponse: signedResponse } }));
  assert.equal(r.outcome, 'success', `got ${r.outcome}${r.err ? `: ${r.err.message}` : ''}`);
  assert.equal(calls[0].length, 2, 'called with two arguments');
  assertMappedProfile(calls[0][0]);
});

test('passReqToCallback true: verify gets (req, profile, done) with the mapped profile', { skip }, async () => {
  const calls = [];
  const strategy = new ubcshib.Strategy(options({ passReqToCallback: true }), function (req, profile, done) {
    calls.push([...arguments]);
    done(null, { id: profile.attributes.ubcEduCwlPuid });
  });
  const req = makePassportReq({ body: { SAMLResponse: signedResponse } });
  const r = await runRequest(strategy, req);
  assert.equal(r.outcome, 'success', `got ${r.outcome}${r.err ? `: ${r.err.message}` : ''}`);
  assert.deepEqual(r.user, { id: '12345678' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].length, 3, 'called with three arguments');
  assert.equal(calls[0][0], req, 'the first argument is the request itself');
  assertMappedProfile(calls[0][1]);
  assert.equal(typeof calls[0][2], 'function');
});

test('passReqToCallback true: an IdP-initiated logout still answers Success with the default logout verify', { skip }, async () => {
  const id = '_lr_passreq_default';
  const req = makePassportReq({
    user: { id: 'u1' },
    ...redirectLogoutRequest(buildLogoutRequest({ id }), keys.idp.key),
  });
  const strategy = new ubcshib.Strategy(options({ passReqToCallback: true }), (rq, profile, done) => done(null, profile));
  const r = await runRequest(strategy, req);
  assert.equal(r.outcome, 'redirect', `got ${r.outcome}${r.err ? `: ${r.err.message}` : ''}`);
  const response = decodeLogoutResponse(r.url);
  assert.equal(response.inResponseTo, id);
  assert.deepEqual(response.statusCodes, [SUCCESS]);
  assert.equal(req.user, null);
});

test("passReqToCallback true: a consumer's logout verify gets (req, profile, done)", { skip }, async () => {
  const id = '_lr_passreq_consumer';
  const req = makePassportReq({
    user: { id: 'u1' },
    ...redirectLogoutRequest(buildLogoutRequest({ id }), keys.idp.key),
  });
  const calls = [];
  const strategy = new ubcshib.Strategy(
    options({ passReqToCallback: true }),
    (rq, profile, done) => done(null, profile),
    function (rq, profile, done) {
      calls.push([...arguments]);
      done(null, { id: 'u1' });
    }
  );
  const r = await runRequest(strategy, req);
  assert.equal(r.outcome, 'redirect', `got ${r.outcome}${r.err ? `: ${r.err.message}` : ''}`);
  assert.deepEqual(decodeLogoutResponse(r.url).statusCodes, [SUCCESS]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].length, 3, 'called with three arguments');
  assert.equal(calls[0][0], req);
  assert.equal(calls[0][1].ID, id, 'the LogoutRequest profile');
});
