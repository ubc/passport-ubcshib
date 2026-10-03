'use strict';

/**
 * Single logout (SLO): an IdP-initiated LogoutRequest, in either binding, must
 * be answered with a LogoutResponse whose StatusCode is Success — what 0.1.6
 * (on passport-saml 3.x) always answered — and must end the app's session.
 *
 * Why this needs a test: @node-saml/passport-saml 5.x answers Success only
 * when the logout verify's user deep-equals `req.user`
 * (lib/strategy.js: `assert.deepStrictEqual(req.user, logoutUser)`), and
 * otherwise Requester/UnknownPrincipal — telling the IdP the app did NOT sign
 * the person out. 0.1.7-rc.1's default logout verify returned the LogoutRequest
 * profile, which never equals a session user, so every app answered Requester.
 *
 * The request is passport 0.7's own (its `req.logout` and SessionManager), so
 * the test sees the real mechanism: passport's `req.logout` sets `req.user` to
 * null.
 *
 * Differential: set UBCSHIB_REFERENCE to the directory of another
 * passport-ubcshib (e.g. `npm install passport-ubcshib@0.1.6` in a scratch
 * directory, then UBCSHIB_REFERENCE=<dir>/node_modules/passport-ubcshib) and
 * the default-logout matrix runs against it too.
 *
 * Requires `openssl` on PATH; skips rather than fails without it.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const {
  setupKeys,
  buildLogoutRequest,
  redirectLogoutRequest,
  postLogoutRequest,
  decodeLogoutResponse,
} = require('./helpers/saml');
const { runRequest, makePassportReq } = require('./helpers/run-strategy');

const SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';
const REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';
const UNKNOWN_PRINCIPAL = 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal';

let opensslAvailable = true;
try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' });
} catch {
  opensslAvailable = false;
}
const skip = !opensslAvailable && 'openssl not available';
const keys = opensslAvailable ? setupKeys() : null;

const implementations = [{ name: 'this branch', lib: require('../index') }];
if (process.env.UBCSHIB_REFERENCE) {
  const dir = path.resolve(process.env.UBCSHIB_REFERENCE);
  implementations.push({
    name: `reference passport-ubcshib@${require(path.join(dir, 'package.json')).version}`,
    lib: require(dir),
  });
}

function makeStrategy(lib, extraOptions, logoutVerify) {
  const args = [
    {
      cert: keys.idp.certBase64,
      issuer: 'http://test-sp',
      callbackUrl: 'http://test-sp/acs',
      entryPoint: 'http://test-idp/sso',
      logoutUrl: 'http://test-idp/slo',
      validateInResponseTo: false,
      ...extraOptions,
    },
    (profile, done) => done(null, profile),
  ];
  if (logoutVerify) args.push(logoutVerify);
  return new lib.Strategy(...args);
}

const BINDINGS = [
  {
    name: 'HTTP-Redirect',
    request: (xml) => redirectLogoutRequest(xml, keys.idp.key, 'relay-1'),
  },
  {
    name: 'HTTP-POST',
    request: (xml) => ({ body: postLogoutRequest(xml, keys.idp.key), url: '/slo' }),
  },
];

const USER_STATES = [
  { name: 'signed in (req.user set)', user: () => ({ user: { id: 'u1', nameID: 'test-nameid' } }) },
  { name: 'no user on the request (req.user unset)', user: () => ({}) },
  { name: 'session already ended by the app (req.user null)', user: () => ({ user: null }) },
];

let nextId = 0;
const logoutRequestId = () => `_lr${++nextId}`;

/** Assert a redirect to the IdP carrying a LogoutResponse to `id`; return its status codes. */
function answeredStatus(r, id) {
  assert.equal(
    r.outcome,
    'redirect',
    `expected a redirect carrying a LogoutResponse, got ${r.outcome}${r.err ? `: ${r.err.message}` : ''}`
  );
  assert.ok(r.url.startsWith('http://test-idp/slo?'), `LogoutResponse goes to the IdP's logoutUrl: ${r.url}`);
  const response = decodeLogoutResponse(r.url);
  assert.equal(response.inResponseTo, id, 'LogoutResponse answers this LogoutRequest');
  return response.statusCodes;
}

/** Assert the app's passport session is over. */
function assertSessionEnded(req) {
  assert.equal(req.user, null, 'req.user is cleared');
  assert.equal(req.isAuthenticated(), false);
  assert.equal(req.session.passport, undefined, 'no passport user in the session');
  assert.ok(req.regenerations >= 1, 'the session was regenerated');
}

for (const impl of implementations) {
  test(`IdP-initiated single logout answers Success with the default logout verify (${impl.name})`, { skip }, async (t) => {
    for (const binding of BINDINGS) {
      for (const state of USER_STATES) {
        await t.test(`${binding.name}, ${state.name}`, async () => {
          const id = logoutRequestId();
          const req = makePassportReq({ ...state.user(), ...binding.request(buildLogoutRequest({ id })) });
          const r = await runRequest(makeStrategy(impl.lib), req);
          assert.deepEqual(answeredStatus(r, id), [SUCCESS]);
          assertSessionEnded(req);
        });
      }
    }
  });
}

test("a consumer's own logout verify (third argument) is honoured: its user decides the answer", { skip }, async (t) => {
  const ubcshib = require('../index');

  await t.test('returns the signed-in user: Success, decided before the session was touched', async () => {
    const id = logoutRequestId();
    const signedIn = { id: 'u1', nameID: 'test-nameid' };
    const seen = [];
    const req = makePassportReq({
      user: { ...signedIn },
      ...redirectLogoutRequest(buildLogoutRequest({ id }), keys.idp.key),
    });
    const strategy = makeStrategy(ubcshib, {}, (profile, done) => {
      seen.push({ profile, userAtCall: req.user });
      done(null, { id: 'u1', nameID: profile.nameID });
    });
    const r = await runRequest(strategy, req);
    assert.deepEqual(answeredStatus(r, id), [SUCCESS]);
    assert.equal(seen.length, 1, 'the consumer logout verify ran once');
    assert.equal(seen[0].profile.ID, id, 'with the LogoutRequest profile');
    assert.equal(seen[0].profile.nameID, 'test-nameid');
    assert.deepEqual(seen[0].userAtCall, signedIn, 'req.user was still the signed-in user when it ran');
    assertSessionEnded(req);
  });

  await t.test('returns a different user: Requester/UnknownPrincipal, as @node-saml answers', async () => {
    const id = logoutRequestId();
    const req = makePassportReq({
      user: { id: 'u1', nameID: 'test-nameid' },
      ...redirectLogoutRequest(buildLogoutRequest({ id }), keys.idp.key),
    });
    const strategy = makeStrategy(ubcshib, {}, (profile, done) => done(null, { id: 'someone-else' }));
    const r = await runRequest(strategy, req);
    assert.deepEqual(answeredStatus(r, id), [REQUESTER, UNKNOWN_PRINCIPAL]);
    assertSessionEnded(req);
  });
});

test('a LogoutRequest signed by the wrong key is refused, and no LogoutResponse is sent', { skip }, async () => {
  const id = logoutRequestId();
  const req = makePassportReq({
    user: { id: 'u1', nameID: 'test-nameid' },
    body: postLogoutRequest(buildLogoutRequest({ id }), keys.wrong.key),
    url: '/slo',
  });
  const r = await runRequest(makeStrategy(require('../index')), req);
  assert.equal(r.outcome, 'error');
  assert.match(r.err.message, /Invalid signature/);
  // The default logout ends the app's session BEFORE the request is validated
  // (index.js, authenticate), so this browser is signed out of the app even
  // though the request was refused: no more than a GET of the app's own logout
  // route can do. Recorded here so a change to that order is a visible one.
  assert.equal(req.user, null);
});
