'use strict';

/**
 * InResponseTo, on the library's DEFAULT setting.
 *
 * `validateInResponseTo` defaults to true (@node-saml's 'always'), so a
 * Response is accepted only when it answers an AuthnRequest this strategy's
 * cache holds, and @node-saml removes the request once it has answered it —
 * which is also what refuses a replayed Response. Every other test file sets
 * `validateInResponseTo: false`, so this is the only place the default path is
 * driven: each sign-in here is STARTED through the strategy (its redirect to
 * the IdP carries the AuthnRequest whose ID the Response must name).
 *
 * It also shows why an app running more than one process needs a shared
 * `cacheProvider` (README, "Running more than one instance"): @node-saml's
 * default cache lives in the process that issued the request.
 *
 * Requires `openssl` on PATH; skips rather than fails without it.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');

const { setupKeys, signedResponse, authnRequestId } = require('./helpers/saml');
const { runRequest, makePassportReq } = require('./helpers/run-strategy');
const ubcshib = require('../index');

let opensslAvailable = true;
try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' });
} catch {
  opensslAvailable = false;
}
const skip = !opensslAvailable && 'openssl not available';
const keys = opensslAvailable ? setupKeys() : null;

/** A strategy on the library's defaults: validateInResponseTo is NOT set. */
function makeStrategy(extra) {
  return new ubcshib.Strategy(
    {
      cert: keys.idp.certBase64,
      issuer: 'http://test-sp',
      callbackUrl: 'http://test-sp/acs',
      entryPoint: 'http://test-idp/sso',
      attributeConfig: ['ubcEduCwlPuid'],
      ...extra,
    },
    (profile, done) => done(null, { id: profile.attributes.ubcEduCwlPuid })
  );
}

/**
 * A CacheProvider (the contract @node-saml/node-saml 5.x defines in
 * lib/types.d.ts) over a Map, recording every call. Shared between two
 * strategies, it stands in for a store every instance of an app can reach.
 */
function recordingCache() {
  const store = new Map();
  const calls = [];
  return {
    store,
    calls,
    async saveAsync(key, value) {
      calls.push(['saveAsync', key]);
      if (store.has(key)) return null;
      const item = { value, createdAt: Date.now() };
      store.set(key, item);
      return item;
    },
    async getAsync(key) {
      calls.push(['getAsync', key]);
      return store.has(key) ? store.get(key).value : null;
    },
    async removeAsync(key) {
      calls.push(['removeAsync', key]);
      if (key === null || key === undefined || !store.has(key)) return null;
      store.delete(key);
      return key;
    },
  };
}

/** Start a sign-in: the strategy redirects to the IdP; return the AuthnRequest's ID. */
async function startSignIn(strategy) {
  const r = await runRequest(strategy, makePassportReq({}));
  assert.equal(r.outcome, 'redirect', `expected a redirect to the IdP, got ${r.outcome}${r.err ? `: ${r.err.message}` : ''}`);
  assert.ok(r.url.startsWith('http://test-idp/sso?'), `redirects to the entryPoint: ${r.url}`);
  return authnRequestId(r.url);
}

/** Post the IdP's Response to the ACS. */
function finishSignIn(strategy, samlResponse) {
  return runRequest(strategy, makePassportReq({ body: { SAMLResponse: samlResponse } }));
}

const answering = (inResponseTo) =>
  signedResponse(keys.idp.key, { attributes: { ubcEduCwlPuid: '12345678' }, inResponseTo });

function assertSignedIn(r) {
  assert.equal(r.outcome, 'success', `expected success, got ${r.outcome}${r.err ? `: ${r.err.message}` : ''}`);
  assert.deepEqual(r.user, { id: '12345678' });
}

function assertRefused(r, message) {
  assert.equal(r.outcome, 'error', `expected an error, got ${r.outcome}`);
  assert.match(r.err.message, message);
}

test('the default is validateInResponseTo "always"', { skip }, () => {
  assert.equal(makeStrategy()._saml.options.validateInResponseTo, 'always');
});

test('a Response answering a request this strategy issued is accepted', { skip }, async () => {
  const strategy = makeStrategy();
  const id = await startSignIn(strategy);
  assertSignedIn(await finishSignIn(strategy, answering(id)));
});

test('a Response naming a request this strategy never issued is refused', { skip }, async () => {
  const strategy = makeStrategy();
  await startSignIn(strategy);
  assertRefused(await finishSignIn(strategy, answering('_never-issued')), /^InResponseTo is not valid$/);
});

test('an unsolicited Response (no InResponseTo) is refused', { skip }, async () => {
  const strategy = makeStrategy();
  assertRefused(await finishSignIn(strategy, answering(undefined)), /^InResponseTo is missing from response$/);
});

test('a replay of the same Response is refused', { skip }, async () => {
  const strategy = makeStrategy();
  const id = await startSignIn(strategy);
  const response = answering(id);
  assertSignedIn(await finishSignIn(strategy, response));
  assertRefused(await finishSignIn(strategy, response), /^InResponseTo is not valid$/);
});

test('a custom cacheProvider is the cache @node-saml uses', { skip }, async () => {
  const cache = recordingCache();
  const strategy = makeStrategy({ cacheProvider: cache });
  assert.equal(strategy._saml.cacheProvider, cache, 'passed through to @node-saml unchanged');

  const id = await startSignIn(strategy);
  assert.deepEqual(cache.calls, [['saveAsync', id]], 'the AuthnRequest ID is saved when the sign-in starts');
  assert.ok(cache.store.has(id));

  assertSignedIn(await finishSignIn(strategy, answering(id)));
  const afterResponse = cache.calls.slice(1);
  assert.ok(afterResponse.some(([m, k]) => m === 'getAsync' && k === id), 'looked up when the Response arrives');
  assert.ok(afterResponse.some(([m, k]) => m === 'removeAsync' && k === id), 'removed once answered');
  assert.equal(cache.store.has(id), false, 'nothing left to replay against');
});

test('two strategies sharing one cache each finish a sign-in the other started', { skip }, async (t) => {
  const cache = recordingCache();
  const a = makeStrategy({ cacheProvider: cache });
  const b = makeStrategy({ cacheProvider: cache });

  await t.test('started on A, finished on B; the replay on A is refused', async () => {
    const id = await startSignIn(a);
    const response = answering(id);
    assertSignedIn(await finishSignIn(b, response));
    assertRefused(await finishSignIn(a, response), /^InResponseTo is not valid$/);
  });

  await t.test('started on B, finished on A; the replay on B is refused', async () => {
    const id = await startSignIn(b);
    const response = answering(id);
    assertSignedIn(await finishSignIn(a, response));
    assertRefused(await finishSignIn(b, response), /^InResponseTo is not valid$/);
  });
});

test('control: a cache whose removeAsync keeps the entry lets the same Response sign in twice', { skip }, async () => {
  // Why a cacheProvider must really remove: @node-saml's replay refusal is the
  // removal, nothing else (README, "The CacheProvider contract").
  const cache = recordingCache();
  cache.removeAsync = async () => null;
  const strategy = makeStrategy({ cacheProvider: cache });
  const id = await startSignIn(strategy);
  const response = answering(id);
  assertSignedIn(await finishSignIn(strategy, response));
  assertSignedIn(await finishSignIn(strategy, response));
});

test('control: two strategies on the default per-process cache refuse a sign-in the other started', { skip }, async () => {
  // Two instances of one app, or one instance replaced by a redeploy mid-sign-in.
  const a = makeStrategy();
  const b = makeStrategy();
  const id = await startSignIn(a);
  assertRefused(await finishSignIn(b, answering(id)), /^InResponseTo is not valid$/);
  // ...and the same Response is still good where the sign-in started.
  assertSignedIn(await finishSignIn(a, answering(id)));
});
