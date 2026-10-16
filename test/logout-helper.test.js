'use strict';

/**
 * The exported `logout(returnUrl)` middleware, AS IT BEHAVES TODAY (0.1.7).
 * These tests pin the behaviour the README documents, defects included, so
 * that a change to any of it is a visible one:
 *
 * - it ends the app's session (passport's `req.logout`) and redirects to the
 *   IdP's logout URL;
 * - that URL is `SAML_LOGOUT_URL`, else the `SAML_ENVIRONMENT` preset's — it
 *   never reads the strategy's own `logoutUrl` option;
 * - `returnUrl` is accepted and ignored;
 * - an unrecognised `SAML_ENVIRONMENT` throws a TypeError when a person signs
 *   out (the constructor falls back to STAGING instead);
 * - a request carrying an IdP's `SAMLRequest` is treated as a new sign-out.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { makePassportReq } = require('./helpers/run-strategy');
const ubcshib = require('../index');

const ENV_KEYS = ['SAML_ENVIRONMENT', 'SAML_LOGOUT_URL'];

/** Run `fn` with exactly these SAML_* variables set (others unset), then restore. */
async function withEnv(vars, fn) {
  const saved = {};
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  Object.assign(process.env, vars);
  try {
    return await fn();
  } finally {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

/** Run the middleware once; resolve with where it redirected and the request. */
function signOut(middleware, reqOpts) {
  return new Promise((resolve, reject) => {
    const req = makePassportReq({ user: { id: 'u1' }, ...reqOpts });
    const res = { redirect: (url) => resolve({ url, req }) };
    try {
      middleware(req, res, (err) => reject(err || new Error('next() called')));
    } catch (err) {
      reject(err);
    }
  });
}

function assertSessionEnded(req) {
  assert.equal(req.user, null);
  assert.equal(req.session.passport, undefined);
}

test('ends the session and redirects to the SAML_ENVIRONMENT preset, ignoring returnUrl', async () => {
  await withEnv({ SAML_ENVIRONMENT: 'PRODUCTION' }, async () => {
    const { url, req } = await signOut(ubcshib.logout('/goodbye'));
    assert.equal(url, ubcshib.UBC_CONFIG.PRODUCTION.logoutUrl);
    assertSessionEnded(req);
  });
});

test('SAML_ENVIRONMENT unset: the STAGING preset', async () => {
  await withEnv({}, async () => {
    const { url } = await signOut(ubcshib.logout());
    assert.equal(url, ubcshib.UBC_CONFIG.STAGING.logoutUrl);
  });
});

test('SAML_LOGOUT_URL overrides the preset', async () => {
  await withEnv({ SAML_ENVIRONMENT: 'LOCAL', SAML_LOGOUT_URL: 'http://idp.example/logout' }, async () => {
    const { url } = await signOut(ubcshib.logout('/goodbye'));
    assert.equal(url, 'http://idp.example/logout');
  });
});

test("the strategy's own logoutUrl option is not read", async () => {
  await withEnv({ SAML_ENVIRONMENT: 'LOCAL' }, async () => {
    const strategy = new ubcshib.Strategy(
      { cert: 'c', issuer: 'http://sp', callbackUrl: 'http://sp/acs', logoutUrl: 'http://idp.example/slo' },
      (p, done) => done(null, p)
    );
    assert.equal(strategy._saml.options.logoutUrl, 'http://idp.example/slo');
    const { url } = await signOut(ubcshib.logout());
    assert.equal(url, ubcshib.UBC_CONFIG.LOCAL.logoutUrl);
  });
});

test('an unrecognised SAML_ENVIRONMENT throws a TypeError at sign-out', async () => {
  await withEnv({ SAML_ENVIRONMENT: 'PROD' }, async () => {
    await assert.rejects(signOut(ubcshib.logout()), TypeError);
  });
});

test("an IdP's SAMLRequest arriving at logout() is treated as a new sign-out", async () => {
  await withEnv({ SAML_ENVIRONMENT: 'STAGING' }, async () => {
    const { url, req } = await signOut(ubcshib.logout(), { query: { SAMLRequest: 'anything' } });
    assert.equal(url, ubcshib.UBC_CONFIG.STAGING.logoutUrl, 'sent back to the IdP, not answered');
    assertSessionEnded(req);
  });
});
