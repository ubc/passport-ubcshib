'use strict';

/**
 * Where a failed sign-in goes, through passport's OWN `authenticate`
 * middleware (passport 0.7), as an Express app mounts it:
 *
 *   app.post('/auth/ubcshib/callback',
 *     passport.authenticate('ubcshib', { failureRedirect: '/login' }), ...)
 *
 * A Response that fails SAML validation (bad signature, unknown InResponseTo,
 * expired, ...) reaches the strategy's `error()`, so passport calls `next(err)`
 * and the app's ERROR HANDLER answers — `failureRedirect` is NOT used. Only a
 * verify callback that answers `done(null, false)` reaches `fail()` and the
 * redirect. This pins today's behaviour, which the README documents.
 *
 * Requires `openssl` on PATH; skips rather than fails without it.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { Passport } = require('passport');

const { setupKeys, signedResponse, buildUnsignedResponse, b64 } = require('./helpers/saml');
const { makePassportReq } = require('./helpers/run-strategy');
const ubcshib = require('../index');

let opensslAvailable = true;
try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' });
} catch {
  opensslAvailable = false;
}
const skip = !opensslAvailable && 'openssl not available';
const keys = opensslAvailable ? setupKeys() : null;

function makeStrategy(verify) {
  return new ubcshib.Strategy(
    {
      cert: keys.idp.certBase64,
      issuer: 'http://test-sp',
      callbackUrl: 'http://test-sp/acs',
      entryPoint: 'http://test-idp/sso',
      validateInResponseTo: false,
      attributeConfig: ['ubcEduCwlPuid'],
    },
    verify
  );
}

/**
 * Run one POST to the callback through passport's middleware. Resolves with
 * what the app would see: `next(err)`, a redirect, or a plain answer.
 */
function postToCallback(strategy, samlResponse) {
  const passport = new Passport();
  passport.use(strategy);
  passport.serializeUser((user, done) => done(null, user.id));
  const middleware = passport.authenticate('ubcshib', { failureRedirect: '/login' });
  return new Promise((resolve) => {
    const req = makePassportReq({ body: { SAMLResponse: samlResponse } });
    const res = {
      statusCode: 200,
      headers: {},
      setHeader(name, value) {
        this.headers[name.toLowerCase()] = value;
      },
      redirect(url) {
        resolve({ redirect: url });
      },
      end() {
        resolve({ status: this.statusCode, location: this.headers.location });
      },
    };
    middleware(req, res, (err) => resolve(err ? { nextErr: err } : { next: true }));
  });
}

test('a Response that fails validation goes to next(err), not to failureRedirect', { skip }, async (t) => {
  const verify = (profile, done) => done(null, { id: profile.attributes.ubcEduCwlPuid });

  await t.test('unsigned', async () => {
    const out = await postToCallback(makeStrategy(verify), b64(buildUnsignedResponse({ attributes: { ubcEduCwlPuid: '1' } })));
    assert.equal(out.redirect, undefined, 'failureRedirect is not used');
    assert.ok(out.nextErr instanceof Error, `next(err) is called: ${JSON.stringify(out)}`);
    assert.match(out.nextErr.message, /^Invalid signature/);
  });

  await t.test('signed by the wrong key', async () => {
    const out = await postToCallback(makeStrategy(verify), signedResponse(keys.wrong.key, { attributes: { ubcEduCwlPuid: '1' } }));
    assert.equal(out.redirect, undefined, 'failureRedirect is not used');
    assert.match(out.nextErr && out.nextErr.message, /^Invalid signature/);
  });
});

test('a verify callback answering done(null, false) goes to failureRedirect', { skip }, async () => {
  const out = await postToCallback(
    makeStrategy((profile, done) => done(null, false)),
    signedResponse(keys.idp.key, { attributes: { ubcEduCwlPuid: '1' } })
  );
  assert.deepEqual(out, { redirect: '/login' });
});

test('control: a valid Response signs the person in through the same middleware', { skip }, async () => {
  const out = await postToCallback(
    makeStrategy((profile, done) => done(null, { id: profile.attributes.ubcEduCwlPuid })),
    signedResponse(keys.idp.key, { attributes: { ubcEduCwlPuid: '1' } })
  );
  // No successRedirect configured: passport logs the user in and calls next().
  assert.deepEqual(out, { next: true });
});
