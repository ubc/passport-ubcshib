'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const ubcshib = require('../index');

function baseOptions(extra) {
  return Object.assign(
    {
      cert: 'dummy-cert-base64',
      issuer: 'http://sp',
      callbackUrl: 'http://sp/acs',
      entryPoint: 'http://idp/sso',
      validateInResponseTo: false,
    },
    extra
  );
}

test('public API surface is unchanged', () => {
  assert.equal(typeof ubcshib.Strategy, 'function');
  assert.equal(typeof ubcshib.ensureAuthenticated, 'function');
  assert.equal(typeof ubcshib.conditionalAuth, 'function');
  assert.equal(typeof ubcshib.logout, 'function');
  assert.equal(typeof ubcshib.loadPrivateKey, 'function');
  assert.equal(typeof ubcshib.fetchIdPCertificate, 'function');
  assert.equal(typeof ubcshib.extractCertFromMetadata, 'function');
  assert.ok(ubcshib.UBC_CONFIG);
  for (const env of ['LOCAL', 'STAGING', 'PRODUCTION']) {
    assert.ok(ubcshib.UBC_CONFIG[env].entryPoint);
    assert.ok(ubcshib.UBC_CONFIG[env].logoutUrl);
    assert.ok(ubcshib.UBC_CONFIG[env].metadataUrl);
  }
});

test('constructor rejects missing options and verify', () => {
  assert.throws(() => new ubcshib.Strategy(), /Options must be provided/);
  assert.throws(() => new ubcshib.Strategy(baseOptions()), /Verify callback/);
});

test('constructor throws the same cert-required message as 0.1.6', () => {
  assert.throws(
    () =>
      new ubcshib.Strategy(
        { issuer: 'http://sp', callbackUrl: 'http://sp/acs' },
        () => {}
      ),
    /SAML certificate is required/
  );
});

test('strategy name is ubcshib and underlying SAML provider is exposed', () => {
  const s = new ubcshib.Strategy(baseOptions(), (p, done) => done(null, p));
  assert.equal(s.name, 'ubcshib');
  assert.ok(s._saml, '_saml provider is present');
  assert.ok(s._saml.options, '_saml.options is present (consumers write forceAuthn here)');
  assert.ok(s.ubcOptions, 'ubcOptions present');
  assert.ok(s._samlOptions, '_samlOptions present');
});

test('consumers can still set strategy._saml.options.forceAuthn after construction', () => {
  const s = new ubcshib.Strategy(baseOptions(), (p, done) => done(null, p));
  s._saml.options.forceAuthn = true;
  assert.equal(s._saml.options.forceAuthn, true);
});

test('cert is mapped to idpCert for @node-saml under the hood', () => {
  const s = new ubcshib.Strategy(baseOptions(), (p, done) => done(null, p));
  assert.equal(s._samlOptions.idpCert, 'dummy-cert-base64');
  assert.equal(s._saml.options.idpCert, 'dummy-cert-base64');
});

test('boolean validateInResponseTo is translated to the @node-saml enum', () => {
  const sTrue = new ubcshib.Strategy(baseOptions({ validateInResponseTo: true }), (p, d) => d(null, p));
  assert.equal(sTrue._saml.options.validateInResponseTo, 'always');
  const sFalse = new ubcshib.Strategy(baseOptions({ validateInResponseTo: false }), (p, d) => d(null, p));
  assert.equal(sFalse._saml.options.validateInResponseTo, 'never');
  // default (unset) matches 0.1.6 default of true -> 'always'
  const sDefault = new ubcshib.Strategy(
    { cert: 'c', issuer: 'http://sp', callbackUrl: 'http://sp/acs', entryPoint: 'http://idp' },
    (p, d) => d(null, p)
  );
  assert.equal(sDefault._saml.options.validateInResponseTo, 'always');
  // a caller already using the enum is passed through
  const sEnum = new ubcshib.Strategy(baseOptions({ validateInResponseTo: 'ifPresent' }), (p, d) => d(null, p));
  assert.equal(sEnum._saml.options.validateInResponseTo, 'ifPresent');
});

test('default signature flags preserve 0.1.6 "either Response or Assertion signed"', () => {
  const s = new ubcshib.Strategy(baseOptions(), (p, done) => done(null, p));
  assert.equal(s._saml.options.wantAuthnResponseSigned, false);
  assert.equal(s._saml.options.wantAssertionsSigned, false);
  // a caller may still opt into the stricter checks
  const strict = new ubcshib.Strategy(
    baseOptions({ wantAssertionsSigned: true, wantAuthnResponseSigned: true }),
    (p, done) => done(null, p)
  );
  assert.equal(strict._saml.options.wantAssertionsSigned, true);
  assert.equal(strict._saml.options.wantAuthnResponseSigned, true);
});

test('audience check is disabled by default (matches 0.1.6)', () => {
  const s = new ubcshib.Strategy(baseOptions(), (p, done) => done(null, p));
  assert.equal(s._saml.options.audience, false);
});

test('default SAML_ENVIRONMENT is STAGING and preset entryPoint is applied', () => {
  const prev = process.env.SAML_ENVIRONMENT;
  delete process.env.SAML_ENVIRONMENT;
  try {
    const s = new ubcshib.Strategy(
      { cert: 'c', issuer: 'http://sp', callbackUrl: 'http://sp/acs' },
      (p, done) => done(null, p)
    );
    assert.equal(s.ubcOptions.environment, 'STAGING');
    assert.equal(s._saml.options.entryPoint, ubcshib.UBC_CONFIG.STAGING.entryPoint);
  } finally {
    if (prev !== undefined) process.env.SAML_ENVIRONMENT = prev;
  }
});

test('ensureAuthenticated redirects when not authenticated, nexts when it is', () => {
  const mw = ubcshib.ensureAuthenticated();
  let redirected = null;
  let nexted = false;
  mw({ isAuthenticated: () => false }, { redirect: (u) => (redirected = u) }, () => (nexted = true));
  assert.equal(redirected, '/auth/ubcshib');
  mw({ isAuthenticated: () => true }, { redirect: () => {} }, () => (nexted = true));
  assert.equal(nexted, true);
});

test('a logout verify callback can be supplied as a third argument', () => {
  let used = false;
  const s = new ubcshib.Strategy(
    baseOptions(),
    (p, done) => done(null, p),
    (p, done) => {
      used = true;
      done(null, p);
    }
  );
  assert.equal(typeof s._logoutVerify, 'function');
  // it is wired through to @node-saml's Strategy
  s._logoutVerify({}, () => {});
  assert.equal(used, true);
});
