# Changelog

## 0.1.7

**Security fix — backwards compatible. No configuration or code change required.**

### Fixed in rc.2: single-logout answers Success again; passReqToCallback honoured

- **Single logout answers the IdP `Success` again.** In rc.1 every IdP-initiated
  LogoutRequest was answered `Requester`/`UnknownPrincipal` — telling the IdP the
  app had *not* signed the person out — because `@node-saml` answers `Success`
  only when the logout verify's user deep-equals `req.user`, and rc.1's default
  returned the LogoutRequest's profile. The default now ends the app's session
  first (passport's `req.logout`, which leaves `req.user` null) and returns
  `null`, so the answer is always `Success`, as 0.1.6's always was. Measured
  against the published 0.1.6 in both bindings, signed in or not.
- **`passReqToCallback: true` works.** rc.1 passed it to `@node-saml`, which then
  calls the verify as `(req, profile, done)`, but the wrapper still expected
  `(profile, done)`, so the consumer's verify was handed the request as its
  profile and no `done`. The verify (and a logout verify) now receives
  `(req, profile, done)` with the attribute-mapped profile when the option is
  true, and `(profile, done)` otherwise.

### Changed

- **Replaced the deprecated `passport-saml@^3.2.4` with `@node-saml/passport-saml@^5.1.1`.**
  `passport-saml` is npm-deprecated and carries the critical, never-to-be-fixed
  SAML signature-verification advisory
  [GHSA-4mxg-3p6v-xgq3 / CVE-2025-54419](https://github.com/advisories/GHSA-4mxg-3p6v-xgq3)
  at range `*`, with `@xmldom/xmldom@0.7.13` beneath it (five high advisories).
  `@node-saml/passport-saml@5.1.x` audits clean (`npm audit`: 0 vulnerabilities).

  All of the breaking changes between `passport-saml` 3.x and `@node-saml` 4/5 are
  absorbed inside this wrapper, so the public API is unchanged:
  - the IdP certificate option is still `cert` (mapped to `@node-saml`'s `idpCert`);
  - `validateInResponseTo` is still a boolean (`true` → `@node-saml`'s `'always'`,
    `false` → `'never'`); the new string enum is also accepted;
  - **signature acceptance is preserved**: a Response is accepted when **either**
    the Response **or** the Assertion carries a valid signature, exactly as 0.1.6
    did. `@node-saml` still requires at least one valid signature over the
    assertion even with both `wantAuthnResponseSigned` and `wantAssertionsSigned`
    left at their (false) defaults;
  - audience is not validated by default (as in 0.1.6); pass `audience` to opt in;
  - the SLO/logout verify callback `@node-saml` now requires is supplied
    automatically: it ends the app's session and answers the IdP's
    LogoutRequest `Success`, as 0.1.6 did. You may pass your own as an optional
    **third** constructor argument; it then gets `@node-saml`'s contract
    unchanged — return the user that deep-equals `req.user` for `Success`,
    anything else answers `Requester`/`UnknownPrincipal` — and the session is
    not ended before it runs (`@node-saml` ends it after answering);
  - the profile handed to the verify callback has the same shape (`nameID`,
    `nameIDFormat`, `sessionIndex`, `issuer`, root-level attribute keys,
    `profile.attributes`, `profile.mail`/`profile.email`, `getAssertionXml` etc.).

### Fixed (additive — previously-dropped attributes now resolve)

- **MACE-named `ubcEduCwlPuid` is no longer silently discarded.** `mapAttributes`
  built a friendly→OID reverse map in which the OID entry overwrote the MACE entry,
  so a MACE-named PUID matched nothing. It now checks every source name (OID, MACE
  and the friendly name) for each requested attribute.
- **`uid` and `eduPersonPrincipalName` now have OID entries** and resolve when the
  IdP (real UBC Shibboleth) sends them under their OID names. Added OID/MACE entries
  for `uid`, `eduPersonPrincipalName`, and MACE entries for the remaining friendly
  names.

  Both are strictly additive: nothing that resolved before stops resolving; some
  attributes that were discarded now arrive.

### Added

- A `node:test` suite (`npm test`) including a differential SAML signature harness:
  Response-signed, Assertion-signed, both, unsigned, tampered-after-signing,
  wrong-key, and two signature-wrapping variants, plus friendly/OID/MACE attribute
  resolution; and (rc.2) single logout in both bindings, decoding the
  LogoutResponse, runnable against a published version with `UBCSHIB_REFERENCE`
  (see `test/slo.test.js`), and `passReqToCallback`. Requires `openssl` on `PATH`
  (skips gracefully otherwise).
- Tests for behaviour the library had but never tested (every earlier test set
  `validateInResponseTo: false`): the default InResponseTo check (a sign-in
  started through the strategy and finished with a response naming it; an
  unknown or missing InResponseTo refused); a replayed response refused; a custom
  `cacheProvider` reaching `@node-saml`; two strategies sharing one cache, each
  finishing a sign-in the other started; a failed validation reaching `next(err)`
  rather than `failureRedirect`, through passport's own middleware; the shape of
  `profile.attributes`; and the `logout()` helper as it behaves today.

### Documentation

- README: the package name in every example (`passport-ubcshib`, not
  `@ubcshib/passport-ubcshib`); `cert` is required, not fetched; the library
  reads only `SAML_ENVIRONMENT` and `SAML_LOGOUT_URL`; the Quick Start's missing
  `express.urlencoded()`; a failed validation reaches the error handler, not
  `failureRedirect`; what `profile.attributes` holds; `privateKeyPath` turns on
  AuthnRequest signing; `enableSLO` has no effect; the `logout()` helper's
  behaviour (it ignores `returnUrl`); single logout, the third (logout verify)
  argument and `passReqToCallback`; links to documents that do not exist
  removed; and a new section, **Running more than one instance**, on the shared
  `cacheProvider` an app needs when more than one process serves it.
- ATTRIBUTES.md lists `uid` and `eduPersonPrincipalName`, and its example PUID
  OID is the one the code maps (`urn:oid:1.3.6.1.4.1.60.6.1.6`).
- LOCAL_SETUP.md describes docker-simple-saml as it is today (SimpleSAMLphp 2.x
  on port 6122) and the `entryPoint`/`logoutUrl` an app must pass until the
  `LOCAL` preset is updated.

### Compatibility notes for consumers

- `^0.1.6` consumers (`npm install` without a frozen lockfile) pick up this fix
  automatically. With a committed lockfile, run `npm update passport-ubcshib`.
- **Options 0.1.6 silently dropped now take effect.** 0.1.6 handed
  `passport-saml` thirteen options — `entryPoint`, `logoutUrl`, `issuer`,
  `callbackUrl`, the key from `privateKeyPath` (as `privateKey` and
  `decryptionPvk`), `signatureAlgorithm`, `digestAlgorithm`,
  `validateInResponseTo`, `acceptedClockSkewMs`, `cert`, `authnRequestBinding`
  and `identifierFormat` — and discarded every other option without a word.
  0.1.7 passes every option it does not manage itself straight to `@node-saml`,
  so an option your app was already passing, and which did nothing, now does
  what `@node-saml` documents. Check your options for:
  - `forceAuthn` — the IdP is asked to re-authenticate the person at every
    sign-in;
  - `cacheProvider` — now used for InResponseTo (see the README's *Running more
    than one instance*);
  - `idpIssuer` — a LogoutRequest or LogoutResponse from any other issuer is
    now refused. (`@node-saml` 5.1.0 does not check it on a sign-in Response:
    measured, a Response from another issuer is still accepted.)
  - `disableRequestedAuthnContext` — the AuthnRequest no longer carries a
    RequestedAuthnContext;
  - `requestIdExpirationPeriodMs` — how long a started sign-in can be answered;
  - `audience` — the assertion's AudienceRestriction is now checked against it;
  - `wantAssertionsSigned` / `wantAuthnResponseSigned` — that signature is now
    required;
  - `passReqToCallback` (below), and anything else `@node-saml` documents
    (`additionalParams`, `racComparison`, `maxAssertionAgeMs`, ...).

  `privateKey`, `decryptionPvk` and `idpCert` are still set by the wrapper and
  cannot be passed directly; use `privateKeyPath` and `cert`.
- `passReqToCallback` was silently ignored by 0.1.6 (it never reached
  `passport-saml`), so a verify written as `(profile, done)` alongside
  `passReqToCallback: true` worked there by accident. From 0.1.7 the option does
  what passport documents: drop it, or take `(req, profile, done)`.
- Consumers that still declare `passport-saml` directly (for their own generic
  strategy) or import from `passport-saml` in a `.d.ts` should migrate those to
  `@node-saml/passport-saml`; this package no longer pulls `passport-saml` in.

### Licence metadata corrected

- **`package.json` now declares `GPL-3.0-only`.** Every published version
  through 0.1.7-rc.2 declared `MIT` in its npm metadata, while the `LICENSE`
  file shipped in every one of those tarballs (and the README since `fb394d9`,
  2025-11-06) said GPL v3. The licence itself has not changed; 0.1.7 makes the
  metadata agree with it. A licence scanner that reads `package.json` will
  report the change.

## 0.1.6

- Patched logout between passport 0.6+ and passport-saml 3.x; added the
  `UBC_CONFIG.LOCAL` preset and http/https handling in the metadata cert fetch.
