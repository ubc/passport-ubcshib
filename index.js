/**
 * Passport UBC Shibboleth Strategy
 * SAML 2.0 authentication strategy for UBC's Shibboleth Identity Provider
 *
 * As of 0.1.7 this wraps `@node-saml/passport-saml` (the maintained successor
 * to the deprecated `passport-saml`, which carried GHSA-4mxg-3p6v-xgq3). The
 * public API — every export, option name, environment preset, default, and the
 * shape of the profile handed to the verify callback — is unchanged. The
 * breaking changes between passport-saml 3.x and @node-saml 5.x are absorbed
 * here so consumers do not have to change anything. See CHANGELOG.md.
 */

const fs = require('fs');
const path = require('path');
const SamlStrategy = require('@node-saml/passport-saml').Strategy;
const { mapAttributes } = require('./lib/attributes');

// UBC IdP configuration
const UBC_CONFIG = {
  LOCAL: {
    entryPoint: 'http://localhost:8080/simplesaml/saml2/idp/SSOService.php',
    logoutUrl: 'http://localhost:8080/simplesaml/saml2/idp/SingleLogoutService.php',
    metadataUrl: 'http://localhost:8080/simplesaml/saml2/idp/metadata.php',
  },
  STAGING: {
    entryPoint: 'https://authentication.stg.id.ubc.ca/idp/profile/SAML2/Redirect/SSO',
    logoutUrl: 'https://authentication.stg.id.ubc.ca/idp/profile/Logout',
    metadataUrl: 'https://authentication.stg.id.ubc.ca/idp/shibboleth',
  },
  PRODUCTION: {
    entryPoint: 'https://authentication.ubc.ca/idp/profile/SAML2/Redirect/SSO',
    logoutUrl: 'https://authentication.ubc.ca/idp/profile/Logout',
    metadataUrl: 'https://authentication.ubc.ca/idp/shibboleth',
  },
};

/**
 * Load private key from file path
 * @param {string} keyPath - Path to private key file
 * @returns {string} - PEM-formatted private key content
 * @throws {Error} - If file cannot be read
 */
function loadPrivateKey(keyPath) {
  if (!keyPath) {
    return null;
  }

  try {
    const absolutePath = path.isAbsolute(keyPath)
      ? keyPath
      : path.join(process.cwd(), keyPath);
    return fs.readFileSync(absolutePath, 'utf8');
  } catch (err) {
    throw new Error(
      `Failed to load private key from ${keyPath}: ${err.message}`
    );
  }
}

/**
 * Extract certificate from IdP metadata
 * Parses the IdP metadata to find the signing certificate
 * @param {string} metadataXml - Raw IdP metadata XML
 * @returns {string} - Base64-encoded certificate
 */
function extractCertFromMetadata(metadataXml) {
  // Match X509Certificate in the metadata
  const certMatch = metadataXml.match(
    /<ds:X509Certificate[^>]*>([A-Za-z0-9+/=]+)<\/ds:X509Certificate>/
  );
  if (!certMatch || !certMatch[1]) {
    throw new Error('No X509Certificate found in IdP metadata');
  }
  return certMatch[1];
}

/**
 * Fetch IdP metadata and extract certificate
 * @param {string} metadataUrl - URL to fetch metadata from
 * @returns {Promise<string>} - Base64-encoded certificate
 */
async function fetchIdPCertificate(metadataUrl) {
  try {
    // Determine if we need http or https
    const isHttps = metadataUrl.startsWith('https://');
    const protocol = isHttps ? require('https') : require('http');

    return new Promise((resolve, reject) => {
      protocol
        .get(metadataUrl, (res) => {
          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
          });
          res.on('end', () => {
            try {
              const cert = extractCertFromMetadata(data);
              resolve(cert);
            } catch (err) {
              reject(err);
            }
          });
        })
        .on('error', reject);
    });
  } catch (err) {
    throw new Error(`Failed to fetch IdP metadata from ${metadataUrl}: ${err.message}`);
  }
}

/**
 * Translate the library's boolean `validateInResponseTo` option to the
 * string enum @node-saml 5.x requires ('never' | 'ifPresent' | 'always').
 *
 * passport-saml 3.x used a boolean: `true` required a valid InResponseTo and
 * `false` disabled the check. @node-saml removed the boolean form. To preserve
 * 0.1.6's behaviour exactly, `true` maps to 'always' and `false' to 'never'.
 * A string value is passed through unchanged for callers that already use the
 * new enum.
 * @param {boolean|string} value
 * @returns {string}
 */
function normalizeValidateInResponseTo(value) {
  if (value === 'never' || value === 'ifPresent' || value === 'always') {
    return value;
  }
  // 0.1.6 default was `options.validateInResponseTo !== false`, i.e. true.
  return value === false ? 'never' : 'always';
}

/**
 * UBC Shibboleth Strategy
 * Extends @node-saml/passport-saml Strategy with UBC-specific configuration.
 */
class UBCStrategy extends SamlStrategy {
  /**
   * @param {Object} options - UBC/SAML options (unchanged from 0.1.6)
   * @param {Function} verify - verify callback: (profile, done), or
   *   (req, profile, done) when `options.passReqToCallback` is true
   * @param {Function} [logoutVerify] - optional SLO verify callback, with the
   *   same arity rule. @node-saml calls it for an IdP-initiated LogoutRequest
   *   and answers the IdP Success only when the user it returns deep-equals
   *   `req.user`. 0.1.6 (on passport-saml 3.x) took no such callback, so this
   *   argument is optional; when it is omitted the wrapper ends the local
   *   session itself and always answers Success, as 0.1.6 did.
   */
  constructor(options, verify, logoutVerify) {
    if (!options) {
      throw new Error('Options must be provided to UBCStrategy');
    }

    if (!verify) {
      throw new Error('Verify callback must be provided to UBCStrategy');
    }

    // Determine environment (staging vs production)
    const environment =
      (process.env.SAML_ENVIRONMENT || 'STAGING').toUpperCase();
    const ubcConfig =
      UBC_CONFIG[environment] || UBC_CONFIG.STAGING;

    // The IdP certificate: must be provided (either directly or loaded from
    // file). Same requirement and message as 0.1.6, computed before super().
    const idpCert =
      options.cert ||
      (() => {
        throw new Error(
          'SAML certificate is required. ' +
            'Either provide options.cert directly, ' +
            'or set up certificate fetching from IdP metadata.'
        );
      })();

    // Merge provided options with UBC defaults.
    const samlOptions = {
      // Use UBC defaults if not provided
      entryPoint: options.entryPoint || ubcConfig.entryPoint,
      logoutUrl: options.logoutUrl || ubcConfig.logoutUrl,

      // Required: must be provided by application
      issuer: options.issuer,
      callbackUrl: options.callbackUrl,

      // Optional signing - load from file if path provided
      privateKey: options.privateKeyPath
        ? loadPrivateKey(options.privateKeyPath)
        : null,

      // Decryption private key - used if IdP encrypts SAML responses
      // Usually the same as privateKey
      decryptionPvk: options.privateKeyPath
        ? loadPrivateKey(options.privateKeyPath)
        : null,

      // SAML options
      signatureAlgorithm: options.signatureAlgorithm || 'sha256',
      digestAlgorithm: options.digestAlgorithm || 'sha256',

      // Security settings.
      // @node-saml 5.x uses a string enum; 0.1.6 used a boolean (default true).
      validateInResponseTo: normalizeValidateInResponseTo(
        options.validateInResponseTo
      ),
      acceptedClockSkewMs: options.acceptedClockSkewMs || 0,

      // @node-saml renamed `cert` -> `idpCert`. The library's public option is
      // still `cert` (set above as idpCert here).
      idpCert,

      // Signature acceptance.
      //
      // passport-saml 3.x accepted a Response that carried a valid signature on
      // EITHER the Response OR the Assertion. @node-saml 4+ defaults
      // `wantAuthnResponseSigned` and `wantAssertionsSigned` to true, which
      // would reject an IdP that signs only one of the two. To keep exactly the
      // cases 0.1.6 accepted, both default to false here — and, measured,
      // @node-saml STILL requires at least one valid signature covering the
      // assertion when both are false (it extracts the assertion only from
      // verified XML, which is the GHSA-4mxg-3p6v-xgq3 fix). A caller that wants
      // to require one or both signatures can still pass these options through.
      wantAuthnResponseSigned:
        options.wantAuthnResponseSigned !== undefined
          ? options.wantAuthnResponseSigned
          : false,
      wantAssertionsSigned:
        options.wantAssertionsSigned !== undefined
          ? options.wantAssertionsSigned
          : false,

      // @node-saml defaults `audience` to the issuer and validates the
      // assertion's AudienceRestriction against it. passport-saml 3.x did NOT
      // validate audience unless one was supplied, so 0.1.6 accepted any
      // audience. Default to false (no audience check) to match 0.1.6; a caller
      // may pass `audience` to opt in to the stricter check.
      audience: options.audience !== undefined ? options.audience : false,

      // SAML protocol options
      authnRequestBinding:
        options.authnRequestBinding ||
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',

      // Identifier format
      identifierFormat: options.identifierFormat || null,
    };

    // Pass through any additional options the caller supplied that this
    // wrapper does not explicitly manage (e.g. forceAuthn,
    // disableRequestedAuthnContext, additionalParams, passReqToCallback,
    // racComparison, maxAssertionAgeMs). Explicit keys above win.
    const managedKeys = new Set([
      'cert',
      'privateKeyPath',
      'attributeConfig',
      'enableSLO',
      'metadataUrl',
      ...Object.keys(samlOptions),
    ]);
    Object.keys(options).forEach((key) => {
      if (!managedKeys.has(key)) {
        samlOptions[key] = options[key];
      }
    });

    // Store UBC-specific options in a variable before calling super
    const ubcOptionsToStore = {
      attributeConfig: options.attributeConfig || [],
      enableSLO: options.enableSLO !== false,
      metadataUrl: options.metadataUrl || ubcConfig.metadataUrl,
      environment: environment,
      cert: options.cert,
    };

    // Map SAML attributes based on configuration
    const mapProfile = (profile) => {
      const mappedProfile = {
        ...profile,
      };

      if (ubcOptionsToStore.attributeConfig.length > 0) {
        const attributes = mapAttributes(
          profile,
          ubcOptionsToStore.attributeConfig
        );
        mappedProfile.attributes = attributes;
      }

      return mappedProfile;
    };

    // `passReqToCallback` is passed through above, and @node-saml then calls
    // both verify callbacks as (req, profile, done) instead of (profile, done).
    // The wrapper's own callbacks take whichever arity @node-saml will use, and
    // call the consumer's verify with the same one, with the mapped profile.
    // (0.1.6 never passed the option to passport-saml, so it was ignored.)
    const passReqToCallback = !!options.passReqToCallback;

    const wrappedVerify = passReqToCallback
      ? (req, profile, done) => verify(req, mapProfile(profile), done)
      : (profile, done) => verify(mapProfile(profile), done);

    // @node-saml's Strategy requires a logout verify callback to process SLO
    // messages (passport-saml 3.x did not), and answers an IdP-initiated
    // LogoutRequest with Success only when the user that callback returns
    // deep-equals `req.user` (its strategy.js: `deepStrictEqual(req.user,
    // logoutUser)`); otherwise Requester/UnknownPrincipal, telling the IdP this
    // app did NOT sign the person out. The default returns `null`, and
    // `authenticate` below ends the local session before @node-saml runs —
    // passport's `req.logout` sets `req.user` to null — so the two always match
    // and the IdP is always told Success, as 0.1.6 always told it.
    //
    // A consumer's own logoutVerify replaces the default and the session is NOT
    // ended first: it gets @node-saml's contract unchanged (return the user
    // that matches `req.user` for Success), and @node-saml ends the session
    // after answering either way.
    const defaultLogoutVerify = passReqToCallback
      ? (req, profile, done) => done(null, null)
      : (profile, done) => done(null, null);
    const slo = logoutVerify || defaultLogoutVerify;

    // Initialize parent SAML Strategy
    super(samlOptions, wrappedVerify, slo);

    // Whether `authenticate` ends the local session before handing an
    // IdP-initiated LogoutRequest to @node-saml (only with the default).
    this._endSessionBeforeLogoutRequest = !logoutVerify;

    // Now that super() is called, we can use this
    // Store UBC-specific options
    this.ubcOptions = ubcOptionsToStore;

    // Override strategy name
    this.name = 'ubcshib';

    // Store SAML options for later access
    this._samlOptions = samlOptions;

    // Fetch IdP certificate if not provided.
    // NOTE: idpCert is required above (we throw when options.cert is falsy), so
    // this branch is effectively unreachable; kept for API parity with 0.1.6.
    if (!samlOptions.idpCert && this.ubcOptions.metadataUrl) {
      this._fetchCertificate();
    }
  }

  /**
   * Fetch and cache IdP certificate from metadata
   * This is called asynchronously during strategy initialization
   */
  async _fetchCertificate() {
    try {
      const cert = await fetchIdPCertificate(this.ubcOptions.metadataUrl);
      // Update the strategy's certificate
      this._samlOptions.idpCert = cert;
      // Update the underlying SAML provider's option if present
      if (this._saml && this._saml.options) {
        this._saml.options.idpCert = cert;
      }
    } catch (err) {
      console.error('Failed to fetch IdP certificate:', err.message);
      // Continue anyway - certificate validation will fail, but strategy won't crash
    }
  }

  /**
   * Authenticate request
   * Overridden to patch req.logout for compatibility between passport-saml 3.x
   * (and @node-saml's SLO path) and passport 0.6.0+, where `req.logout`
   * requires a callback; and, for an IdP-initiated LogoutRequest under the
   * default logout verify, to end the local session before @node-saml answers
   * it (see the constructor).
   * @param {Object} req - Request object
   * @param {Object} options - Authentication options
   */
  authenticate(req, options) {
    // Patch req.logout if it exists
    if (req.logout) {
      const originalLogout = req.logout;
      req.logout = function (cb) {
        // If called without callback, provide one
        if (!cb) {
          return originalLogout.call(this, (err) => {
            if (err) console.error('SAML Logout Error (patched):', err);
          });
        }
        // Otherwise pass through
        return originalLogout.apply(this, arguments);
      };
    }

    // An IdP-initiated LogoutRequest (HTTP-Redirect or HTTP-POST binding):
    // end the local session FIRST, so `req.user` is null when @node-saml
    // compares it with the default logout verify's null, and the IdP is told
    // Success. This runs before the request is validated, so a LogoutRequest
    // that then fails validation has still signed this browser out of the app
    // — no more than a plain GET of the app's own logout route can do. A
    // failure to end the session is an error, not a Success.
    const carriesLogoutRequest =
      (req.query && req.query.SAMLRequest) ||
      (req.body && req.body.SAMLRequest);
    if (
      this._endSessionBeforeLogoutRequest &&
      carriesLogoutRequest &&
      typeof req.logout === 'function'
    ) {
      req.logout((err) => {
        if (err) {
          return this.error(err);
        }
        super.authenticate(req, options);
      });
      return undefined;
    }

    return super.authenticate(req, options);
  }
}

/**
 * Middleware to protect routes - requires authentication
 * @param {Object} options - Optional configuration
 * @returns {Function} Express middleware
 */
function ensureAuthenticated(options = {}) {
  return (req, res, next) => {
    if (req.isAuthenticated()) {
      return next();
    }

    const loginUrl = options.loginUrl || '/auth/ubcshib';
    res.redirect(loginUrl);
  };
}

/**
 * Middleware to conditionally protect routes
 * @param {Function} checkFn - Function to determine if auth is needed
 * @returns {Function} Express middleware
 */
function conditionalAuth(checkFn) {
  return (req, res, next) => {
    if (checkFn(req)) {
      if (!req.isAuthenticated()) {
        return res.redirect('/auth/ubcshib');
      }
    }
    next();
  };
}

/**
 * Middleware to handle single logout
 * @param {string} returnUrl - URL to redirect to after logout
 * @returns {Function} Express middleware
 */
function logout(returnUrl = '/') {
  return (req, res) => {
    const logoutUrl =
      process.env.SAML_LOGOUT_URL ||
      UBC_CONFIG[
        (process.env.SAML_ENVIRONMENT || 'STAGING').toUpperCase()
      ].logoutUrl;

    req.logout((err) => {
      if (err) {
        console.error('Logout error:', err);
      }

      // If SLO is enabled, redirect to IdP logout, otherwise just redirect
      const finalUrl = logoutUrl;
      res.redirect(finalUrl);
    });
  };
}

module.exports = {
  Strategy: UBCStrategy,
  UBC_CONFIG,
  ensureAuthenticated,
  conditionalAuth,
  logout,
  // Utilities for advanced usage
  loadPrivateKey,
  fetchIdPCertificate,
  extractCertFromMetadata,
};
