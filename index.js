/**
 * Passport UBC Shibboleth Strategy
 * SAML 2.0 authentication strategy for UBC's Shibboleth Identity Provider
 */

const fs = require('fs');
const path = require('path');
const SamlStrategy = require('passport-saml').Strategy;
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
 * UBC Shibboleth Strategy
 * Extends passport-saml Strategy with UBC-specific configuration
 */
class UBCStrategy extends SamlStrategy {
  constructor(options, verify) {
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

    // Merge provided options with UBC defaults
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

      // Security settings
      validateInResponseTo: options.validateInResponseTo !== false, // Default true
      acceptedClockSkewMs:
        options.acceptedClockSkewMs || 0,

      // Certificate: must be provided (either directly or loaded from file)
      // This is the IdP's public certificate for validating SAML responses
      cert: options.cert || (() => {
        throw new Error(
          'SAML certificate is required. ' +
          'Either provide options.cert directly, ' +
          'or set up certificate fetching from IdP metadata.'
        );
      })(),

      // SAML protocol options
      authnRequestBinding:
        options.authnRequestBinding ||
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',

      // Identifier format
      identifierFormat: options.identifierFormat || null,
    };

    // Store UBC-specific options in a variable before calling super
    const ubcOptionsToStore = {
      attributeConfig: options.attributeConfig || [],
      enableSLO: options.enableSLO !== false,
      metadataUrl: options.metadataUrl || ubcConfig.metadataUrl,
      environment: environment,
      cert: options.cert,
    };

    // Create wrapped verify function that handles attribute mapping
    const wrappedVerify = (profile, done) => {
      // Map SAML attributes based on configuration
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

      // Call original verify with mapped profile
      verify(mappedProfile, done);
    };

    // Initialize parent SAML Strategy
    super(samlOptions, wrappedVerify);

    // Now that super() is called, we can use this
    // Store UBC-specific options
    this.ubcOptions = ubcOptionsToStore;

    // Override strategy name
    this.name = 'ubcshib';

    // Store SAML options for later access
    this._samlOptions = samlOptions;

    // Fetch IdP certificate if not provided
    if (!samlOptions.cert && this.ubcOptions.metadataUrl) {
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
      this._samlOptions.cert = cert;
      // Update parent's certs array if it exists
      if (this.certs) {
        this.certs = [cert];
      }
    } catch (err) {
      console.error('Failed to fetch IdP certificate:', err.message);
      // Continue anyway - certificate validation will fail, but strategy won't crash
    }
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
