/**
 * Test-only driver: push a base64 SAMLResponse through a passport SAML
 * Strategy's `authenticate` and capture the outcome, without needing Express.
 *
 * Works against both the published passport-ubcshib@0.1.6 (passport-saml 3.x)
 * and this branch (@node-saml/passport-saml 5.x), because both expose the same
 * passport-strategy surface (success/fail/error/redirect/pass).
 */

/**
 * @param {object} strategy - a configured passport Strategy instance
 * @param {string} samlResponseB64 - base64-encoded SAMLResponse
 * @returns {Promise<{outcome: 'success'|'fail'|'error', user?: object, info?: any, err?: Error}>}
 */
function runPostResponse(strategy, samlResponseB64) {
  return new Promise((resolve) => {
    const req = {
      body: { SAMLResponse: samlResponseB64 },
      query: {},
      // Minimal passport/express surface the strategy may touch.
      logout: (cb) => {
        if (typeof cb === 'function') cb();
      },
      isAuthenticated: () => false,
      user: undefined,
    };

    // Override the passport-strategy result hooks on this instance.
    strategy.success = (user, info) => resolve({ outcome: 'success', user, info });
    strategy.fail = (info, status) => resolve({ outcome: 'fail', info, status });
    strategy.error = (err) => resolve({ outcome: 'error', err });
    strategy.redirect = (url) => resolve({ outcome: 'redirect', url });
    strategy.pass = () => resolve({ outcome: 'pass' });

    try {
      const maybe = strategy.authenticate(req, {});
      if (maybe && typeof maybe.catch === 'function') {
        maybe.catch((err) => resolve({ outcome: 'error', err }));
      }
    } catch (err) {
      resolve({ outcome: 'error', err });
    }
  });
}

module.exports = { runPostResponse };
