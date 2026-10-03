/**
 * Test-only driver: push a SAML message through a passport SAML Strategy's
 * `authenticate` and capture the outcome, without needing Express.
 *
 * Works against both the published passport-ubcshib@0.1.6 (passport-saml 3.x)
 * and this branch (@node-saml/passport-saml 5.x), because both expose the same
 * passport-strategy surface (success/fail/error/redirect/pass).
 */

const passportRequest = require('passport/lib/http/request');
const SessionManager = require('passport/lib/sessionmanager');

/**
 * Run one request through `strategy.authenticate` and resolve with the first
 * passport-strategy outcome it reaches.
 * @param {object} strategy - a configured passport Strategy instance
 * @param {object} req - the request (see makePassportReq)
 * @returns {Promise<{outcome: 'success'|'fail'|'error'|'redirect'|'pass', user?: object, info?: any, err?: Error, url?: string}>}
 */
function runRequest(strategy, req) {
  return new Promise((resolve) => {
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

/**
 * @param {object} strategy - a configured passport Strategy instance
 * @param {string} samlResponseB64 - base64-encoded SAMLResponse
 * @returns {Promise<{outcome: 'success'|'fail'|'error', user?: object, info?: any, err?: Error}>}
 */
function runPostResponse(strategy, samlResponseB64) {
  return runRequest(strategy, {
    body: { SAMLResponse: samlResponseB64 },
    query: {},
    // Minimal passport/express surface the strategy may touch.
    logout: (cb) => {
      if (typeof cb === 'function') cb();
    },
    isAuthenticated: () => false,
    user: undefined,
  });
}

/**
 * A request as passport 0.7 leaves it after `passport.initialize()` and
 * `passport.session()`: passport's own `req.logout`/`isAuthenticated`, its own
 * SessionManager, and an in-memory session with express-session's
 * save/regenerate surface. passport's `req.logout` is what sets `req.user` to
 * null, which is the value @node-saml's single-logout check compares against.
 *
 * @param {object} [opts]
 * @param {object|null} [opts.user] - signed-in user; null = the app already
 *   ended the session; omitted = no user was ever on this request.
 * @param {object} [opts.query]
 * @param {object} [opts.body]
 * @param {string} [opts.url]
 * @returns {object} req, with `req.regenerations` counting session regenerations
 */
function makePassportReq(opts) {
  const { query = {}, body = {}, url = '/' } = opts || {};
  const req = { query, body, url, headers: {}, regenerations: 0 };
  const newSession = (passportData) => {
    const session = {
      save(cb) {
        cb();
      },
      regenerate(cb) {
        req.regenerations += 1;
        req.session = newSession();
        cb();
      },
    };
    if (passportData) session.passport = passportData;
    return session;
  };
  const hasUser = opts && Object.prototype.hasOwnProperty.call(opts, 'user');
  if (hasUser) req.user = opts.user;
  req.session = newSession(hasUser && opts.user ? { user: opts.user.id } : undefined);
  req._sessionManager = new SessionManager((user, r, done) => done(null, user.id));
  req.logout = req.logOut = passportRequest.logout;
  req.isAuthenticated = passportRequest.isAuthenticated;
  return req;
}

module.exports = { runRequest, runPostResponse, makePassportReq };
