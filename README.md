# passport-ubcshib

A Passport.js strategy for integrating UBC's Shibboleth SAML 2.0 Identity Provider with Node.js applications. An extension of the [`@node-saml/passport-saml`](https://github.com/node-saml/passport-saml) library, with thanks to University of Washington for publishing theirs from which we could work: https://www.passportjs.org/packages/passport-uwshib/

> **Since 0.1.7** this library is built on `@node-saml/passport-saml` (the maintained successor to the deprecated `passport-saml`, which carried the unfixable critical advisory [GHSA-4mxg-3p6v-xgq3](https://github.com/advisories/GHSA-4mxg-3p6v-xgq3)). The upgrade is **backwards compatible** — no configuration or code change is required. See [CHANGELOG.md](./CHANGELOG.md), including the options 0.1.6 silently ignored that now take effect.

## Features

-   **SAML 2.0 Support**: SAML 2.0 sign-in with UBC's Shibboleth IdP
-   **Multi-Environment**: Endpoint presets for LOCAL (SimpleSAMLphp), STAGING, and PRODUCTION, chosen by `SAML_ENVIRONMENT`
-   **Local Development**: Test with [docker-simple-saml](https://github.com/ubc/docker-simple-saml) before deploying to staging/production (see [LOCAL_SETUP.md](./LOCAL_SETUP.md))
-   **Flexible Attributes**: Per-application attribute selection with OID-to-friendly-name mapping
-   **Secure**: Response signatures validated against the IdP certificate you supply; optional AuthnRequest signing
-   **Single Logout (SLO)**: Answers an IdP-initiated LogoutRequest and ends the app's session

## Installation

```bash
npm install passport-ubcshib passport express-session
```

## Quick Start

### 1. Configure Passport

```javascript
const fs = require('fs');
const passport = require('passport');
const { Strategy } = require('passport-ubcshib');

passport.use(
	new Strategy(
		{
			// Service Provider identity (your app's entity ID, as registered with UBC IAM)
			issuer: 'https://myapp.example.com/shibboleth',

			// Where the IdP POSTs the sign-in response (must match the registration exactly)
			callbackUrl: 'https://myapp.example.com/auth/ubcshib/callback',

			// REQUIRED: the IdP's signing certificate. The constructor throws without it;
			// it is not fetched for you (see "Certificate Management").
			cert: fs.readFileSync(process.env.SAML_IDP_CERT_PATH, 'utf8'),

			// Optional: your SP's private key. Setting it makes the strategy SIGN every
			// AuthnRequest, so the IdP must hold your SP's certificate (see the option table).
			privateKeyPath: process.env.SAML_PRIVATE_KEY_PATH,

			// Which attributes to map into profile.attributes (see ATTRIBUTES.md)
			attributeConfig: ['ubcEduCwlPuid', 'mail', 'eduPersonAffiliation'],
		},
		// Verify callback: called with the profile after a successful sign-in
		(profile, done) => {
			// profile.nameID - SAML NameID
			// profile.attributes - the attributeConfig names, mapped to friendly names
			User.findOrCreate(
				{ ubcId: profile.attributes.ubcEduCwlPuid },
				(err, user) => done(err, user)
			);
		}
	)
);

// Serialize and deserialize user for session management
passport.serializeUser((user, done) => {
	done(null, user.id);
});

passport.deserializeUser((id, done) => {
	User.findById(id, (err, user) => {
		done(err, user);
	});
});
```

### 2. Set Up the App and Routes

```javascript
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { ensureAuthenticated } = require('passport-ubcshib');

const app = express();

// REQUIRED: the IdP POSTs the response as a form. Without this parser req.body is
// empty, the callback is treated as a NEW sign-in and the browser is sent straight
// back to the IdP — a loop that logs no error.
app.use(express.urlencoded({ extended: false }));

app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// Login route - redirects to UBC IdP
app.get('/auth/ubcshib', passport.authenticate('ubcshib'));

// Callback route - the IdP POSTs here after authentication
app.post(
	'/auth/ubcshib/callback',
	passport.authenticate('ubcshib', { failureRedirect: '/login' }),
	(req, res) => {
		// Successful authentication
		res.redirect('/dashboard');
	}
);

// Protected route
app.get('/dashboard', ensureAuthenticated(), (req, res) => {
	res.send(`Welcome, ${req.user.name}`);
});

// A response that FAILS SAML validation (bad signature, expired, an unknown or
// replayed InResponseTo) reaches Express's error handler, NOT failureRedirect —
// see "When a sign-in fails".
app.use((err, req, res, next) => {
	console.error('Sign-in failed:', err.message);
	res.status(500).send('Sign-in failed');
});
```

For signing out, see [Single Logout](#single-logout) and [`logout(returnUrl)`](#logoutreturnurl).

### 3. Configure the Environment

```env
# The only variable the strategy itself reads. Set it explicitly: unset means STAGING.
SAML_ENVIRONMENT=STAGING  # LOCAL, STAGING or PRODUCTION
```

Everything else your app needs (issuer, callback URL, certificate and key paths) is
passed as options; any environment variable names you use for them are your app's own.

## Configuration Options

### Required Options

| Option        | Type   | Description                                                                                         |
| ------------- | ------ | --------------------------------------------------------------------------------------------------- |
| `issuer`      | string | Your Service Provider's entity ID (as registered with UBC IAM)                                      |
| `callbackUrl` | string | URL where the IdP POSTs the response (must match the registered URL exactly)                        |
| `cert`        | string | The IdP's signing certificate (PEM, or its base64 body). **The constructor throws without it.**     |

### Optional Options

| Option                                              | Type                                         | Default                                | Description |
| --------------------------------------------------- | -------------------------------------------- | -------------------------------------- | ----------- |
| `privateKeyPath`                                    | string                                       | none                                   | Path to your SP's private key (PEM). **Setting it makes the strategy sign every AuthnRequest** (and use the key to decrypt encrypted assertions), so the IdP must hold your SP's certificate — in UBC IAM's registration, or in docker-simple-saml as `certData` on your SP's row — or it refuses the sign-in. |
| `attributeConfig`                                   | Array                                        | `[]`                                   | Friendly attribute names to map into `profile.attributes` (see [Attribute Mapping](#attribute-mapping)). Empty: nothing is mapped. |
| `entryPoint`                                        | string                                       | the `SAML_ENVIRONMENT` preset          | The IdP's SSO endpoint |
| `logoutUrl`                                         | string                                       | the `SAML_ENVIRONMENT` preset          | The IdP's SLO endpoint: where the strategy sends a LogoutResponse. (The `logout()` helper does not read it.) |
| `validateInResponseTo`                              | boolean, or `'never'`/`'ifPresent'`/`'always'` | `true` (`'always'`)                  | Accept a response only if it answers a sign-in this app started. See [Running more than one instance](#running-more-than-one-instance). |
| `cacheProvider`                                     | object                                       | `@node-saml`'s in-memory cache         | Where started sign-ins are remembered. Needed when more than one process serves the app. |
| `acceptedClockSkewMs`                               | number                                       | `0`                                    | Allowed clock skew between the IdP and your server |
| `signatureAlgorithm` / `digestAlgorithm`            | string                                       | `'sha256'`                             | Algorithms for signing AuthnRequests |
| `audience`                                          | string or `false`                            | `false` (not checked, as in 0.1.6)     | When set, the assertion's AudienceRestriction must name it |
| `wantAssertionsSigned` / `wantAuthnResponseSigned`  | boolean                                      | `false`                                | Require that specific signature. With both `false` a response is still refused unless the Response or the Assertion carries a valid signature. |
| `passReqToCallback`                                 | boolean                                      | `false`                                | Call the verify (and logout verify) as `(req, profile, done)` |
| `identifierFormat`                                  | string                                       | none                                   | NameID format to request |
| `metadataUrl`                                       | string                                       | the `SAML_ENVIRONMENT` preset          | Stored only. Nothing fetches it (see [Certificate Management](#certificate-management)). |
| `enableSLO`                                         | boolean                                      | `true`                                 | Stored and never read: it has **no effect**. |

**Other `@node-saml` options pass straight through** (since 0.1.7; 0.1.6 dropped them silently): for example `forceAuthn`, `idpIssuer`, `disableRequestedAuthnContext`, `requestIdExpirationPeriodMs`, `additionalParams`, `racComparison` and `maxAssertionAgeMs`. See the [`@node-saml/node-saml` 5.1.0 documentation](https://github.com/node-saml/node-saml/tree/v5.1.0#config-parameter-details). `privateKey`, `decryptionPvk` and `idpCert` are set by the wrapper and cannot be passed directly: use `privateKeyPath` and `cert`.

### Environment Variables

The library reads exactly two:

| Variable           | Read by                                  | Meaning |
| ------------------ | ---------------------------------------- | ------- |
| `SAML_ENVIRONMENT` | the strategy, and the `logout()` helper | `LOCAL`, `STAGING` or `PRODUCTION` (any case): which preset supplies `entryPoint`, `logoutUrl` and `metadataUrl` when you do not pass them. **Unset, it means `STAGING` — real UBC infrastructure.** An unrecognised value is silently treated as `STAGING` by the strategy, and makes the `logout()` helper throw a `TypeError` when someone signs out. |
| `SAML_LOGOUT_URL`  | the `logout()` helper only              | The IdP logout URL the helper redirects to, instead of the preset's |

## Environments

### Local

Use [docker-simple-saml](https://github.com/ubc/docker-simple-saml), as described in [LOCAL_SETUP.md](./LOCAL_SETUP.md). **The `LOCAL` preset is out of date in 0.1.7**: it points at `http://localhost:8080` with SimpleSAMLphp 1.x-era paths, and docker-simple-saml now serves SimpleSAMLphp 2.x on port 6122. Pass `entryPoint` and `logoutUrl` (and set `SAML_LOGOUT_URL` if you use the `logout()` helper) as LOCAL_SETUP.md shows.

### Staging

-   **Entry Point**: `https://authentication.stg.id.ubc.ca/idp/profile/SAML2/Redirect/SSO`
-   **Logout URL**: `https://authentication.stg.id.ubc.ca/idp/profile/Logout`
-   **Metadata**: `https://authentication.stg.id.ubc.ca/idp/shibboleth`

### Production

-   **Entry Point**: `https://authentication.ubc.ca/idp/profile/SAML2/Redirect/SSO`
-   **Logout URL**: `https://authentication.ubc.ca/idp/profile/Logout`
-   **Metadata**: `https://authentication.ubc.ca/idp/shibboleth`

Set the environment via:

```bash
SAML_ENVIRONMENT=PRODUCTION node app.js
```

## Running more than one instance

By default (`validateInResponseTo: true`) the strategy accepts a sign-in response only if it answers an AuthnRequest this app sent, and it forgets the request once answered — which is also what refuses a replayed response. `@node-saml` remembers those requests **in the memory of the process that sent them**. So when an app runs as more than one process — several containers behind a load balancer, a Node cluster, or one instance replaced by a redeploy while somebody is half-way through signing in — a sign-in that starts on one process and whose response reaches another is refused with `InResponseTo is not valid`, and goes to your error handler.

**Sticky sessions do not fix this.** The IdP returns the person with a cross-site form POST, and a browser does not send a `SameSite=Lax` cookie (a typical load-balancer affinity cookie) on a cross-site POST, so the balancer cannot route the response back to the process that started it. A redeploy replaces the process regardless.

**The fix is a shared `cacheProvider`**: a store every process can reach. (Turning `validateInResponseTo` off also turns off the replay refusal; do not.)

### The CacheProvider contract

`@node-saml/node-saml` 5.x calls three async methods (`lib/types.d.ts`, `CacheProvider`):

| Method | Called | Must |
| ------ | ------ | ---- |
| `saveAsync(key, value)` | when a sign-in starts (and when the app sends a LogoutRequest), with the request's ID and its IssueInstant (an ISO 8601 string) | store `value` under `key` where every process can read it, expiring after `requestIdExpirationPeriodMs` (default 8 hours). Resolve `{ value, createdAt }` (`createdAt` in epoch milliseconds), or `null` if `key` is already stored and live. |
| `getAsync(key)` | when a response arrives | resolve **exactly** the `value` saved (`@node-saml` parses it as a date), or `null` if absent or expired |
| `removeAsync(key)` | once a response has answered the request, or failed | delete it; resolve `key` if something was removed, else `null`. `key` may be `null`. **This removal is the replay refusal**: a cache that does not remove lets the same response sign in again until the entry expires. |

The library passes `cacheProvider` to `@node-saml` unchanged. Any shared store works: in Redis, for instance, `SET key value NX PX <ttl>`, `GET` and `DEL`.

### Example: MongoDB

Adapted from the cache Manifest's Node blueprint uses (MongoDB Node driver; an 8-hour TTL index):

```javascript
const SAML_REQUEST_TTL_MS = 8 * 60 * 60 * 1000; // @node-saml's default requestIdExpirationPeriodMs

async function mongoSamlRequestCache(collection) {
	// Mongo removes old entries itself, about once a minute; reads also check the age,
	// so an entry past its TTL is gone to the library whether or not it has been swept.
	await collection.createIndex(
		{ createdAt: 1 },
		{ expireAfterSeconds: SAML_REQUEST_TTL_MS / 1000 }
	);
	const liveSince = () => new Date(Date.now() - SAML_REQUEST_TTL_MS);

	return {
		async saveAsync(key, value) {
			// An expired entry not yet swept must not block a new one with the same id.
			await collection.deleteOne({ _id: key, createdAt: { $lte: liveSince() } });
			const createdAt = new Date();
			try {
				await collection.insertOne({ _id: key, value, createdAt });
			} catch (err) {
				if (err && err.code === 11000) return null; // already stored and live
				throw err;
			}
			return { value, createdAt: createdAt.getTime() };
		},
		async getAsync(key) {
			const found = await collection.findOne({ _id: key, createdAt: { $gt: liveSince() } });
			return found ? found.value : null;
		},
		async removeAsync(key) {
			if (key === null || key === undefined) return null;
			const { deletedCount } = await collection.deleteOne({ _id: key });
			return deletedCount === 1 ? key : null;
		},
	};
}

// At startup, with the MongoClient your app already holds (e.g. for its sessions):
const cacheProvider = await mongoSamlRequestCache(
	client.db('myapp').collection('saml_requests')
);
passport.use(new Strategy({ /* ...options... */ cacheProvider }, verify));
```

If you set `requestIdExpirationPeriodMs`, give the cache the same TTL. `test/in-response-to.test.js` shows two strategies sharing one cache, each finishing a sign-in the other started, with the replay still refused.

## Attribute Mapping

The strategy maps SAML attribute names (OID or MACE, as UBC's IdP sends them; or friendly names, as docker-simple-saml sends them) to friendly names. See **[ATTRIBUTES.md](./ATTRIBUTES.md)** for the names it knows.

Common attributes:

-   `ubcEduCwlPuid` - UBC CWL Persistent Unique Identifier
-   `mail` - Email address
-   `eduPersonAffiliation` - Affiliation (student, faculty, staff, etc.)

What the verify callback receives:

-   **`profile.attributes` holds only the names listed in `attributeConfig`**, under their friendly names. A listed attribute the IdP did not release is absent.
-   **Every attribute also stays at the profile root under the name the IdP sent** — `profile['urn:oid:0.9.2342.19200300.100.1.3']` from UBC, `profile.mail` from docker-simple-saml — whether or not it is in `attributeConfig`.
-   **One value arrives as a string, several as an array.** Check with `Array.isArray` before treating `eduPersonAffiliation` as either.
-   **With no `attributeConfig` (or an empty one) nothing is mapped**: `profile.attributes` is then `@node-saml`'s own map, keyed by the names the IdP sent — OIDs from UBC, friendly names locally — so code written against one IdP breaks against the other. Set `attributeConfig`.

```javascript
req.user.attributes = {
	ubcEduCwlPuid: '12345678',
	mail: 'user@ubc.ca',
	eduPersonAffiliation: ['student', 'member'], // several values: an array
};
```

### Adding New Attributes

A name the table does not know is looked up under exactly that name. To map a new OID, add it to `ATTRIBUTE_MAPPINGS` in [`lib/attributes.js`](./lib/attributes.js) and to the table in [ATTRIBUTES.md](./ATTRIBUTES.md); ATTRIBUTES.md also describes how attribute release is requested from UBC IAM.

## When a sign-in fails

-   **A response that fails SAML validation** — a bad or missing signature, an expired assertion, an unknown or replayed `InResponseTo` — reaches the strategy's `error()`. Passport then calls `next(err)`, so **Express's error handler answers, not `failureRedirect`**. Add an error handler that shows a useful page.
-   **Your verify callback answering `done(null, false)`** reaches `fail()`, and that is what `failureRedirect` handles.

`test/failure-routing.test.js` drives both through passport's own middleware.

## Single Logout

When the IdP ends a person's session it sends a LogoutRequest to the URL registered as your SP's SingleLogoutService. Mount the strategy there:

```javascript
// The route registered with the IdP as this SP's SingleLogoutService
app.get('/auth/ubcshib/slo', passport.authenticate('ubcshib'));
```

The strategy validates the request, ends the app's session, and redirects the browser back to the IdP's `logoutUrl` with a LogoutResponse. With the default logout handling the IdP is always told `Success`. In 0.1.7 **the app's session is ended before the LogoutRequest is validated**, so any request to this route that carries a `SAMLRequest` signs that browser out of the app (no more than a plain GET of a logout route can do); the request is still validated, and an invalid one gets an error rather than a LogoutResponse.

### Your own logout verify (optional third argument)

```javascript
new Strategy(options, verify, (profile, done) => {
	// profile: the LogoutRequest (profile.nameID, profile.sessionIndex, ...)
	// Answer with the user that deep-equals req.user to tell the IdP Success;
	// anything else tells it Requester/UnknownPrincipal.
	done(null, findSignedInUser(profile));
});
```

When you supply one, the library does **not** end the session first: `@node-saml/passport-saml` calls your function, answers the IdP according to whether the user it returns deep-equals `req.user` (`assert.deepStrictEqual`), and then ends the session either way. An app that ends the session itself before handing the request to the strategy should return `null`, which then matches.

With `passReqToCallback: true`, both the verify and the logout verify are called as `(req, profile, done)`.

## Helper Middleware

### ensureAuthenticated(options)

Middleware to protect routes. Redirects unauthenticated users to login.

```javascript
const { ensureAuthenticated } = require('passport-ubcshib');

app.get('/protected', ensureAuthenticated(), (req, res) => {
	res.send('Only authenticated users see this');
});

// Custom login URL
app.get(
	'/protected',
	ensureAuthenticated({ loginUrl: '/auth/ubcshib' }),
	(req, res) => {
		res.send('Only authenticated users see this');
	}
);
```

### logout(returnUrl)

Ends the app's session and redirects the browser to the IdP's logout URL. As of 0.1.7:

-   **`returnUrl` is accepted and ignored.** The browser ends on the IdP's page.
-   The URL is `SAML_LOGOUT_URL` if set, else the `SAML_ENVIRONMENT` preset's. **It does not read the strategy's `logoutUrl` option**: if you pass one, set `SAML_LOGOUT_URL` to the same value.
-   An unrecognised `SAML_ENVIRONMENT` makes it throw a `TypeError` when someone signs out.
-   **Do not mount it at your SingleLogoutService route**: an IdP's LogoutRequest arriving there is treated as a new sign-out and sent back to the IdP instead of being answered. Mount `passport.authenticate('ubcshib')` there ([Single Logout](#single-logout)).

```javascript
const { logout } = require('passport-ubcshib');

app.get('/logout', logout());
```

`test/logout-helper.test.js` pins this behaviour.

### conditionalAuth(checkFn)

Middleware to conditionally protect routes based on a function.

```javascript
const { conditionalAuth } = require('passport-ubcshib');

app.get(
	'/maybe-protected',
	conditionalAuth((req) => req.query.admin === 'true'),
	(req, res) => {
		res.send('Protected if admin query param is true');
	}
);
```

## Profile Structure

After a successful sign-in, the verify callback's `profile` has (with `attributeConfig: ['ubcEduCwlPuid', 'mail', 'eduPersonAffiliation']`, from UBC's IdP):

```javascript
profile = {
	issuer: '...', // the IdP's entity ID
	nameID: '...', // SAML NameID
	nameIDFormat: '...',
	sessionIndex: '...',
	// every released attribute, under the name the IdP sent:
	'urn:oid:1.3.6.1.4.1.60.6.1.6': '12345678',
	'urn:oid:0.9.2342.19200300.100.1.3': 'user@ubc.ca',
	'urn:oid:1.3.6.1.4.1.5923.1.1.1.1': ['student', 'member'],
	// the attributeConfig names, mapped:
	attributes: {
		ubcEduCwlPuid: '12345678',
		mail: 'user@ubc.ca',
		eduPersonAffiliation: ['student', 'member'],
	},
};
```

`@node-saml` also copies a released `mail` attribute to `profile.mail` and `profile.email`.

## Certificate Management

**`cert` is required.** The constructor throws `SAML certificate is required` without it, and nothing fetches the certificate for you (`metadataUrl` is stored and unused). Save the IdP's signing certificate from its metadata once, and load it at startup:

```javascript
new Strategy(
	{
		// ... other options
		cert: fs.readFileSync('/path/to/idp-cert.pem', 'utf8'),
	},
	verifyCallback
);
```

The exported `fetchIdPCertificate(metadataUrl)` and `extractCertFromMetadata(xml)` are utilities you may call yourself; the strategy does not call them.

## Testing with Staging Environment

1. **Register with UBC IAM**:

    - Provide them with your Service Provider's metadata (entity ID, callback URL, and your SP certificate if you set `privateKeyPath`)
    - They will configure your app in their staging environment
    - They will confirm the entity ID and which attributes are released

2. **Test in Staging**:

    ```bash
    SAML_ENVIRONMENT=STAGING node app.js
    ```

3. **Validate attributes**:
    - Sign in and log the keys of `profile` (not the values) to see which attributes arrived, and under which names
    - Add the ones you need to `attributeConfig`

## Production Deployment

1. Work with UBC IAM to:

    - Register your production URLs (issuer, callbackUrl, SingleLogoutService)
    - Confirm entity ID and metadata
    - Verify attributes are configured correctly

2. Deploy with production settings:
    ```bash
    SAML_ENVIRONMENT=PRODUCTION node app.js
    ```

## Troubleshooting

### Every sign-in returns to the IdP, with no error

-   The callback route has no form body parser: add `app.use(express.urlencoded({ extended: false }))` before the routes
-   Check `express-session`, `passport.initialize()` and `passport.session()` come before the routes, in that order

### "InResponseTo is not valid"

-   The response reached a process that did not start the sign-in (more than one instance, or a redeploy mid-sign-in): see [Running more than one instance](#running-more-than-one-instance)
-   Or the same response was posted twice (the browser's back button, a refresh): this refusal is the replay protection working

### "Failed to load private key"

-   Ensure `privateKeyPath` points to an existing file
-   Check file permissions (app must be able to read it)
-   Verify the file contains a valid PEM-formatted private key

### SAML validation fails

-   Verify `cert` is the signing certificate of the IdP you are pointed at (LOCAL, STAGING and PRODUCTION each have their own)
-   Check that your Service Provider's entityID (issuer) matches what's registered with UBC
-   Ensure `callbackUrl` exactly matches what's registered with UBC IAM
-   If you set `privateKeyPath`, the IdP must hold your SP's certificate (docker-simple-saml answers "Missing certificate in metadata")
-   Check server clocks are synchronized (NTP)

### Attributes not returned

-   Verify attributes are listed in your `attributeConfig`
-   Check that UBC IAM has authorized release of those attributes to your app
-   Use the `attributeConfig` to only request attributes your app truly needs

## Documentation

- **[LOCAL_SETUP.md](./LOCAL_SETUP.md)** - Local development with SimpleSAMLphp using docker-simple-saml
- **[ATTRIBUTES.md](./ATTRIBUTES.md)** - The SAML attributes the library maps, and how release is requested
- **[TESTING.md](./TESTING.md)** - Testing strategies and debugging techniques
- **[DEVELOPMENT.md](./DEVELOPMENT.md)** - For library maintainers and contributors
- **[CHANGELOG.md](./CHANGELOG.md)** - What changed in each release

## Contributing

For issues, questions, or contributions, please contact the UBC IAM team.

## License

GPL v3 only (SPDX: `GPL-3.0-only`). See [LICENSE](./LICENSE).

## References

-   [Passport.js Documentation](http://www.passportjs.org/)
-   [`@node-saml/node-saml` Documentation](https://github.com/node-saml/node-saml)
-   [SAML 2.0 Standard](https://en.wikipedia.org/wiki/SAML_2.0)
-   [Shibboleth Documentation](https://wiki.shibboleth.net/)
