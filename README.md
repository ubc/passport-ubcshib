# @ubcshib/passport-ubcshib

A Passport.js strategy for integrating UBC's Shibboleth SAML 2.0 Identity Provider with Node.js applications. An extension of the passport-saml library, with thanks to University of Washington for publishing theirs from which we could work: https://www.passportjs.org/packages/passport-uwshib/

## Features

-   **SAML 2.0 Support**: Full SAML 2.0 authentication with UBC's Shibboleth IdP
-   **Multi-Environment**: Automatic configuration for staging and production environments
-   **Flexible Attributes**: Per-application attribute selection with OID-to-friendly-name mapping
-   **Secure**: Supports SAML request signing and response validation
-   **Single Logout (SLO)**: Optional support for single logout at the IdP
-   **Certificate Management**: Automatic fetching of IdP certificates from metadata
-   **Environment-Based Configuration**: Support for both environment variables and runtime configuration

## Installation

```bash
npm install passport-ubcshib passport
```

## Quick Start

### 1. Configure Passport

```javascript
const passport = require('passport');
const { Strategy } = require('passport-ubcshib');
const fs = require('fs');

passport.use(
	new Strategy(
		{
			// Service Provider Identity (usually your app's URL)
			issuer: 'https://myapp.example.com/shibboleth',

			// Callback URL after authentication
			callbackUrl: 'https://myapp.example.com/auth/ubcshib/callback',

			// Path to your application's private key for signing SAML requests
			privateKeyPath: process.env.SAML_PRIVATE_KEY_PATH,

			// Specify which attributes your app needs
			// See ATTRIBUTES.md for full list of available attributes
			attributeConfig: ['ubcEduCwlPuid', 'mail', 'eduPersonAffiliation'],

			// Optional: Enable single logout
			enableSLO: true,
		},
		// Verify callback: called with user profile after successful authentication
		(profile, done) => {
			// profile.nameID - SAML nameID
			// profile.attributes - Mapped attributes based on attributeConfig

			User.findOrCreate(
				{ ubcId: profile.attributes.ubcEduCwlPuid },
				(err, user) => {
					return done(err, user);
				}
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

### 2. Set Up Routes

```javascript
const express = require('express');
const passport = require('passport');
const { ensureAuthenticated, logout } = require('passport-ubcshib');

const app = express();

// Login route - redirects to UBC IdP
app.get('/auth/ubcshib', passport.authenticate('ubcshib'));

// Callback route - called by UBC IdP after authentication
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

// Logout
app.get('/logout', logout('/'));
```

### 3. Configure Environment

Create a `.env` file:

```env
# SAML Configuration
SAML_ENVIRONMENT=STAGING  # or PRODUCTION
SAML_PRIVATE_KEY_PATH=/path/to/your/private.key
SAML_ISSUER=https://myapp.example.com/shibboleth
SAML_CALLBACK_URL=https://myapp.example.com/auth/ubcshib/callback

# Attributes your app needs
# (optional - can also configure in code)
```

## Configuration Options

### Required Options

| Option        | Type   | Description                                                                               |
| ------------- | ------ | ----------------------------------------------------------------------------------------- |
| `issuer`      | string | Your Service Provider's entity ID (usually your app's base URL + `/shibboleth`)           |
| `callbackUrl` | string | URL where the IdP redirects after authentication (must match registered URL with UBC IAM) |

### Optional Options

| Option                 | Type    | Default                               | Description                                                     |
| ---------------------- | ------- | ------------------------------------- | --------------------------------------------------------------- |
| `privateKeyPath`       | string  | null                                  | Path to your app's private key for signing SAML requests        |
| `attributeConfig`      | Array   | []                                    | List of attribute names to request from IdP (see ATTRIBUTES.md) |
| `entryPoint`           | string  | Staging or Production SSO endpoint    | Identity Provider's SSO endpoint                                |
| `logoutUrl`            | string  | Staging or Production logout endpoint | Identity Provider's logout endpoint                             |
| `enableSLO`            | boolean | true                                  | Enable single logout (SLO) on user logout                       |
| `validateInResponseTo` | boolean | true                                  | Validate response InResponseTo against request ID               |
| `acceptedClockSkewMs`  | number  | 0                                     | Allowed clock skew in milliseconds between servers              |
| `signatureAlgorithm`   | string  | 'sha256'                              | SAML signature algorithm (sha256, sha512, etc.)                 |

### Environment Variables

The following environment variables can be used to configure the strategy:

```env
# Environment selection
SAML_ENVIRONMENT=STAGING  # STAGING or PRODUCTION

# For custom IdP configuration
SAML_ENTRY_POINT=https://authentication.ubc.ca/idp/profile/SAML2/Redirect/SSO
SAML_LOGOUT_URL=https://authentication.ubc.ca/idp/profile/Logout
SAML_METADATA_URL=https://authentication.ubc.ca/idp/shibboleth

# Private key location
SAML_PRIVATE_KEY_PATH=/etc/app/saml/private.key

# Service Provider config
SAML_ISSUER=https://myapp.example.com/shibboleth
SAML_CALLBACK_URL=https://myapp.example.com/auth/ubcshib/callback

# Enable/disable features
ENABLE_SLO=true
```

## Environments

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

## Attribute Mapping

The strategy automatically maps SAML OID attribute names to friendly names. See **ATTRIBUTES.md** for the complete reference.

Common attributes:

-   `ubcEduCwlPuid` - UBC Computing User ID
-   `mail` - Email address
-   `eduPersonAffiliation` - Affiliation (student, faculty, staff, etc.)

### Adding New Attributes

Need to add support for a new attribute? See **ADDING_ATTRIBUTES.md** for a step-by-step guide on how to add new OID mappings to the library.

After successful authentication, mapped attributes are available as:

```javascript
req.user.attributes = {
	ubcEduCwlPuid: '12345678',
	mail: 'user@ubc.ca',
	eduPersonAffiliation: ['student', 'member'],
};
```

## Helper Middleware

### ensureAuthenticated(options)

Middleware to protect routes. Redirects unauthenticated users to login.

```javascript
const { ensureAuthenticated } = require('@ubcshib/passport-ubcshib');

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

Middleware to handle logout. Clears session and optionally redirects to IdP logout if SLO is enabled.

```javascript
const { logout } = require('@ubcshib/passport-ubcshib');

app.get('/logout', logout('/goodbye'));
```

### conditionalAuth(checkFn)

Middleware to conditionally protect routes based on a function.

```javascript
const { conditionalAuth } = require('@ubcshib/passport-ubcshib');

app.get(
	'/maybe-protected',
	conditionalAuth((req) => req.query.admin === 'true'),
	(req, res) => {
		res.send('Protected if admin query param is true');
	}
);
```

## Profile Structure

After successful authentication, the user profile will have:

```javascript
profile = {
	nameID: 'user@ubc.ca', // SAML nameID (usually email)
	nameIDFormat: '...', // SAML format identifier
	attributes: {
		// Mapped attributes (from attributeConfig)
		ubcEduCwlPuid: '12345678',
		mail: 'user@ubc.ca',
		eduPersonAffiliation: ['student'],
	},
};
```

## Certificate Management

The strategy automatically fetches the IdP's public certificate from the metadata endpoint. No configuration is needed for certificate handling in most cases.

If you need to provide a certificate manually:

```javascript
new Strategy(
	{
		// ... other options
		cert: fs.readFileSync('/path/to/idp-cert.pem', 'utf8'),
	},
	verifyCallback
);
```

## Testing with Staging Environment

1. **Request metadata from UBC IAM**:

    - Provide them with your Service Provider's metadata
    - They will configure your app in their staging environment
    - They will provide you with Entity ID confirmation

2. **Test in Staging**:

    ```bash
    SAML_ENVIRONMENT=STAGING SAML_PRIVATE_KEY_PATH=/path/to/key node app.js
    ```

3. **Validate attributes**:
    - Visit `https://authentication.stg.id.ubc.ca/idp/shibboleth` to see available attributes
    - Add to `attributeConfig` in your code

## Production Deployment

1. Work with UBC IAM to:

    - Register your production URLs (issuer, callbackUrl)
    - Confirm entity ID and metadata
    - Verify attributes are configured correctly

2. Deploy with production settings:
    ```bash
    SAML_ENVIRONMENT=PRODUCTION node app.js
    ```

## Troubleshooting

### "Failed to load private key"

-   Ensure `SAML_PRIVATE_KEY_PATH` points to an existing file
-   Check file permissions (app must be able to read it)
-   Verify the file contains a valid PEM-formatted private key

### "No X509Certificate found in IdP metadata"

-   Check that the IdP metadata URL is accessible
-   Verify you're using the correct environment
-   Try accessing the metadata URL in a browser

### SAML validation fails

-   Verify your private key matches what UBC IAM has on file
-   Check that your Service Provider's entityID (issuer) matches what's registered with UBC
-   Ensure `callbackUrl` exactly matches what's registered with UBC IAM
-   Check server clocks are synchronized (NTP)

### Attributes not returned

-   Verify attributes are listed in your `attributeConfig`
-   Check that UBC IAM has authorized release of those attributes to your app
-   Use the `attributeConfig` to only request attributes your app truly needs

## Contributing

For issues, questions, or contributions, please contact the UBC IAM team.

## License

MIT

## References

-   [Passport.js Documentation](http://www.passportjs.org/)
-   [Passport-SAML Documentation](https://github.com/node-saml/node-saml)
-   [SAML 2.0 Standard](https://en.wikipedia.org/wiki/SAML_2.0)
-   [Shibboleth Documentation](https://wiki.shibboleth.net/)
