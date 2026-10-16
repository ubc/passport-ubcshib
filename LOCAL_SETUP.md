# Local Development with SimpleSAMLphp

This guide explains how to set up and use `passport-ubcshib` with a local SimpleSAMLphp IdP for development and testing.

## Overview

For local development, you can use **SimpleSAMLphp**, a reference implementation of SAML that allows you to run a complete IdP locally without needing access to UBC's production or staging infrastructure.

This document explains how to:
1. Start a local SimpleSAMLphp IdP using [docker-simple-saml](https://github.com/ubc/docker-simple-saml)
2. Configure `passport-ubcshib` to use it
3. Test authentication flows locally
4. Transition to STAGING and PRODUCTION

> **0.1.7: pass `entryPoint` and `logoutUrl` yourself.** The library's `LOCAL` preset still points at `http://localhost:8080` with SimpleSAMLphp 1.x-era paths. docker-simple-saml now runs **SimpleSAMLphp 2.x on port 6122**, so with `SAML_ENVIRONMENT=LOCAL` alone the browser is sent to a port nothing listens on. Step 4 shows the options to pass.

## Quick Start

### 1. Start SimpleSAMLphp IdP

Clone and start the docker-simple-saml container:

```bash
git clone https://github.com/ubc/docker-simple-saml.git
cd docker-simple-saml
docker compose up -d --build
```

The IdP is served at `http://localhost:6122/simplesaml/`. Its SAML 2.x endpoints are:

| Endpoint | URL |
|----------|-----|
| **Single sign-on** | `http://localhost:6122/simplesaml/module.php/saml/idp/singleSignOnService` |
| **Single logout** | `http://localhost:6122/simplesaml/module.php/saml/idp/singleLogout` |
| **Metadata** | `http://localhost:6122/simplesaml/module.php/saml/idp/metadata` |

### 2. Register Your App with the Local IdP

docker-simple-saml only answers Service Providers listed in its `config/simplesamlphp/saml20-sp-remote.php`. Your app's `issuer` must be one of the entity IDs there (for example `http://localhost:8050`), and your `callbackUrl` must be the AssertionConsumerService registered for it (for the generic rows, `<base URL>/auth/saml/callback`). To use your own entity ID or callback path, add a row for your app to that file in your copy of docker-simple-saml.

### 3. Get the IdP's Certificate

`cert` is required. docker-simple-saml generates its key pair on first start; copy the certificate from your docker-simple-saml folder:

```bash
mkdir -p ./certs
cp ../docker-simple-saml/cert/server.crt ./certs/idp-cert.pem
```

(It is also in the IdP's metadata, at the metadata URL above.)

**Do not set `privateKeyPath` locally unless your SP's row in `saml20-sp-remote.php` carries your certificate (`certData`).** Setting it makes the strategy sign every AuthnRequest, and SimpleSAMLphp validates any signature that is present: without your certificate it refuses the sign-in with "Missing certificate in metadata".

### 4. Configure passport-ubcshib

In your application's `.env` file (every name except `SAML_ENVIRONMENT` and `SAML_LOGOUT_URL` is your app's own, read by the code below):

```bash
SAML_ENVIRONMENT=LOCAL

# An entity ID registered in docker-simple-saml's saml20-sp-remote.php, and its ACS
SAML_ISSUER=http://localhost:8050
SAML_CALLBACK_URL=http://localhost:8050/auth/saml/callback

# The local IdP's certificate (step 3)
SAML_IDP_CERT_PATH=./certs/idp-cert.pem

# Read by the library's logout() helper, which does not read the strategy's logoutUrl
SAML_LOGOUT_URL=http://localhost:6122/simplesaml/module.php/saml/idp/singleLogout
```

In your app.js or auth configuration:

```javascript
const fs = require('fs');
const passport = require('passport');
const { Strategy } = require('passport-ubcshib');

const LOCAL_IDP = 'http://localhost:6122/simplesaml/module.php/saml/idp';

passport.use(
  new Strategy(
    {
      issuer: process.env.SAML_ISSUER,
      callbackUrl: process.env.SAML_CALLBACK_URL,
      cert: fs.readFileSync(process.env.SAML_IDP_CERT_PATH, 'utf8'),
      // Until the LOCAL preset is updated, point the strategy at docker-simple-saml:
      entryPoint: `${LOCAL_IDP}/singleSignOnService`,
      logoutUrl: `${LOCAL_IDP}/singleLogout`,
      // Request specific attributes from IdP
      attributeConfig: [
        'ubcEduCwlPuid',
        'mail',
        'eduPersonAffiliation',
        'givenName',
        'sn',
      ],
    },
    (profile, done) => {
      // Verify callback - process authenticated user
      return done(null, profile);
    }
  )
);

// express.urlencoded(), express-session, passport.initialize() and
// passport.session() as in the README's Quick Start.
```

### 5. Test Authentication

1. Start your application on the port its registered entity ID names
2. Navigate to your login route (for example `http://localhost:8050/auth/ubcshib`)
3. You'll be redirected to the SimpleSAMLphp login page on `http://localhost:6122/simplesaml/...`
4. Sign in as one of docker-simple-saml's test users
5. You'll be redirected back to your application with the SAML response
6. Your verify callback receives the user profile with attributes

## Local Development Features

### Test Users

docker-simple-saml defines its test users, with their passwords and attributes, in `config/simplesamlphp/authsources.php` (the `example-userpass` auth source).

To sign in as a different test user, end the IdP's own session first: visit `http://localhost:6122/simplesaml/module.php/core/logout/example-userpass`. Signing out of your app alone leaves the IdP session alive, and the next sign-in completes without asking for a password.

### Attribute Names: friendly locally, OIDs at UBC

docker-simple-saml releases attributes under their **friendly names** (`ubcEduCwlPuid`, `mail`, `eduPersonAffiliation`, ...). UBC's IdP releases them under their **OID names** (`urn:oid:1.3.6.1.4.1.60.6.1.6`, ...). With `attributeConfig` set, `profile.attributes` holds friendly names from either IdP. Without it, nothing is mapped and `profile.attributes` is keyed by whatever names the IdP sent, so code that works locally breaks at UBC. Always set `attributeConfig`.

### Environment URLs

With `SAML_ENVIRONMENT=LOCAL`, 0.1.7's preset (`UBC_CONFIG.LOCAL` in `index.js`) supplies these when you do not pass them:

| Setting | 0.1.7 `LOCAL` preset | docker-simple-saml today |
|---------|----------------------|--------------------------|
| **Entry Point (SSO)** | `http://localhost:8080/simplesaml/saml2/idp/SSOService.php` | `http://localhost:6122/simplesaml/module.php/saml/idp/singleSignOnService` |
| **Logout URL** | `http://localhost:8080/simplesaml/saml2/idp/SingleLogoutService.php` | `http://localhost:6122/simplesaml/module.php/saml/idp/singleLogout` |
| **Metadata URL** | `http://localhost:8080/simplesaml/saml2/idp/metadata.php` | `http://localhost:6122/simplesaml/module.php/saml/idp/metadata` |

The port is what breaks: nothing in docker-simple-saml listens on 8080. (Earlier versions of this guide gave the logout URL as `/simplesaml/module.php/saml/sp/singleLogout.php`, an SP endpoint the library never used.) SimpleSAMLphp 2.4 and 2.5 still ship the 1.x-style `/saml2/idp/*.php` scripts as deprecated aliases (read from SimpleSAMLphp's source, not measured), but use the module routes above: the aliases are marked for removal.

Only two environment variables are read by the library: `SAML_ENVIRONMENT`, and `SAML_LOGOUT_URL` (by the `logout()` helper only). Every other endpoint override is an option you pass in code, as in step 4.

### Signing Out Locally

-   Mount `passport.authenticate('ubcshib')` at the route registered as your SP's SingleLogoutService (`<base URL>/auth/logout` for docker-simple-saml's generic rows) to answer the IdP's LogoutRequests. Do not mount the library's `logout()` helper there.
-   The library's `logout()` helper redirects to `SAML_LOGOUT_URL` with no SAML message. SimpleSAMLphp's `singleLogout` endpoint expects a SAML message or a `ReturnTo` parameter (SimpleSAMLphp 2.4.9.3 `modules/saml/src/Controller/SingleLogout.php`, read from source, not measured), so expect it to answer with an error page; use the `core/logout/example-userpass` URL above to end the IdP session.

### HTTP vs HTTPS

Local development with SimpleSAMLphp uses **HTTP** (not HTTPS):

- **Development**: Use `http://localhost:<port>/...` URLs for `issuer` and `callbackUrl`
- **Production/Staging**: Use `https://...` URLs

If you need HTTPS for local testing, consider:
- Using [ngrok](https://ngrok.com) to create an HTTPS tunnel to your local app
- Using a self-signed certificate with a custom domain name (e.g., `saml.local`)

## Debugging and Troubleshooting

### Check SimpleSAMLphp is Running

```bash
curl -s http://localhost:6122/simplesaml/module.php/saml/idp/metadata | grep -c X509Certificate
```

A count of 1 or more means the IdP is up AND can sign. A `200` from `/simplesaml/` alone does not show that.

### Enable Debug Logging

`@node-saml` logs through the `debug` package under the `node-saml` namespace. Set it in the environment before the app starts:

```bash
DEBUG=node-saml npm start
```

### Common Issues

**Browser sent to `localhost:8080`, connection refused**
- The `LOCAL` preset is in use: pass `entryPoint` and `logoutUrl` (step 4)

**"Invalid signature" errors**
- Ensure you're using the local IdP's certificate (`cert/server.crt` from your docker-simple-saml folder), not staging's or production's
- Regenerating docker-simple-saml's certificate means copying it again

**"Missing certificate in metadata" from the IdP**
- You set `privateKeyPath`, so the AuthnRequest is signed, and your SP's row has no `certData`: remove `privateKeyPath` locally, or add your certificate to the row

**The IdP shows an error instead of a login page**
- Your `issuer` is not an entity ID in docker-simple-saml's `saml20-sp-remote.php`, or `callbackUrl` is not the ACS registered for it

**Every sign-in returns to the IdP, with no error**
- The app has no form body parser before the callback route: add `app.use(express.urlencoded({ extended: false }))`
- Check that express-session middleware is configured before passport, and `passport.session()` after `passport.initialize()`

**"No test users available"**
- Check docker-simple-saml is running: `docker compose ps`
- See `config/simplesamlphp/authsources.php` in docker-simple-saml

## Moving to STAGING

Once your local testing is complete, transition to UBC's staging environment:

### 1. Update the Environment and Remove the Local Overrides

```bash
SAML_ENVIRONMENT=STAGING
```

Remove the `entryPoint` and `logoutUrl` you passed for docker-simple-saml (the `STAGING` preset supplies UBC's), and unset `SAML_LOGOUT_URL`.

### 2. Update URLs

```bash
# Must use HTTPS for staging/production
SAML_ISSUER=https://myapp.example.com/shibboleth
SAML_CALLBACK_URL=https://myapp.example.com/auth/ubcshib/callback
```

### 3. Get the Staging IdP Certificate

```bash
# Fetch UBC staging IdP metadata
curl https://authentication.stg.id.ubc.ca/idp/shibboleth > ./certs/staging-metadata.xml

# Extract the signing certificate
python3 << 'EOF'
import xml.etree.ElementTree as ET

tree = ET.parse('./certs/staging-metadata.xml')
root = tree.getroot()

namespaces = {
    'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
    'ds': 'http://www.w3.org/2000/09/xmldsig#'
}

for idp in root.findall('.//md:IDPSSODescriptor', namespaces):
    for key_desc in idp.findall('.//md:KeyDescriptor[@use="signing"]', namespaces):
        cert_elem = key_desc.find('.//ds:X509Certificate', namespaces)
        if cert_elem is not None and cert_elem.text:
            cert_data = ''.join(cert_elem.text.split())
            with open('./certs/staging-idp-cert.pem', 'w') as f:
                f.write('-----BEGIN CERTIFICATE-----\n')
                for i in range(0, len(cert_data), 64):
                    f.write(cert_data[i:i+64] + '\n')
                f.write('-----END CERTIFICATE-----\n')
            print("Staging IdP certificate extracted")
            break
    break
EOF
```

### 4. Update Your .env

```bash
# Staging configuration
SAML_ENVIRONMENT=STAGING
SAML_ISSUER=https://myapp.example.com/shibboleth
SAML_CALLBACK_URL=https://myapp.example.com/auth/ubcshib/callback
SAML_IDP_CERT_PATH=./certs/staging-idp-cert.pem
```

### 5. Register with UBC IAM

Contact UBC Identity & Access Management to register your application:
- Provide your `issuer` (entity ID), callback URL and SingleLogoutService URL
- Provide your SP certificate if you set `privateKeyPath` (the strategy then signs its AuthnRequests)
- Request approval for staging environment testing

See the README's *Testing with Staging Environment* and *Production Deployment*.

## Additional Resources

- [SimpleSAMLphp Official Documentation](https://simplesamlphp.org/)
- [SAML 2.0 Overview](https://en.wikipedia.org/wiki/SAML_2.0)
- [UBC Authentication Services](https://it.ubc.ca/services/auth-systems)
- [docker-simple-saml Repository](https://github.com/ubc/docker-simple-saml)
