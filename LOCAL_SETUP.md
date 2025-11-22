# Local Development with SimpleSAMLphp

This guide explains how to set up and use `passport-ubcshib` with a local SimpleSAMLphp IdP for development and testing.

## Overview

For local development, you can use **SimpleSAMLphp**, a reference implementation of SAML that allows you to run a complete IdP locally without needing access to UBC's production or staging infrastructure.

This document explains how to:
1. Start a local SimpleSAMLphp IdP using [docker-simple-saml](https://github.com/ubc/docker-simple-saml)
2. Configure `passport-ubcshib` to use LOCAL environment
3. Test authentication flows locally
4. Transition to STAGING and PRODUCTION

## Quick Start

### 1. Start SimpleSAMLphp IdP

Clone and start the docker-simple-saml container:

```bash
git clone https://github.com/ubc/docker-simple-saml.git
cd docker-simple-saml
docker compose up -d
```

The IdP will be available at: `http://localhost:8080`

### 2. Configure Your Application

In your application's `.env` file:

```bash
# Use LOCAL environment for SimpleSAMLphp
SAML_ENVIRONMENT=LOCAL

# Your application's Service Provider entity ID
# For local development with http://, typically use localhost
SAML_ISSUER=http://localhost:3000/shibboleth

# Callback URL after successful authentication
SAML_CALLBACK_URL=http://localhost:3000/auth/ubcshib/callback

# Paths to your local development certificates
SAML_PRIVATE_KEY_PATH=./certs/sp-key.pem
SAML_CERT_PATH=./certs/idp-cert.pem
```

### 3. Generate Local Certificates

For local development, you can use self-signed certificates:

```bash
# Create certs directory
mkdir -p ./certs

# Generate a self-signed certificate and private key
openssl req -new -x509 -days 365 -nodes \
  -out ./certs/sp-cert.pem \
  -keyout ./certs/sp-key.pem \
  -subj "/CN=localhost"

# Fetch the SimpleSAMLphp IdP certificate from the local metadata
curl http://localhost:8080/simplesaml/saml2/idp/metadata.php > /tmp/metadata.xml

# Extract the certificate from metadata (using Python)
python3 << 'EOF'
import xml.etree.ElementTree as ET

tree = ET.parse('/tmp/metadata.xml')
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
            with open('./certs/idp-cert.pem', 'w') as f:
                f.write('-----BEGIN CERTIFICATE-----\n')
                for i in range(0, len(cert_data), 64):
                    f.write(cert_data[i:i+64] + '\n')
                f.write('-----END CERTIFICATE-----\n')
            print("IdP certificate extracted to ./certs/idp-cert.pem")
            break
    break
EOF
```

### 4. Initialize Your Application with passport-ubcshib

In your app.js or auth configuration:

```javascript
const express = require('express');
const passport = require('passport');
const fs = require('fs');
const UBCStrategy = require('passport-ubcshib').Strategy;

const app = express();

// Configure passport-ubcshib with LOCAL environment
passport.use(
  new UBCStrategy(
    {
      issuer: process.env.SAML_ISSUER,
      callbackUrl: process.env.SAML_CALLBACK_URL,
      privateKeyPath: process.env.SAML_PRIVATE_KEY_PATH,
      cert: fs.readFileSync(process.env.SAML_CERT_PATH, 'utf8'),
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
      // In local development, this creates or updates a user session
      return done(null, profile);
    }
  )
);

// Other passport setup...
```

### 5. Test Authentication

1. Start your application: `npm start` (or your app's start command)
2. Navigate to your login route: `http://localhost:3000/auth/ubcshib`
3. You'll be redirected to SimpleSAMLphp login page: `http://localhost:8080/simplesaml/...`
4. SimpleSAMLphp will show available test users (configured in docker-simple-saml)
5. Select a user to authenticate
6. You'll be redirected back to your application with the SAML response
7. Your verify callback receives the user profile with attributes

## Local Development Features

### Test Users

SimpleSAMLphp comes with pre-configured test users. Check the [docker-simple-saml documentation](https://github.com/ubc/docker-simple-saml) for available users and their attributes.

Typical test users:
- **admin**: Staff user with administrative attributes
- **student**: Student user with student affiliation
- **staff**: Staff member with staff affiliation

Attributes returned by local SimpleSAMLphp usually match the real UBC IdP format, including:
- `urn:oid:1.3.6.1.4.1.60.6.1.6` → `ubcEduCwlPuid`
- `urn:oid:1.3.6.1.4.1.5923.1.1.1.1` → `eduPersonAffiliation`
- `urn:oid:0.9.2342.19200300.100.1.3` → `mail`
- `urn:oid:2.5.4.42` → `givenName`
- `urn:oid:2.5.4.4` → `sn`

### Environment URLs

When using `SAML_ENVIRONMENT=LOCAL`, passport-ubcshib automatically configures:

| Setting | Value |
|---------|-------|
| **Entry Point (SSO)** | `http://localhost:8080/simplesaml/saml2/idp/SSOService.php` |
| **Metadata URL** | `http://localhost:8080/simplesaml/saml2/idp/metadata.php` |
| **Logout URL** | `http://localhost:8080/simplesaml/module.php/saml/sp/singleLogout.php` |

These can be overridden by setting environment variables if needed.

### HTTP vs HTTPS

Local development with SimpleSAMLphp uses **HTTP** (not HTTPS). passport-ubcshib handles this automatically when fetching IdP metadata, but your application needs to accept HTTP callbacks:

- **Development**: Use `http://localhost:3000/...` URLs in `SAML_ISSUER` and `SAML_CALLBACK_URL`
- **Production/Staging**: Use `https://...` URLs

If you need HTTPS for local testing, consider:
- Using [ngrok](https://ngrok.com) to create an HTTPS tunnel to your local app
- Using a self-signed certificate with a custom domain name (e.g., `saml.local`)

## Debugging and Troubleshooting

### Check SimpleSAMLphp is Running

```bash
curl http://localhost:8080/simplesaml/
```

Should return the SimpleSAMLphp admin interface.

### View SAML Metadata

```bash
curl http://localhost:8080/simplesaml/saml2/idp/metadata.php
```

This should show the IdP's XML metadata including the signing certificate.

### Enable Debug Logging

In your application, enable passport-saml debug logging:

```javascript
process.env.DEBUG = 'passport-saml:*';
```

This will show detailed SAML request/response information.

### Common Issues

**Certificate extraction fails**
- Ensure SimpleSAMLphp is running and metadata is accessible
- Check the metadata XML format hasn't changed
- Verify the certificate is in the correct X509Certificate element

**"Invalid signature" errors**
- Ensure you're using the correct IdP certificate (from LOCAL metadata, not staging/production)
- Verify certificate matches SimpleSAMLphp's actual signing certificate
- Check that your SP's private key matches the certificate you provided

**Redirect loop or "Cannot POST /auth/ubcshib/callback"**
- Ensure `SAML_CALLBACK_URL` exactly matches your route configuration
- Check that express-session middleware is configured before passport
- Verify passport.session() middleware is in correct order

**"No test users available"**
- Check docker-simple-saml is running: `docker compose ps`
- Review docker-simple-saml README for test user configuration
- May need to add test users to the SimpleSAMLphp configuration

## Moving to STAGING

Once your local testing is complete, transition to UBC's staging environment:

### 1. Update Environment Variable

```bash
# Change from LOCAL to STAGING
SAML_ENVIRONMENT=STAGING
```

### 2. Update URLs

```bash
# Must use HTTPS for staging/production
SAML_ISSUER=https://myapp.example.com/shibboleth
SAML_CALLBACK_URL=https://myapp.example.com/auth/ubcshib/callback
```

### 3. Get Proper Certificates

```bash
# Fetch UBC staging IdP certificate
curl https://authentication.stg.id.ubc.ca/idp/shibboleth > /tmp/staging-metadata.xml

# Extract the certificate (same Python script as above, but save to different location)
python3 << 'EOF'
import xml.etree.ElementTree as ET

tree = ET.parse('/tmp/staging-metadata.xml')
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
SAML_CERT_PATH=./certs/staging-idp-cert.pem
```

### 5. Register with UBC IAM

Contact UBC Identity & Access Management to register your application:
- Provide your `SAML_ISSUER` (entity ID)
- Provide your service provider metadata (can be generated by passport-saml)
- Request approval for staging environment testing

See the main [INTEGRATION-GUIDE.md](./INTEGRATION-GUIDE.md) for complete staging/production setup.

## Additional Resources

- [SimpleSAMLphp Official Documentation](https://simplesamlphp.org/)
- [SAML 2.0 Overview](https://en.wikipedia.org/wiki/SAML_2.0)
- [UBC Authentication Services](https://it.ubc.ca/services/auth-systems)
- [docker-simple-saml Repository](https://github.com/ubc/docker-simple-saml)
