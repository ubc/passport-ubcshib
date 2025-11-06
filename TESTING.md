# Testing Guide for @ubcshib/passport-ubcshib

This guide covers how to test the passport-ubcshib strategy during development and deployment.

## Prerequisites

- Node.js 22+
- npm or yarn
- A private key and certificate for your Service Provider
- Access to UBC's Shibboleth IdP (staging or production)

## Local Development Setup

### 1. Generate Test Certificates

If you don't have a private key and certificate yet, generate test ones:

```bash
# Generate a self-signed certificate and private key
openssl req -new -x509 -days 365 -nodes \
  -out sp-cert.pem \
  -keyout sp-key.pem \
  -subj "/CN=localhost"
```

### 2. Install Dependencies

```bash
npm install
# or for the example app:
cd example
npm install
```

### 3. Configure Environment

Copy the example configuration:

```bash
cp example/.env.example .env
```

Edit `.env` with your test values:

```env
# For local development
SAML_ENVIRONMENT=STAGING
SAML_ISSUER=https://localhost:3000/shibboleth
SAML_CALLBACK_URL=https://localhost:3000/auth/ubcshib/callback
SAML_PRIVATE_KEY_PATH=./sp-key.pem
NODE_ENV=development
```

### 4. Register with UBC IAM (Staging)

Before you can test:

1. Generate your Service Provider's metadata (the strategy does this automatically)
2. Contact UBC IAM and provide:
   - Your Service Provider Entity ID: `https://localhost:3000/shibboleth`
   - Your metadata
   - Your callback URL
3. Ask them to register your app in the **staging** environment
4. They will confirm registration and provide you with details

### 5. HTTPS for Local Testing

UBC's Shibboleth IdP requires HTTPS (even for staging). For local development, you have options:

#### Option A: Use ngrok (Recommended)

Tunnel your local app through ngrok to get a public HTTPS URL:

```bash
# Install ngrok: https://ngrok.com/

# Start your app locally
npm start

# In another terminal, tunnel it
ngrok http 3000

# Update .env with the ngrok URL
SAML_ISSUER=https://your-ngrok-url.ngrok.io/shibboleth
SAML_CALLBACK_URL=https://your-ngrok-url.ngrok.io/auth/ubcshib/callback

# Register this URL with UBC IAM
```

#### Option B: Docker with HTTPS

Use Docker to run your app with HTTPS:

```bash
# Create a Dockerfile or use docker-compose
# (See examples online for Express + HTTPS in Docker)
```

#### Option C: Disable SSL Verification (Dev Only - Insecure!)

For quick testing only:

```bash
NODE_TLS_REJECT_UNAUTHORIZED=0 NODE_ENV=development npm start
```

⚠️ **Never use this in production!**

## Running Tests

### Unit Tests (if implemented)

```bash
npm test
```

### Integration Testing with UBC Staging

#### 1. Start the Example App

```bash
cd example
npm install
npm start
```

#### 2. Visit the App

Open https://your-app-url/ in a browser

#### 3. Click Login

Click "Login with UBC Shibboleth" - you should be redirected to the UBC IdP login page

#### 4. Authenticate

- Enter your UBC CWL credentials
- Complete any MFA challenges
- Accept attribute release (if prompted)

#### 5. Verify Attributes

After authentication, the app should display:
- Your UBC ID (ubcEduCwlPuid)
- Your email (mail)
- Your affiliation (eduPersonAffiliation)
- Any other configured attributes

#### 6. Check Logs

Look at the console logs:

```
SAML Profile received: {
  nameID: 'your-email@ubc.ca',
  attributes: {
    ubcEduCwlPuid: '12345678',
    mail: 'your-email@ubc.ca',
    eduPersonAffiliation: ['student'],
    ...
  }
}
```

## Debugging

### Enable Debug Logging

Set the DEBUG environment variable:

```bash
DEBUG=passport-saml* npm start
```

Or for more verbose output:

```bash
DEBUG=* npm start
```

### Check SAML Request/Response

The `passport-saml` library includes debugging. Set:

```bash
NODE_DEBUG=http npm start
```

### Common Issues

#### "Callback URL mismatch"
- **Problem**: The callback URL in your IdP configuration doesn't match your app
- **Solution**: Ensure SAML_CALLBACK_URL exactly matches what's registered with UBC IAM

#### "Signature validation failed"
- **Problem**: The private key doesn't match what UBC IAM has on file
- **Solution**: Regenerate your certificate and key, send the new certificate to UBC IAM

#### "Certificate not found in metadata"
- **Problem**: The IdP metadata endpoint is unreachable or doesn't contain certificates
- **Solution**:
  - Check network connectivity to the metadata URL
  - Verify you're using the correct environment (staging vs production)
  - Test accessing the metadata URL in a browser

#### "No attributes returned"
- **Problem**: SAML response arrives but attributes are empty
- **Solution**:
  - Check that your app is authorized to receive those attributes
  - Verify attribute names are correct in `attributeConfig`
  - Contact UBC IAM to confirm attribute release is configured

## Testing Different Scenarios

### Test as Different User Types

If you have access to multiple test accounts:

1. **Student Account**
   - Verify `eduPersonAffiliation` includes 'student'
   - Test student-specific features

2. **Faculty Account**
   - Verify `eduPersonAffiliation` includes 'faculty'
   - Test faculty-specific features

3. **Staff Account**
   - Verify `eduPersonAffiliation` includes 'staff'

### Test Multi-Value Attributes

Some attributes return multiple values. Verify your app handles them:

```javascript
// eduPersonAffiliation might be an array
const affiliations = profile.attributes.eduPersonAffiliation;
if (Array.isArray(affiliations)) {
  affiliations.forEach(aff => {
    console.log('User affiliation:', aff);
  });
}
```

### Test Session Management

1. Log in and verify session is created
2. Close browser and reopen - session should persist
3. Click logout - session should be cleared
4. Try accessing protected routes - should redirect to login

## Production Testing

### Before Going Live

1. **Complete staging testing** - verify all features work
2. **Get production approval** from UBC IAM
3. **Register in production environment**
4. **Update .env** to use production URLs:
   ```env
   SAML_ENVIRONMENT=PRODUCTION
   SAML_ISSUER=https://myapp.ubc.ca/shibboleth
   SAML_CALLBACK_URL=https://myapp.ubc.ca/auth/ubcshib/callback
   ```
5. **Deploy to production**
6. **Smoke test** with a real user account
7. **Monitor logs** for errors

### Production Configuration Checklist

- [ ] HTTPS enabled (certificate must be valid)
- [ ] SAML_ENVIRONMENT=PRODUCTION
- [ ] Correct production URLs in env vars
- [ ] Production certificate/key deployed
- [ ] Production URLs registered with UBC IAM
- [ ] Error handling configured
- [ ] Logging configured
- [ ] Session storage configured (not in-memory!)
- [ ] CSRF protection enabled in Express

## Monitoring

### What to Log

```javascript
// Log successful authentication
console.log('User authenticated:', {
  id: user.id,
  email: user.email,
  affiliation: user.affiliation
});

// Log failures (without sensitive data)
console.error('Authentication failed:', {
  reason: err.message,
  code: err.code
});
```

### What to Monitor

- Authentication success/failure rates
- Failed SAML validation errors
- Certificate fetch failures
- Session creation and cleanup
- User attribute completeness

## Troubleshooting Checklist

- [ ] App is running on HTTPS
- [ ] Private key path is correct and file exists
- [ ] Service Provider entity ID matches registration
- [ ] Callback URL exactly matches registration
- [ ] Environment (STAGING vs PRODUCTION) is correct
- [ ] UBC IAM has authorized your app
- [ ] Requested attributes are in `attributeConfig`
- [ ] UBC IAM has authorized attribute release to your app
- [ ] Firewall/network allows HTTPS traffic to UBC IdP
- [ ] Server time is synchronized (NTP)

## Getting Help

If you encounter issues:

1. Check the [main README](README.md) for configuration help
2. Check [ATTRIBUTES.md](ATTRIBUTES.md) for attribute questions
3. Check your application logs
4. Try the example app first to isolate issues
5. Contact UBC IAM with:
   - Your Service Provider entity ID
   - The error message
   - Steps to reproduce
   - Environment (staging/production)

## References

- [Passport.js Documentation](http://www.passportjs.org/)
- [SAML 2.0 Specification](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [Shibboleth IdP Documentation](https://wiki.shibboleth.net/)
- [Certificate Generation Guide](https://www.ssl.com/article/how-to-create-self-signed-certificates/)
