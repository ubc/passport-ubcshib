# Development Guide

This document is for developers working on the `passport-ubcshib` library itself, not for developers using the library in their applications (see [README.md](README.md) for that).

## Project Structure

```
passport-ubcshib/
├── index.js                    # Main strategy implementation
├── package.json               # Package metadata and dependencies
├── README.md                  # User-facing documentation
├── ATTRIBUTES.md              # Reference for available SAML attributes
├── TESTING.md                 # Testing guide for end users
├── DEVELOPMENT.md             # This file
├── .gitignore                 # Git ignore rules
├── lib/
│   └── attributes.js          # OID-to-friendly-name mappings and utilities
├── example/
│   ├── .env.example           # Example environment configuration
│   └── app.js                 # Example Express application
└── production.html            # Documentation (reference)
```

## Architecture

### Main Components

#### 1. **UBCStrategy Class** (`index.js`)

-   Extends `passport-saml.Strategy`
-   Handles UBC-specific configuration
-   Manages certificate fetching from IdP metadata
-   Wraps the verify callback to handle attribute mapping

#### 2. **Attribute Mapping** (`lib/attributes.js`)

-   Maps OID attribute names to friendly names
-   Filters attributes based on app configuration
-   Provides utilities for attribute handling

#### 3. **Environment Configuration**

-   Supports staging and production environments
-   Defaults built-in for UBC IdP endpoints
-   Can be overridden per application

## Development Setup

### Prerequisites

-   Node.js 22+
-   npm or yarn
-   Understanding of SAML 2.0
-   Understanding of Passport.js

### Installation

```bash
# Clone the repository
git clone https://github.com/ubc/passport-ubcshib.git
cd passport-ubcshib

# Install dependencies
npm install

# Install example app dependencies
cd example && npm install && cd ..
```

### Code Style

Currently no formal style guide is enforced. Follow these principles:

-   Use 2-space indentation
-   Use semicolons
-   Clear variable names
-   Comment complex logic
-   Avoid deeply nested code

### Making Changes

#### Adding a New Attribute

1. Update `lib/attributes.js` with the OID mapping:

    ```javascript
    const ATTRIBUTE_MAPPINGS = {
    	'urn:oid:1.3.6.1.4.1.60.6.1.5': 'ubcEduCwlPuid',
    	'urn:oid:NEW_OID_HERE': 'newAttributeName', // Add here
    };
    ```

2. Update `ATTRIBUTES.md` with documentation

3. Test with the example app

#### Modifying Strategy Configuration

1. Update the `UBCStrategy` constructor in `index.js`
2. Update `README.md` with new options
3. Update `.env.example` if it's an environment variable
4. Test with the example app

#### Fixing a Bug

1. Create a minimal test case
2. Fix the bug
3. Verify the test case passes
4. Update relevant documentation

## Testing

### Manual Testing with Example App

```bash
# Configure environment
cp example/.env.example example/.env
# Edit example/.env with your test values

# Start the example app
cd example
npm start

# Visit https://localhost:3000
```

### Debugging

Enable debug output:

```bash
DEBUG=* npm start
```

Check logs in the example app's console output.

## Key Design Decisions

### 1. Extend passport-saml vs. Standalone

**Decision**: Extend `passport-saml.Strategy`

**Rationale**:

-   SAML handling is complex; no need to reinvent it
-   Follows the pattern of similar libraries (passport-uwshib)
-   Leverages battle-tested SAML implementation
-   Allows UBC-specific customization on top

### 2. Environment-Based Configuration

**Decision**: Support both environment variables and runtime config

**Rationale**:

-   Environment variables work well in containerized deployments
-   Runtime config allows apps to override per-instance
-   Both approaches are common in Node.js ecosystem

### 3. Attribute Mapping

**Decision**: Central mapping in library, configurable per app

**Rationale**:

-   Reduces boilerplate for app developers
-   Centralizes OID-to-friendly-name mappings
-   Apps only request what they need
-   Follows privacy-by-default principle

### 4. Certificate Handling

**Decision**: Fetch IdP certificate from metadata, private key from file

**Rationale**:

-   IdP cert is public; no security issue fetching it
-   Private key is sensitive; must be managed securely by each app
-   Metadata endpoint is the standard way to get IdP certificates

## Security Considerations

### Private Keys

-   Never log private keys
-   Always use file paths with restrictive permissions
-   In the library, never print or transmit private keys

### SAML Responses

-   Validate signatures (default behavior)
-   Check inResponseTo field (prevents replay attacks)
-   Validate certificate chains
-   Never disable security features in production

### Certificates

-   Keep IdP certificates current
-   Validate certificate dates before expiration
-   Support certificate rotation

## Version Management

### Versioning Scheme

Uses semantic versioning (MAJOR.MINOR.PATCH):

-   **MAJOR**: Breaking changes to API or behavior
-   **MINOR**: New features that are backward-compatible
-   **PATCH**: Bug fixes

### Release Process

1. Update version in `package.json`
2. Update `CHANGELOG.md` (if it exists)
3. Commit with message "Release v1.2.3"
4. Tag commit: `git tag -a v1.2.3`
5. Push: `git push origin main --tags`
6. Publish to npm: `npm publish`

## Publishing to npm

### First Time Setup

```bash
# Create npm account at https://www.npmjs.com/
# Login locally
npm login

# Set up scoped package (if using @ubcshib scope)
npm config set scope ubcshib
```

### Publishing

```bash
# From the project root
npm publish
```

## Documentation

### README.md

For end users - how to use the library in their apps.

### ATTRIBUTES.md

Reference for available SAML attributes and how to request them.

### TESTING.md

Testing guide for end users integrating the library.

### DEVELOPMENT.md (this file)

For developers working on the library itself.

### Comments in Code

-   Document complex SAML logic
-   Explain non-obvious configuration options
-   Link to SAML specs where relevant

## Common Tasks

### Running the Example App Locally

```bash
cd example
# Configure .env with staging details
npm start
# Visit https://localhost:3000
```

### Checking for Common Errors

```bash
# Check for console errors
npm start 2>&1 | grep -i error

# Check for missing dependencies
npm ls

# Verify package.json is valid
npm validate
```

### Updating Dependencies

```bash
# Check for outdated packages
npm outdated

# Update packages (test carefully!)
npm update
npm audit fix

# After updates, test thoroughly
npm test
cd example && npm start
```

## Debugging SAML Issues

### Enable More Logging

In `index.js`, add console logs to `UBCStrategy`:

```javascript
class UBCStrategy extends SamlStrategy {
	constructor(options, verify) {
		console.log('UBCStrategy constructor called with options:', {
			issuer: options.issuer,
			callbackUrl: options.callbackUrl,
			// Don't log privateKey!
		});
		// ... rest of constructor
	}
}
```

### Test SAML Metadata Fetch

```javascript
const https = require('https');
const { extractCertFromMetadata } = require('./index');

https.get('https://authentication.stg.id.ubc.ca/idp/shibboleth', (res) => {
	let data = '';
	res.on('data', (chunk) => (data += chunk));
	res.on('end', () => {
		const cert = extractCertFromMetadata(data);
		console.log('Certificate found:', cert.substring(0, 50) + '...');
	});
});
```

## Roadmap / Future Improvements

Potential areas for enhancement:

1. **Caching**: Cache IdP metadata and certificates for faster startup
2. **Testing**: Add automated test suite
3. **Logging**: Implement structured logging (optional)
4. **Multi-IdP**: Support multiple IdP configurations
5. **SLO**: More robust single logout handling
6. **TypeScript**: Add TypeScript definitions
7. **Advanced Features**:
    - Request signing algorithm selection
    - Encryption algorithm options
    - Custom SAML request builders

## Getting Help

-   Check existing code comments
-   Review passport-saml documentation
-   Refer to SAML 2.0 specifications
-   Ask in issues/discussions on GitHub

## Contributing

See the main README for contribution guidelines.

## License

MIT - See LICENSE file

## Contact

For questions about the library development:

-   Create an issue on GitHub
-   Contact UBC IAM team for SAML/IdP questions
