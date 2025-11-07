/**
 * Example Express application using passport-ubcshib
 * This demonstrates a complete setup with authentication flow
 */

const fs = require('fs');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const path = require('path');
require('dotenv').config();

// Import the UBC Shibboleth strategy
const { Strategy: UBCStrategy, ensureAuthenticated, logout } = require('../index');

// Initialize Express app
const app = express();

// ============================================================================
// MIDDLEWARE SETUP
// ============================================================================

// Body parser
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Session management
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production', // HTTPS only in production
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// ============================================================================
// PASSPORT CONFIGURATION
// ============================================================================

// Configure UBC Shibboleth strategy
passport.use(
  new UBCStrategy(
    {
      // Required configuration
      issuer: process.env.SAML_ISSUER,
      callbackUrl: process.env.SAML_CALLBACK_URL,

      // Optional: private key for signing requests
      privateKeyPath: process.env.SAML_PRIVATE_KEY_PATH,

      // Required: IdP's public certificate for validating SAML responses
      // In production, load from /etc/your-app-name/saml/idp-cert.pem
      cert: fs.readFileSync('./example/idp-cert.pem', 'utf8'),

      // Specify which attributes your app needs
      attributeConfig: [
        'ubcEduCwlPuid',      // UBC Computing User ID
        'mail',               // Email address
        'eduPersonAffiliation', // User's affiliation
        'givenName',          // First name
        'sn',                 // Last name
        'displayName',        // Display name
      ],

      // Optional: enable single logout
      enableSLO: process.env.ENABLE_SLO !== 'false',
    },
    // Verify callback - called after successful authentication
    (profile, done) => {
      console.log('SAML Profile received:', {
        nameID: profile.nameID,
        attributes: profile.attributes,
      });

      // Here you would typically:
      // 1. Find or create user in your database
      // 2. Update user's SAML attributes
      // 3. Return the user object

      // Simple example - create a user object from profile
      const user = {
        id: profile.attributes.ubcEduCwlPuid,
        nameID: profile.nameID,
        email: profile.attributes.mail,
        name: profile.attributes.displayName,
        affiliation: profile.attributes.eduPersonAffiliation,
        attributes: profile.attributes,
      };

      // In a real app, you would save/update this in your database
      return done(null, user);
    }
  )
);

// Serialize user for session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from session
// In a real app, you would fetch from the database
passport.deserializeUser((id, done) => {
  const user = {
    id: id,
    email: 'user@ubc.ca',
    name: 'John Doe',
  };
  done(null, user);
});

// ============================================================================
// ROUTES
// ============================================================================

// Home page
app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`
      <!DOCTYPE html>
      <html>
        <head><title>Authenticated</title></head>
        <body>
          <h1>Welcome, ${req.user.name}!</h1>
          <p>Email: ${req.user.email}</p>
          <p>UBC ID: ${req.user.id}</p>
          <p>Affiliation: ${Array.isArray(req.user.affiliation)
            ? req.user.affiliation.join(', ')
            : req.user.affiliation}</p>
          <p><a href="/profile">View Full Profile</a></p>
          <p><a href="/logout">Logout</a></p>
        </body>
      </html>
    `);
  } else {
    res.send(`
      <!DOCTYPE html>
      <html>
        <head><title>Home</title></head>
        <body>
          <h1>Welcome to the Example App</h1>
          <p>This is a demonstration of @ubcshib/passport-ubcshib</p>
          <p><a href="/auth/ubcshib">Login with UBC Shibboleth</a></p>
        </body>
      </html>
    `);
  }
});

// Initiate SAML authentication - redirects to UBC IdP
app.get('/auth/ubcshib', passport.authenticate('ubcshib'));

// SAML callback - called by IdP after authentication
app.post(
  '/auth/ubcshib/callback',
  passport.authenticate('ubcshib', { failureRedirect: '/login-failed' }),
  (req, res) => {
    // Successful authentication
    console.log('User authenticated:', req.user);
    res.redirect('/');
  }
);

// Protected route - shows user profile
app.get('/profile', ensureAuthenticated(), (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head><title>User Profile</title></head>
      <body>
        <h1>User Profile</h1>
        <h2>Basic Info</h2>
        <ul>
          <li><strong>ID:</strong> ${req.user.id}</li>
          <li><strong>Name:</strong> ${req.user.name}</li>
          <li><strong>Email:</strong> ${req.user.email}</li>
          <li><strong>Affiliation:</strong> ${Array.isArray(req.user.affiliation)
            ? req.user.affiliation.join(', ')
            : req.user.affiliation}</li>
        </ul>

        <h2>All Attributes</h2>
        <pre>${JSON.stringify(req.user.attributes, null, 2)}</pre>

        <p><a href="/">Home</a> | <a href="/logout">Logout</a></p>
      </body>
    </html>
  `);
});

// Login failure page
app.get('/login-failed', (req, res) => {
  res.status(401).send(`
    <!DOCTYPE html>
    <html>
      <head><title>Login Failed</title></head>
      <body>
        <h1>Authentication Failed</h1>
        <p>There was a problem authenticating with UBC Shibboleth.</p>
        <p>Please try again or contact support.</p>
        <p><a href="/">Home</a></p>
      </body>
    </html>
  `);
});

// Logout route
app.get('/logout', logout('/goodbye'));

// Goodbye page
app.get('/goodbye', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head><title>Logged Out</title></head>
      <body>
        <h1>You have been logged out</h1>
        <p><a href="/">Home</a></p>
      </body>
    </html>
  `);
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).send(`
    <!DOCTYPE html>
    <html>
      <head><title>Error</title></head>
      <body>
        <h1>An Error Occurred</h1>
        <p>${process.env.NODE_ENV === 'development' ? err.message : 'Internal Server Error'}</p>
        <p><a href="/">Home</a></p>
      </body>
    </html>
  `);
});

// ============================================================================
// SERVER START
// ============================================================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`
    ============================================================================
    Example app listening on port ${PORT}
    ============================================================================

    Environment: ${process.env.SAML_ENVIRONMENT || 'STAGING'}

    To test:
    1. Visit http://localhost:${PORT}/
    2. Click "Login with UBC Shibboleth"
    3. You'll be redirected to the UBC IdP
    4. After authentication, you'll return to the app

    Configuration:
    - Service Provider ID: ${process.env.SAML_ISSUER}
    - Callback URL: ${process.env.SAML_CALLBACK_URL}

    Make sure your .env file is configured correctly!
    ============================================================================
  `);
});

module.exports = app;
