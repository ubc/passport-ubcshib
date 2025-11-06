# UBC Shibboleth SAML Attributes Reference

This document describes the SAML attributes available from the UBC Shibboleth Identity Provider and how to request them in your application.

## Overview

SAML attributes are identified by OIDs (Object Identifiers), which are technical names like `urn:oid:1.3.6.1.4.1.60.6.1.5`. This library automatically maps these OIDs to friendly names so you don't have to work with the technical identifiers.

## Requesting Attributes

When you configure the strategy, specify which attributes your application needs:

```javascript
new Strategy({
  attributeConfig: [
    'ubcEduCwlPuid',
    'mail',
    'eduPersonAffiliation'
  ]
}, verifyCallback)
```

After authentication, these attributes will be available in the user profile:

```javascript
const profile = {
  attributes: {
    ubcEduCwlPuid: '12345678',
    mail: 'user@ubc.ca',
    eduPersonAffiliation: ['student']
  }
}
```

## Available Attributes

### Currently Configured Attributes

These are the attributes currently configured in `lib/attributes.js` and available for use in your applications.

| Friendly Name | OID | Description | Example |
|---|---|---|---|
| `ubcEduCwlPuid` | `urn:oid:1.3.6.1.4.1.60.6.1.6` | UBC Computing User ID (permanent unique ID) | `12345678` |
| `mail` | `urn:oid:0.9.2342.19200300.100.1.3` | Email address | `user@ubc.ca` |
| `sn` | `urn:oid:2.5.4.4` | Surname / last name | `Smith` |
| `givenName` | `urn:oid:2.5.4.42` | Given name / first name | `John` |
| `displayName` | `urn:oid:2.16.840.1.113730.3.1.241` | Display name | `John Smith` |
| `eduPersonAffiliation` | `urn:oid:1.3.6.1.4.1.5923.1.1.1.1` | Affiliation (student, faculty, staff, member, affiliate) | `student` |

## Recommended Attributes

UBC IAM has authorized these three core attributes for all applications:

```javascript
attributeConfig: [
  'ubcEduCwlPuid',           // Unique identifier for the user
  'mail',                    // Email address
  'eduPersonAffiliation'     // User's role/affiliation
]
```

These are the primary attributes you'll use for authentication and user identification. Additional attributes (like `givenName`, `sn`, `displayName`) are available if your application needs them.

### Examples for Different Use Cases

**Basic Application** (recommended for most apps)
```javascript
attributeConfig: [
  'ubcEduCwlPuid',           // User ID for database key
  'mail',                    // Email for contact
  'eduPersonAffiliation'     // Role/permission checking
]
```

**Application Needing Display Names**
```javascript
attributeConfig: [
  'ubcEduCwlPuid',
  'mail',
  'displayName',             // For user interface display
  'eduPersonAffiliation'
]
```

**Application with Detailed Name Information**
```javascript
attributeConfig: [
  'ubcEduCwlPuid',
  'mail',
  'givenName',               // First name
  'sn',                      // Last name
  'eduPersonAffiliation'
]
```

## Attribute Requirements and Release

### Core Attributes (Already Authorized)

UBC IAM has pre-authorized these three core attributes for all applications:
- `ubcEduCwlPuid` - For user identification
- `mail` - For contact and notifications
- `eduPersonAffiliation` - For role-based access control

You can use these immediately in your `attributeConfig`.

### How to Request Additional Attributes

If your application needs attributes beyond the core three (like `givenName`, `sn`, `displayName`), or other attributes not yet configured in the library:

1. Contact **UBC IAM Team** with your application details
2. Specify which attributes your app needs and why
3. They will authorize release of those attributes to your app
4. Once authorized and you have the OID:
   - Add the mapping to `lib/attributes.js` (see [ADDING_ATTRIBUTES.md](ADDING_ATTRIBUTES.md))
   - Update your `attributeConfig` in your application

### Authorization Process

- **Each application must be explicitly authorized** to receive each attribute
- Attributes are not automatically released to all applications
- UBC follows a privacy-first approach: request only what you need
- The three core attributes (ubcEduCwlPuid, mail, eduPersonAffiliation) are pre-authorized

### Testing Attribute Release

After UBC IAM authorizes attributes for your app:

1. Add them to your `attributeConfig`
2. Deploy to **staging** first
3. Authenticate and verify the attributes are present in the response
4. Check your application logs for the profile data
5. Once verified in staging, request production authorization and deploy

## Attribute Data Types

Most attributes are returned as strings, but some may be arrays:

```javascript
// String attribute
mail: 'user@ubc.ca'

// Array of values
eduPersonAffiliation: ['student', 'member']

// Single value (array with one element)
displayName: 'John Smith'
```

If an attribute is not authorized or not released by the IdP, it will simply be absent from the profile. Always check for attribute existence:

```javascript
if (profile.attributes && profile.attributes.mail) {
  // Use mail
}
```

## Attribute Name Format

This library supports two ways of referring to attributes:

1. **Friendly Names** (recommended): `ubcEduCwlPuid`, `mail`, etc.
   - Human-readable
   - Consistent across environments
   - Use in `attributeConfig`

2. **OID Names** (technical): `urn:oid:1.3.6.1.4.1.60.6.1.5`
   - SAML standard format
   - What the IdP uses internally
   - What you see in raw SAML responses

The library automatically converts between these formats.

## Privacy and Data Protection

### Principle: Minimum Necessary Access

Request only the attributes your application genuinely needs:

- ✓ Request `mail` if you need to contact the user
- ✗ Don't request all attributes "just in case"
- ✓ Request `eduPersonAffiliation` if you need to determine user role
- ✗ Don't request attributes for features you might add later

### Data Handling Best Practices

1. **Don't log SAML attributes** in plain text
2. **Hash or encrypt** sensitive attributes at rest
3. **Use HTTPS** for all SAML communication (configured by default)
4. **Validate input** from all SAML attributes
5. **Don't share** raw attribute data with third parties

## Troubleshooting

### Attribute Not in Profile

If you've requested an attribute but it's not in the profile:

1. **Verify the attribute was authorized**
   - Contact UBC IAM to confirm
   - Check your application settings in their system

2. **Verify the attribute name is correct**
   - Check this document for the exact friendly name
   - Spelling matters (case-sensitive)

3. **Test with a known user**
   - Some attributes might only be set for certain users
   - Try with a faculty member if requesting faculty-specific attributes

4. **Check application logs**
   ```javascript
   console.log('Full profile:', JSON.stringify(profile, null, 2));
   ```

### OID vs Friendly Name Errors

If you receive an error mentioning OIDs:

- Don't use OID names in `attributeConfig` - use friendly names
- If the IdP returns an unknown OID, it might be a custom attribute
- Contact UBC IAM for details on custom attributes

## Advanced: Custom Attributes

If your application needs custom attributes beyond the standard set:

1. Work with UBC IAM to define the custom attribute
2. Get the OID for the custom attribute
3. Add it to the mappings in `lib/attributes.js`
4. Use it in your `attributeConfig`

Contact the UBC IAM team for guidance on this process.

## References

- **eduPerson Schema**: https://www.internet2.edu/products-services/eduperson-rdsprov-service/
- **SAML Attributes**: https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSpAttributeIds
- **OASIS SAML 2.0**: http://docs.oasis-open.org/security/saml/v2.0/

## Contact

For questions about attributes, authorization, or the SAML setup:

- **UBC IAM Team**: [contact information from your documentation]
- **Application Support**: [your internal support contact]
