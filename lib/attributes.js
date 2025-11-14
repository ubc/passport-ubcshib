/**
 * UBC Shibboleth SAML Attribute Mappings
 * Maps OID attribute names to friendly names
 */

const ATTRIBUTE_MAPPINGS = {
  // UBC-specific attributes - support both MACE and OID formats
  // (UBC IdP may return either format)
  'urn:mace:dir:attribute-def:ubcEduCwlPuid': 'ubcEduCwlPuid',  // MACE format
  'urn:oid:1.3.6.1.4.1.60.6.1.6': 'ubcEduCwlPuid',             // OID format
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.1': 'eduPersonAffiliation',

  // Standard eduPerson attributes
  'urn:oid:0.9.2342.19200300.100.1.3': 'mail',
  'urn:oid:2.5.4.4': 'sn',
  'urn:oid:2.5.4.42': 'givenName',
  'urn:oid:2.16.840.1.113730.3.1.241': 'displayName',
};

/**
 * Get friendly attribute name from OID
 * @param {string} oid - The OID attribute name
 * @returns {string} - Friendly name or original OID if not found
 */
function getFriendlyName(oid) {
  return ATTRIBUTE_MAPPINGS[oid] || oid;
}

/**
 * Filter SAML response attributes based on requested attributes
 * Maps OID names to friendly names and returns only requested attributes
 * @param {Object} samlResponse - Raw SAML response object
 * @param {Array<string>} requestedAttributes - Array of friendly attribute names to return
 * @returns {Object} - Filtered and mapped attributes
 */
function mapAttributes(samlResponse, requestedAttributes) {
  if (!samlResponse) {
    return {};
  }

  const mappedUser = {};

  // If no specific attributes requested, return all with friendly names
  if (!requestedAttributes || requestedAttributes.length === 0) {
    Object.entries(samlResponse).forEach(([key, value]) => {
      const friendlyName = getFriendlyName(key);
      mappedUser[friendlyName] = value;
    });
    return mappedUser;
  }

  // Build reverse mapping: friendly name -> OID
  const friendlyToOid = {};
  Object.entries(ATTRIBUTE_MAPPINGS).forEach(([oid, friendly]) => {
    friendlyToOid[friendly] = oid;
  });

  // Map requested friendly names to OIDs and extract values
  requestedAttributes.forEach((friendlyName) => {
    const oid = friendlyToOid[friendlyName];
    if (oid && samlResponse[oid]) {
      mappedUser[friendlyName] = samlResponse[oid];
    } else if (samlResponse[friendlyName]) {
      // Handle case where OID or friendly name might be used directly
      mappedUser[friendlyName] = samlResponse[friendlyName];
    }
  });

  return mappedUser;
}

module.exports = {
  ATTRIBUTE_MAPPINGS,
  getFriendlyName,
  mapAttributes,
};
