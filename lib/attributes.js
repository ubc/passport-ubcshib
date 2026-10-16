/**
 * UBC Shibboleth SAML Attribute Mappings
 * Maps OID / MACE attribute names to friendly names.
 *
 * Real UBC Shibboleth releases attributes under their OID (`urn:oid:...`)
 * names. Some IdPs (and the local `docker-simple-saml` test IdP) release the
 * same attributes under friendly names or MACE (`urn:mace:...`) names instead,
 * so each friendly name may have more than one source name. The mapping below
 * is therefore MANY source names -> ONE friendly name, and the lookup
 * (`mapAttributes`) walks every source name a friendly name can arrive under.
 */

const ATTRIBUTE_MAPPINGS = {
  // UBC-specific attributes - support both MACE and OID formats
  // (UBC IdP may return either format)
  'urn:mace:dir:attribute-def:ubcEduCwlPuid': 'ubcEduCwlPuid', // MACE format
  'urn:oid:1.3.6.1.4.1.60.6.1.6': 'ubcEduCwlPuid', // OID format
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.1': 'eduPersonAffiliation',

  // Standard eduPerson / LDAP attributes
  'urn:oid:0.9.2342.19200300.100.1.3': 'mail',
  'urn:oid:2.5.4.4': 'sn',
  'urn:oid:2.5.4.42': 'givenName',
  'urn:oid:2.16.840.1.113730.3.1.241': 'displayName',

  // OID entries added in 0.1.7 so these friendly names resolve when UBC
  // sends OID names. Before this, uid and eduPersonPrincipalName had no OID
  // entry and only resolved when the IdP happened to send the friendly name.
  // MACE entries are kept alongside OID entries; mapAttributes checks every
  // source name, so neither overwrites the other any more.
  'urn:oid:0.9.2342.19200300.100.1.1': 'uid', // uid
  'urn:mace:dir:attribute-def:uid': 'uid',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'eduPersonPrincipalName', // eppn
  'urn:mace:dir:attribute-def:eduPersonPrincipalName': 'eduPersonPrincipalName',
  'urn:mace:dir:attribute-def:eduPersonAffiliation': 'eduPersonAffiliation',
  'urn:mace:dir:attribute-def:mail': 'mail',
  'urn:mace:dir:attribute-def:sn': 'sn',
  'urn:mace:dir:attribute-def:givenName': 'givenName',
  'urn:mace:dir:attribute-def:displayName': 'displayName',
};

/**
 * Build friendly name -> [every source name that maps to it].
 * This is the collision-free inverse of ATTRIBUTE_MAPPINGS. The friendly name
 * itself is always included last as a fallback so an IdP that sends friendly
 * names directly still resolves.
 * @returns {Object<string, string[]>}
 */
function buildFriendlyToSources() {
  const friendlyToSources = {};
  Object.entries(ATTRIBUTE_MAPPINGS).forEach(([source, friendly]) => {
    if (!friendlyToSources[friendly]) {
      friendlyToSources[friendly] = [];
    }
    friendlyToSources[friendly].push(source);
  });
  // Ensure the friendly name itself is a candidate source, as a fallback.
  Object.keys(friendlyToSources).forEach((friendly) => {
    if (!friendlyToSources[friendly].includes(friendly)) {
      friendlyToSources[friendly].push(friendly);
    }
  });
  return friendlyToSources;
}

/**
 * Get friendly attribute name from an OID / MACE name
 * @param {string} oid - The OID (or MACE) attribute name
 * @returns {string} - Friendly name or original name if not found
 */
function getFriendlyName(oid) {
  return ATTRIBUTE_MAPPINGS[oid] || oid;
}

/**
 * Filter SAML response attributes based on requested attributes.
 * Maps OID/MACE names to friendly names and returns only requested attributes.
 * @param {Object} samlResponse - Raw SAML profile object (keys are OID/MACE/friendly names)
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

  // For each requested friendly name, try every source name it can arrive
  // under (OID, MACE, and the friendly name itself), taking the first present.
  const friendlyToSources = buildFriendlyToSources();

  requestedAttributes.forEach((friendlyName) => {
    const sources = friendlyToSources[friendlyName] || [friendlyName];
    for (const source of sources) {
      // Guard against inherited keys; only accept the attribute's own values.
      if (
        Object.prototype.hasOwnProperty.call(samlResponse, source) &&
        samlResponse[source] !== undefined &&
        samlResponse[source] !== null
      ) {
        mappedUser[friendlyName] = samlResponse[source];
        break;
      }
    }
  });

  return mappedUser;
}

module.exports = {
  ATTRIBUTE_MAPPINGS,
  getFriendlyName,
  mapAttributes,
};
