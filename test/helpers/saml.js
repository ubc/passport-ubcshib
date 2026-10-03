/**
 * Test-only SAML fixture builder.
 *
 * Generates a throwaway IdP key/cert pair (via openssl) and builds SAML
 * Responses in every shape the differential harness needs: Response-signed,
 * Assertion-signed, both, unsigned, tampered, wrong-key, and two
 * signature-wrapping variants. Attributes can be emitted under friendly, OID
 * or MACE names. Also builds an IdP-initiated LogoutRequest in both bindings
 * (signed) and decodes the LogoutResponse an SP answers it with.
 *
 * No key material is committed; everything is generated into a temp dir at
 * runtime. This file is excluded from the npm package (see .npmignore).
 */

const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { SignedXml } = require('xml-crypto');

const SIG_ALG = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const DIGEST_ALG = 'http://www.w3.org/2001/04/xmlenc#sha256';
const C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

/**
 * Generate an RSA key + self-signed cert with openssl.
 * @param {string} dir
 * @param {string} name
 * @returns {{key: string, cert: string, certBase64: string}}
 */
function makeKeyPair(dir, name) {
  const keyPath = path.join(dir, `${name}-key.pem`);
  const certPath = path.join(dir, `${name}-cert.pem`);
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048',
    '-keyout', keyPath, '-out', certPath,
    '-days', '3650', '-nodes', '-subj', `/CN=${name}`,
  ], { stdio: 'ignore' });
  const cert = fs.readFileSync(certPath, 'utf8');
  const certBase64 = cert
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s+/g, '');
  return { key: fs.readFileSync(keyPath, 'utf8'), cert, certBase64 };
}

/**
 * Create the two key pairs the harness needs (the real IdP key, and a wrong
 * key used for the forgery cases). openssl must be on PATH.
 * @returns {{dir: string, idp: object, wrong: object}}
 */
function setupKeys() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ubcshib-test-'));
  return {
    dir,
    idp: makeKeyPair(dir, 'idp'),
    wrong: makeKeyPair(dir, 'wrong'),
  };
}

// Attribute name tables for the three naming styles.
const OID = {
  ubcEduCwlPuid: 'urn:oid:1.3.6.1.4.1.60.6.1.6',
  mail: 'urn:oid:0.9.2342.19200300.100.1.3',
  eduPersonAffiliation: 'urn:oid:1.3.6.1.4.1.5923.1.1.1.1',
  givenName: 'urn:oid:2.5.4.42',
  sn: 'urn:oid:2.5.4.4',
  displayName: 'urn:oid:2.16.840.1.113730.3.1.241',
  uid: 'urn:oid:0.9.2342.19200300.100.1.1',
  eduPersonPrincipalName: 'urn:oid:1.3.6.1.4.1.5923.1.1.1.6',
};
const MACE = {
  ubcEduCwlPuid: 'urn:mace:dir:attribute-def:ubcEduCwlPuid',
  mail: 'urn:mace:dir:attribute-def:mail',
  eduPersonAffiliation: 'urn:mace:dir:attribute-def:eduPersonAffiliation',
  uid: 'urn:mace:dir:attribute-def:uid',
  eduPersonPrincipalName: 'urn:mace:dir:attribute-def:eduPersonPrincipalName',
};

/**
 * Resolve an attribute's SAML Name for the requested naming style.
 * @param {string} friendly
 * @param {'friendly'|'oid'|'mace'} style
 */
function attrName(friendly, style) {
  if (style === 'oid') return OID[friendly] || friendly;
  if (style === 'mace') return MACE[friendly] || friendly;
  return friendly;
}

const NOW = Date.now();
const iso = (ms) => new Date(ms).toISOString();

/**
 * Build an unsigned SAML Response XML string.
 * @param {object} opts
 * @param {object} opts.attributes - friendly name -> value
 * @param {'friendly'|'oid'|'mace'} [opts.style='oid']
 * @param {string} [opts.nameID]
 * @param {string} [opts.issuer]
 * @param {string} [opts.audience]
 * @param {string} [opts.responseId]
 * @param {string} [opts.assertionId]
 */
function buildUnsignedResponse(opts) {
  const {
    attributes = {},
    style = 'oid',
    nameID = 'test-nameid',
    issuer = 'http://test-idp',
    audience = 'http://test-sp',
    responseId = '_resp1',
    assertionId = '_assert1',
  } = opts || {};

  const attrXml = Object.entries(attributes)
    .map(([friendly, value]) => {
      const name = attrName(friendly, style);
      const values = (Array.isArray(value) ? value : [value])
        .map((v) => `<saml:AttributeValue>${v}</saml:AttributeValue>`)
        .join('');
      return `<saml:Attribute Name="${name}">${values}</saml:Attribute>`;
    })
    .join('');

  const notBefore = iso(NOW - 60000);
  const notOnOrAfter = iso(NOW + 600000);

  const assertion =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
    `ID="${assertionId}" Version="2.0" IssueInstant="${iso(NOW)}">` +
    `<saml:Issuer>${issuer}</saml:Issuer>` +
    `<saml:Subject>` +
    `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">${nameID}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}"/>` +
    `</saml:SubjectConfirmation>` +
    `</saml:Subject>` +
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">` +
    `<saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction>` +
    `</saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${iso(NOW)}" SessionIndex="_session1">` +
    `<saml:AuthnContext><saml:AuthnContextClassRef>` +
    `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport` +
    `</saml:AuthnContextClassRef></saml:AuthnContext>` +
    `</saml:AuthnStatement>` +
    `<saml:AttributeStatement>${attrXml}</saml:AttributeStatement>` +
    `</saml:Assertion>`;

  const response =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
    `ID="${responseId}" Version="2.0" IssueInstant="${iso(NOW)}" ` +
    `Destination="http://test-sp/acs">` +
    `<saml:Issuer>${issuer}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    assertion +
    `</samlp:Response>`;

  return response;
}

/**
 * Sign one element (by local-name) of an XML string, enveloped.
 * @param {string} xml
 * @param {string} key - PEM private key
 * @param {string} localName - 'Response' or 'Assertion'
 * @returns {string} signed XML
 */
function signElement(xml, key, localName) {
  const sig = new SignedXml();
  sig.privateKey = key;
  sig.publicCert = undefined;
  sig.signatureAlgorithm = SIG_ALG;
  sig.canonicalizationAlgorithm = C14N;
  sig.addReference({
    xpath: `//*[local-name(.)='${localName}']`,
    transforms: [ENVELOPED, C14N],
    digestAlgorithm: DIGEST_ALG,
  });
  // Place the signature as the first child after the element's Issuer, which
  // is where SAML expects it and where node-saml/passport-saml look.
  sig.computeSignature(xml, {
    location: {
      reference: `//*[local-name(.)='${localName}']/*[local-name(.)='Issuer']`,
      action: 'after',
    },
  });
  return sig.getSignedXml();
}

const b64 = (xml) => Buffer.from(xml, 'utf8').toString('base64');

/**
 * Build the full set of test cases. Returns { legit: [...], attacks: [...] }
 * where each case is { name, samlResponse (base64), expectAccept, attributes,
 * style, description }.
 * @param {object} keys - from setupKeys()
 */
function buildCases(keys) {
  const baseAttrs = {
    ubcEduCwlPuid: '12345678',
    mail: 'person@ubc.ca',
    eduPersonAffiliation: 'faculty',
    givenName: 'Test',
    sn: 'Person',
  };

  const legit = [];
  const attacks = [];

  // ---- Legitimate, correctly signed cases (should be accepted) ----

  // 1. Response-signed only, OID names
  {
    const unsigned = buildUnsignedResponse({ attributes: baseAttrs, style: 'oid' });
    legit.push({
      name: 'response-signed (OID names)',
      samlResponse: b64(signElement(unsigned, keys.idp.key, 'Response')),
      expectAccept: true,
      attributes: baseAttrs,
      style: 'oid',
    });
  }

  // 2. Assertion-signed only, OID names
  {
    const unsigned = buildUnsignedResponse({ attributes: baseAttrs, style: 'oid' });
    legit.push({
      name: 'assertion-signed (OID names)',
      samlResponse: b64(signElement(unsigned, keys.idp.key, 'Assertion')),
      expectAccept: true,
      attributes: baseAttrs,
      style: 'oid',
    });
  }

  // 3. Both signed (Assertion first, then Response), friendly names
  {
    const unsigned = buildUnsignedResponse({ attributes: baseAttrs, style: 'friendly' });
    const assertionSigned = signElement(unsigned, keys.idp.key, 'Assertion');
    const bothSigned = signElement(assertionSigned, keys.idp.key, 'Response');
    legit.push({
      name: 'both-signed (friendly names)',
      samlResponse: b64(bothSigned),
      expectAccept: true,
      attributes: baseAttrs,
      style: 'friendly',
    });
  }

  // 4. Assertion-signed, MACE-named PUID (library bug #1 territory)
  {
    const attrs = { ubcEduCwlPuid: '87654321', mail: 'mace@ubc.ca', eduPersonAffiliation: 'student' };
    const unsigned = buildUnsignedResponse({ attributes: attrs, style: 'mace' });
    legit.push({
      name: 'assertion-signed (MACE-named PUID)',
      samlResponse: b64(signElement(unsigned, keys.idp.key, 'Assertion')),
      expectAccept: true,
      attributes: attrs,
      style: 'mace',
    });
  }

  // 5. Assertion-signed, includes uid + eduPersonPrincipalName under OID (bug #2)
  {
    const attrs = {
      ubcEduCwlPuid: '11223344',
      uid: 'tperson',
      eduPersonPrincipalName: 'tperson@ubc.ca',
      mail: 'eppn@ubc.ca',
    };
    const unsigned = buildUnsignedResponse({ attributes: attrs, style: 'oid' });
    legit.push({
      name: 'assertion-signed (uid + eppn under OID)',
      samlResponse: b64(signElement(unsigned, keys.idp.key, 'Assertion')),
      expectAccept: true,
      attributes: attrs,
      style: 'oid',
    });
  }

  // ---- Attacks (should all be rejected) ----

  // A. Unsigned
  {
    const unsigned = buildUnsignedResponse({ attributes: baseAttrs, style: 'oid' });
    attacks.push({
      name: 'unsigned',
      samlResponse: b64(unsigned),
      expectAccept: false,
    });
  }

  // B. Tampered after signing: change an attribute value post-signature
  {
    const unsigned = buildUnsignedResponse({ attributes: baseAttrs, style: 'oid' });
    let signed = signElement(unsigned, keys.idp.key, 'Assertion');
    signed = signed.replace('>12345678<', '>99999999<');
    attacks.push({
      name: 'tampered-after-signing',
      samlResponse: b64(signed),
      expectAccept: false,
    });
  }

  // C. Signed by the wrong key
  {
    const unsigned = buildUnsignedResponse({ attributes: baseAttrs, style: 'oid' });
    attacks.push({
      name: 'wrong-key signed',
      samlResponse: b64(signElement(unsigned, keys.wrong.key, 'Assertion')),
      expectAccept: false,
    });
  }

  // D. Signature wrapping (XSW): keep the signed assertion, inject a forged
  //    second assertion with elevated attributes as a sibling.
  {
    const unsigned = buildUnsignedResponse({
      attributes: baseAttrs,
      style: 'oid',
      assertionId: '_assertLegit',
    });
    const signed = signElement(unsigned, keys.idp.key, 'Assertion');
    const forged = buildUnsignedResponse({
      attributes: { ubcEduCwlPuid: '00000001', eduPersonAffiliation: 'admin', mail: 'attacker@evil.test' },
      style: 'oid',
      nameID: 'attacker',
      assertionId: '_assertForged',
    });
    // Extract just the forged <saml:Assertion> element and splice it in after
    // the signed one, inside the Response.
    const m = forged.match(/<saml:Assertion[\s\S]*<\/saml:Assertion>/);
    const forgedAssertion = m ? m[0] : '';
    const wrapped = signed.replace('</samlp:Response>', `${forgedAssertion}</samlp:Response>`);
    attacks.push({
      name: 'xsw: two assertions (signed + forged sibling)',
      samlResponse: b64(wrapped),
      expectAccept: false,
    });
  }

  // E. Signature wrapping (XSW): forged outer assertion carries the real signed
  //    assertion nested inside an Extensions element, so a naive parser reads
  //    the forged attributes while the signature still verifies over the inner.
  {
    const unsigned = buildUnsignedResponse({
      attributes: baseAttrs,
      style: 'oid',
      assertionId: '_assertInner',
    });
    const signedInner = signElement(unsigned, keys.idp.key, 'Assertion');
    const innerAssertionMatch = signedInner.match(/<saml:Assertion[\s\S]*<\/saml:Assertion>/);
    const innerAssertion = innerAssertionMatch ? innerAssertionMatch[0] : '';
    const forgedOuter =
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
      `ID="_assertOuter" Version="2.0" IssueInstant="${iso(NOW)}">` +
      `<saml:Issuer>http://test-idp</saml:Issuer>` +
      `<saml:Subject><saml:NameID>attacker</saml:NameID></saml:Subject>` +
      `<saml:Extensions>${innerAssertion}</saml:Extensions>` +
      `<saml:AttributeStatement>` +
      `<saml:Attribute Name="${OID.ubcEduCwlPuid}"><saml:AttributeValue>00000002</saml:AttributeValue></saml:Attribute>` +
      `<saml:Attribute Name="${OID.eduPersonAffiliation}"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>` +
      `</saml:AttributeStatement>` +
      `</saml:Assertion>`;
    const base = buildUnsignedResponse({ attributes: {}, style: 'oid', assertionId: '_unused' })
      .replace(/<saml:Assertion[\s\S]*<\/saml:Assertion>/, forgedOuter);
    attacks.push({
      name: 'xsw: signed assertion nested in forged outer',
      samlResponse: b64(base),
      expectAccept: false,
    });
  }

  // F. Comment-injection in the signed NameID (the GHSA-4mxg-3p6v-xgq3 class):
  //    value signed as 12345678, a comment splits it so a naive text read may
  //    truncate. A correct implementation reads the verified value.
  {
    const unsigned = buildUnsignedResponse({
      attributes: baseAttrs,
      style: 'oid',
      nameID: '12345678',
    });
    let signed = signElement(unsigned, keys.idp.key, 'Assertion');
    signed = signed.replace('>12345678<', '>1234<!---->5678<');
    attacks.push({
      name: 'comment-injection in signed NameID',
      samlResponse: b64(signed),
      // Must NOT yield a modified identity. We assert on the resolved nameID
      // rather than pure accept/reject (see the runner).
      expectAccept: 'nameid-intact',
      expectedNameID: '12345678',
    });
  }

  return { legit, attacks };
}

// ---- Single logout (an IdP-initiated LogoutRequest, and the SP's answer) ----

/**
 * Build an unsigned IdP-initiated SAML LogoutRequest XML string.
 * @param {object} [opts]
 * @param {string} [opts.id]
 * @param {string} [opts.issuer]
 * @param {string} [opts.nameID]
 * @param {string} [opts.sessionIndex]
 */
function buildLogoutRequest(opts) {
  const {
    id = '_logoutreq1',
    issuer = 'http://test-idp',
    nameID = 'test-nameid',
    sessionIndex = '_session1',
  } = opts || {};
  return (
    `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
    `ID="${id}" Version="2.0" IssueInstant="${iso(Date.now())}" ` +
    `Destination="http://test-sp/slo">` +
    `<saml:Issuer>${issuer}</saml:Issuer>` +
    `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">${nameID}</saml:NameID>` +
    `<samlp:SessionIndex>${sessionIndex}</samlp:SessionIndex>` +
    `</samlp:LogoutRequest>`
  );
}

/**
 * Encode a LogoutRequest for the HTTP-Redirect binding, signed the way that
 * binding signs: deflate + base64 the XML, then sign the query string
 * `SAMLRequest=…&RelayState=…&SigAlg=…` (SAML Bindings §3.4.4.1).
 * @param {string} xml
 * @param {string} key - PEM private key
 * @param {string} [relayState]
 * @returns {{query: object, url: string}} req.query (decoded) and req.url (raw)
 */
function redirectLogoutRequest(xml, key, relayState) {
  const encoded = zlib.deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64');
  let qs = `SAMLRequest=${encodeURIComponent(encoded)}`;
  if (relayState) qs += `&RelayState=${encodeURIComponent(relayState)}`;
  qs += `&SigAlg=${encodeURIComponent(SIG_ALG)}`;
  const signature = crypto.createSign('RSA-SHA256').update(qs).sign(key, 'base64');
  qs += `&Signature=${encodeURIComponent(signature)}`;
  return { query: Object.fromEntries(new URLSearchParams(qs)), url: `/slo?${qs}` };
}

/**
 * Encode a LogoutRequest for the HTTP-POST binding: an enveloped XML signature
 * on the LogoutRequest element, base64 in the form body.
 * @param {string} xml
 * @param {string} key - PEM private key
 * @returns {{SAMLRequest: string}} req.body
 */
function postLogoutRequest(xml, key) {
  return { SAMLRequest: b64(signElement(xml, key, 'LogoutRequest')) };
}

/**
 * Decode the LogoutResponse an SP redirects the browser back to the IdP with.
 * @param {string} redirectUrl - the URL passed to strategy.redirect()
 * @returns {{xml: string, statusCodes: string[], inResponseTo: string|undefined}}
 *   statusCodes lists every StatusCode Value in document order: the top-level
 *   code first, then any nested second-level code.
 */
function decodeLogoutResponse(redirectUrl) {
  const encoded = new URL(redirectUrl).searchParams.get('SAMLResponse');
  if (!encoded) throw new Error(`no SAMLResponse in ${redirectUrl}`);
  const xml = zlib.inflateRawSync(Buffer.from(encoded, 'base64')).toString('utf8');
  if (!/<(\w+:)?LogoutResponse[\s>]/.test(xml)) throw new Error(`not a LogoutResponse: ${xml}`);
  const statusCodes = [...xml.matchAll(/<(?:\w+:)?StatusCode[^>]*\sValue="([^"]+)"/g)].map((m) => m[1]);
  const inResponseTo = (xml.match(/\sInResponseTo="([^"]+)"/) || [])[1];
  return { xml, statusCodes, inResponseTo };
}

module.exports = {
  setupKeys,
  buildUnsignedResponse,
  signElement,
  buildCases,
  attrName,
  OID,
  MACE,
  b64,
  buildLogoutRequest,
  redirectLogoutRequest,
  postLogoutRequest,
  decodeLogoutResponse,
};
