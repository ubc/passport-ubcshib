'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  mapAttributes,
  getFriendlyName,
  ATTRIBUTE_MAPPINGS,
} = require('../lib/attributes');

test('getFriendlyName resolves OID and MACE names, passes unknowns through', () => {
  assert.equal(getFriendlyName('urn:oid:1.3.6.1.4.1.60.6.1.6'), 'ubcEduCwlPuid');
  assert.equal(
    getFriendlyName('urn:mace:dir:attribute-def:ubcEduCwlPuid'),
    'ubcEduCwlPuid'
  );
  assert.equal(getFriendlyName('urn:oid:9.9.9'), 'urn:oid:9.9.9');
});

test('empty requested list returns all keys mapped to friendly names', () => {
  const profile = {
    'urn:oid:1.3.6.1.4.1.60.6.1.6': '12345678',
    'urn:oid:0.9.2342.19200300.100.1.3': 'a@ubc.ca',
    nameID: 'nid',
  };
  const out = mapAttributes(profile, []);
  assert.equal(out.ubcEduCwlPuid, '12345678');
  assert.equal(out.mail, 'a@ubc.ca');
  assert.equal(out.nameID, 'nid');
});

test('bug #1: a MACE-named PUID resolves (reverse-map collision fixed)', () => {
  const profile = { 'urn:mace:dir:attribute-def:ubcEduCwlPuid': '87654321' };
  const out = mapAttributes(profile, ['ubcEduCwlPuid']);
  assert.equal(out.ubcEduCwlPuid, '87654321');
});

test('an OID-named PUID still resolves', () => {
  const profile = { 'urn:oid:1.3.6.1.4.1.60.6.1.6': '12345678' };
  const out = mapAttributes(profile, ['ubcEduCwlPuid']);
  assert.equal(out.ubcEduCwlPuid, '12345678');
});

test('bug #2: uid and eduPersonPrincipalName resolve under their OIDs', () => {
  const profile = {
    'urn:oid:0.9.2342.19200300.100.1.1': 'tperson',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'tperson@ubc.ca',
  };
  const out = mapAttributes(profile, ['uid', 'eduPersonPrincipalName']);
  assert.equal(out.uid, 'tperson');
  assert.equal(out.eduPersonPrincipalName, 'tperson@ubc.ca');
});

test('friendly-named attributes still resolve (docker-simple-saml path)', () => {
  const profile = { ubcEduCwlPuid: '11', mail: 'x@ubc.ca', cwlLoginName: 'xlogin' };
  const out = mapAttributes(profile, ['ubcEduCwlPuid', 'mail', 'cwlLoginName']);
  assert.equal(out.ubcEduCwlPuid, '11');
  assert.equal(out.mail, 'x@ubc.ca');
  // A name not in the table falls back to the friendly key itself.
  assert.equal(out.cwlLoginName, 'xlogin');
});

test('unrequested attributes are not returned', () => {
  const profile = {
    'urn:oid:1.3.6.1.4.1.60.6.1.6': '1',
    'urn:oid:0.9.2342.19200300.100.1.3': 'x@ubc.ca',
  };
  const out = mapAttributes(profile, ['ubcEduCwlPuid']);
  assert.deepEqual(Object.keys(out), ['ubcEduCwlPuid']);
});

test('null / undefined profile is handled', () => {
  assert.deepEqual(mapAttributes(null, ['mail']), {});
  assert.deepEqual(mapAttributes(undefined, []), {});
});

test('OID and MACE entries coexist for ubcEduCwlPuid in the table', () => {
  assert.equal(
    ATTRIBUTE_MAPPINGS['urn:oid:1.3.6.1.4.1.60.6.1.6'],
    'ubcEduCwlPuid'
  );
  assert.equal(
    ATTRIBUTE_MAPPINGS['urn:mace:dir:attribute-def:ubcEduCwlPuid'],
    'ubcEduCwlPuid'
  );
});
