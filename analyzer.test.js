'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeURL } = require('../src/analyzer');

test('flags a homoglyph brand spoof as high risk', () => {
  const result = analyzeURL('https://paypa1.com/login/secure-account');
  assert.equal(result.level, 'danger');
  assert.ok(result.score >= 60);
  const homoglyph = result.flags.find(f => f.id === 'homoglyph');
  assert.equal(homoglyph.triggered, true);
});

test('flags a brand-prefixed lookalike domain for brand spoofing', () => {
  const result = analyzeURL('https://amazon-order-security.info/verify?id=8823');
  const brandFlag = result.flags.find(f => f.id === 'brand');
  assert.equal(brandFlag.triggered, true);
  assert.ok(result.score > 0);
});

test('does not flag the real brand domain itself', () => {
  const result = analyzeURL('https://www.amazon.com/gp/orders');
  const brandFlag = result.flags.find(f => f.id === 'brand');
  assert.equal(brandFlag.triggered, false);
});

test('scores a known-good domain as safe', () => {
  const result = analyzeURL('https://github.com/anthropics/claude');
  assert.equal(result.level, 'safe');
});

test('flags bare IP hosts', () => {
  const result = analyzeURL('http://192.168.1.10/login');
  const ipFlag = result.flags.find(f => f.id === 'ip');
  assert.equal(ipFlag.triggered, true);
});

test('throws a clear error on unparsable input', () => {
  assert.throws(() => analyzeURL('http://'));
});

test('normalizes bare domains without a protocol', () => {
  const result = analyzeURL('g00gle.ru/signin');
  assert.equal(result.normalizedUrl.startsWith('https://'), true);
});
