const test = require('node:test');
const assert = require('node:assert/strict');
const { generateSync } = require('otplib');
const { generateTotpSecret, verifyTotp, getOtpAuthUrl, getDemoMfaSecret } = require('../auth');

test('generateTotpSecret creates a usable base32 secret', () => {
  const secret = generateTotpSecret();

  assert.ok(secret);
  assert.match(secret, /^[A-Z2-7]+=*$/i);
});

test('verifyTotp accepts a valid generated code', () => {
  const secret = generateTotpSecret();
  const code = generateSync({ secret });

  assert.equal(verifyTotp(secret, code).valid, true);
});

test('getOtpAuthUrl includes the issuer and user identity', () => {
  const secret = generateTotpSecret();
  const url = getOtpAuthUrl('analyst@company.test', secret, 'Secure Auth Lab');

  assert.match(url, /^otpauth:\/\/totp\//);
  assert.match(url, /analyst%40company\.test/);
  assert.match(url, /Secure%20Auth%20Lab/);
});

test('demo accounts use stable MFA secrets', () => {
  const analystSecret = getDemoMfaSecret('analyst@company.test');
  const adminSecret = getDemoMfaSecret('admin@company.test');
  const analystCode = generateSync({ secret: analystSecret });
  const adminCode = generateSync({ secret: adminSecret });

  assert.ok(analystSecret);
  assert.ok(adminSecret);
  assert.equal(verifyTotp(analystSecret, analystCode).valid, true);
  assert.equal(verifyTotp(adminSecret, adminCode).valid, true);
});
