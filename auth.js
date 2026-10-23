const { generateSecret, generateSync, verifySync, generateURI } = require('otplib');

const DEMO_MFA_SECRETS = {
  'analyst@company.test': 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
  'admin@company.test': 'K5Q7D3JWKW4XQ7K2K5Q7D3JWKW4XQ7K2'
};

function generateTotpSecret() {
  return generateSecret();
}

function getDemoMfaSecret(email) {
  return DEMO_MFA_SECRETS[email] || generateTotpSecret();
}

function verifyTotp(secret, token) {
  if (!secret || !token) {
    return false;
  }

  return verifySync({ secret, token });
}

function getOtpAuthUrl(email, secret, issuer = 'Secure Auth Lab') {
  return generateURI({ issuer, label: email, secret });
}

module.exports = {
  generateTotpSecret,
  getDemoMfaSecret,
  verifyTotp,
  getOtpAuthUrl
};
