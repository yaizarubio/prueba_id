const { generateSecret, generateSync, verifySync, generateURI } = require('otplib');

function generateTotpSecret() {
  return generateSecret();
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
  verifyTotp,
  getOtpAuthUrl
};
