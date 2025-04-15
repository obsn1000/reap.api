// 🔐 K/BAN Utility Functions
import crypto from 'crypto';

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32);
const IV_LENGTH = 16;
const kbanDB = {};
const eventLog = [];

export function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

export function decrypt(encryptedText) {
  const [ivHex, dataHex] = encryptedText.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const encrypted = Buffer.from(dataHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString();
}

export function generateChecksum(str) {
  let sum = 0;
  for (let i = 0; i < str.length; i++) {
    const num = str.charCodeAt(i) % 10;
    sum += i % 2 === 0 ? num * 2 : num;
  }
  return (10 - (sum % 10)) % 10;
}

export function validateChecksum(base, checksum) {
  return generateChecksum(base).toString() === checksum;
}

export async function storeKBAN(kban, sessionToken, authCode, meta) {
  kbanDB[kban] = { sessionToken, authCode, meta };
}

export async function verifySessionToken(kban, token) {
  return kbanDB[kban]?.sessionToken === token;
}

export async function verifyAuthCode(kban, code) {
  return kbanDB[kban]?.authCode === code;
}

export async function logEvent(kban, action, status) {
  eventLog.push({
    timestamp: new Date().toISOString(),
    kban,
    action,
    status
  });
}