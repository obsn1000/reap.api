import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { storeKBAN, generateChecksum, encrypt, logEvent } from '@/lib/kbanUtils';
import { isValidApiKey } from '@/lib/apiKeyUtils';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');
  if (!isValidApiKey(token)) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }

  const {
    country, branch, name, dob, personalCode,
    deviceId, deviceType, enablePush, tags = []
  } = req.body;

  if (!country || !branch || !name || !dob || !personalCode) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';

  const nameHash = crypto.createHash('sha256').update(name + dob).digest('hex').slice(0, 6).toUpperCase();
  const randomPayload = Math.floor(Math.random() * 1e8).toString().padStart(8, '0');
  const rawKBAN = `${country}${branch}${nameHash}${randomPayload}`;
  const checksum = generateChecksum(rawKBAN);
  const fullKBAN = `${rawKBAN}${checksum}`;

  const encryptedKBAN = encrypt(fullKBAN);
  const sessionToken = uuidv4().replace(/-/g, '').slice(0, 32);
  const authCode = uuidv4().replace(/-/g, '').slice(0, 32);
  const riskScore = 1;

  await storeKBAN(fullKBAN, sessionToken, authCode, {
    name,
    dob,
    country,
    personalCode,
    deviceId: deviceId || 'unknown',
    deviceType: deviceType || 'web',
    pushEnabled: enablePush || false,
    ip,
    userAgent,
    riskScore,
    tags
  });

  await logEvent(fullKBAN, 'create', 'success');

  const mobileconfig = `<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0">
    <dict>
      <key>PayloadContent</key>
      <array>
        <dict>
          <key>PayloadType</key>
          <string>com.apple.ManagedConfiguration</string>
          <key>PayloadVersion</key>
          <integer>1</integer>
          <key>PayloadIdentifier</key>
          <string>com.reapware.kbanprofile</string>
          <key>PayloadUUID</key>
          <string>${uuidv4()}</string>
          <key>PayloadDisplayName</key>
          <string>K/BAN Profile</string>
          <key>PayloadOrganization</key>
          <string>Reapware</string>
          <key>PayloadDescription</key>
          <string>Installs a secure K/BAN identity profile on your device.</string>
          <key>PayloadContent</key>
          <dict>
            <key>com.reapware.kban</key>
            <dict>
              <key>EncryptedKBAN</key>
              <string>${encryptedKBAN}</string>
              <key>SessionToken</key>
              <string>${sessionToken}</string>
              <key>AuthCode</key>
              <string>${authCode}</string>
              <key>DeviceID</key>
              <string>${deviceId || 'unknown'}</string>
              <key>DeviceType</key>
              <string>${deviceType || 'web'}</string>
              <key>PushEnabled</key>
              <string>${enablePush ? 'true' : 'false'}</string>
              <key>IP</key>
              <string>${ip}</string>
              <key>UserAgent</key>
              <string>${userAgent}</string>
              <key>RiskScore</key>
              <string>${riskScore}</string>
              <key>Tags</key>
              <array>${tags.map(tag => `<string>${tag}</string>`).join('')}</array>
            </dict>
          </dict>
        </dict>
      </array>
      <key>PayloadType</key>
      <string>Configuration</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>com.reapware.kban.root</string>
      <key>PayloadUUID</key>
      <string>${uuidv4()}</string>
      <key>PayloadDisplayName</key>
      <string>Reapware K/BAN Profile</string>
      <key>PayloadDescription</key>
      <string>This profile installs and secures a unique K/BAN identity to this device.</string>
      <key>PayloadOrganization</key>
      <string>Reapware</string>
    </dict>
  </plist>`;

  return res.status(200).json({
    kban: encryptedKBAN,
    sessionToken,
    authCode,
    mobileconfig,
    qr: `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(encryptedKBAN)}&size=200x200`
  });
}