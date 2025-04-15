// 🔐 API Key Utilities
const validKeys = new Map([
  ["testkey1234567890testkey1234567890", { owner: "admin", plan: "unlimited" }],
]);

export function isValidApiKey(apiKey) {
  return validKeys.has(apiKey);
}

export function getApiKeyMeta(apiKey) {
  return validKeys.get(apiKey) || null;
}