import { SignJWT, importPKCS8 } from "jose";

function normalizePrivateKey(pem) {
  // Cloudflare env vars sometimes store \n literally
  return pem.includes("\\n") ? pem.replace(/\\n/g, "\n") : pem;
}

export async function getSalesforceAccessToken(env) {
  const loginUrl = env.SF_LOGIN_URL;
  const clientId = env.SF_CLIENT_ID;
  const username = env.SF_USERNAME;
  const privateKeyPem = normalizePrivateKey(env.SF_JWT_PRIVATE_KEY);

  if (!loginUrl || !clientId || !username || !privateKeyPem) {
    throw new Error("Missing Salesforce env vars (SF_LOGIN_URL, SF_CLIENT_ID, SF_USERNAME, SF_JWT_PRIVATE_KEY).");
  }

  // JWT Bearer assertion
  const now = Math.floor(Date.now() / 1000);
  const pk = await importPKCS8(privateKeyPem, "RS256");

  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(clientId)     // iss = Connected App Consumer Key
    .setSubject(username)    // sub = SF integration username
    .setAudience(loginUrl)   // aud = login URL
    .setIssuedAt(now)
    .setExpirationTime(now + 180) // 3 minutes is plenty
    .sign(pk);

  const tokenUrl = `${loginUrl}/services/oauth2/token`;
  const body = new URLSearchParams();
  body.set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
  body.set("assertion", assertion);

  const resp = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(`Salesforce token error (${resp.status}): ${JSON.stringify(json)}`);
  }

  // json: { access_token, instance_url, token_type, ... }
  return json;
}
