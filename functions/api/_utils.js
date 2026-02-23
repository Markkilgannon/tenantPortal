import { jwtVerify, createRemoteJWKSet } from "jose";

export function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin": env.CORS_ORIGIN || "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Authorization,Content-Type",
  };
}

export async function verifyAuth0JWT(env, request) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) throw new Error("Missing bearer token");
  const token = auth.slice("Bearer ".length);

  const issuer = `https://${env.AUTH0_DOMAIN}/`;
  const audience = env.AUTH0_AUDIENCE;

  const jwks = createRemoteJWKSet(
    new URL(`https://${env.AUTH0_DOMAIN}/.well-known/jwks.json`)
  );

  const { payload } = await jwtVerify(token, jwks, { issuer, audience });

  if (!payload?.sub) throw new Error("JWT missing sub");
  return payload;
}

let cachedSf = null;

export async function getSalesforceAccessToken(env) {
  const now = Date.now();
  if (cachedSf && now - cachedSf.issued_at_ms < 15 * 60 * 1000) {
    return cachedSf.access_token;
  }

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: env.SF_CLIENT_ID,
    client_secret: env.SF_CLIENT_SECRET,
    refresh_token: env.SF_REFRESH_TOKEN,
  });

  const resp = await fetch(`${env.SF_LOGIN_URL}/services/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!resp.ok) throw new Error(`Salesforce token error: ${resp.status} ${await resp.text()}`);

  const json = await resp.json();
  cachedSf = { access_token: json.access_token, issued_at_ms: now };
  return json.access_token;
}

export async function callSalesforceApex(env, method, path, authSub, bodyObj) {
  const token = await getSalesforceAccessToken(env);
  const url = `${env.SF_INSTANCE_URL}/services/apexrest${path}`;

  const headers = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    "X-Portal-Secret": env.PORTAL_SHARED_SECRET,
    "X-Auth-Sub": authSub,
  };

  const init = { method, headers };
  if (bodyObj && method !== "GET") init.body = JSON.stringify(bodyObj);

  const resp = await fetch(url, init);
  const ct = resp.headers.get("Content-Type") || "";

  if (ct.includes("application/json")) {
    return { status: resp.status, headers: resp.headers, json: await resp.json().catch(() => ({})) };
  } else {
    return { status: resp.status, headers: resp.headers, arrayBuffer: await resp.arrayBuffer() };
  }
}
