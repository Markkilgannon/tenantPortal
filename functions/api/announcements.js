import { jwtVerify, createRemoteJWKSet } from "jose";
import { getSalesforceAccessToken } from "./_sf.js";

function getAuth0TokenFromRequest(request) {
  const authHeader = request.headers.get("Authorization") || "";

  if (!authHeader.startsWith("Bearer ")) {
    throw new Error("Missing bearer token");
  }

  return authHeader.slice("Bearer ".length);
}

async function verifyAccessToken(token, env) {

  const issuer = env.AUTH0_ISSUER;
  const audience = env.AUTH0_AUDIENCE;

  if (!issuer || !audience) {
    throw new Error("Missing Auth0 env vars");
  }

  const jwks = createRemoteJWKSet(
    new URL(`${issuer}.well-known/jwks.json`)
  );

  const { payload } = await jwtVerify(token, jwks, {
    issuer,
    audience
  });

  return payload;
}

export async function onRequestGet(context) {

  const { request, env } = context;

  try {

    // Verify Auth0 token
    const token = getAuth0TokenFromRequest(request);
    const payload = await verifyAccessToken(token, env);

    const sub = payload.sub;

    if (!sub) {
      return new Response(
        JSON.stringify({ ok: false, message: "Missing user identity" }),
        { status: 401 }
      );
    }

    // Get Salesforce access token
    const sfAuth = await getSalesforceAccessToken(env);

    const url =
      `${sfAuth.instance_url}` +
      `/services/apexrest/portal/announcements` +
      `?sub=${encodeURIComponent(sub)}`;

    const sfResponse = await fetch(url, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${sfAuth.access_token}`,
        "Content-Type": "application/json"
      }
    });

    const text = await sfResponse.text();

    return new Response(text, {
      status: sfResponse.status,
      headers: {
        "Content-Type": "application/json"
      }
    });

  } catch (err) {

    return new Response(
      JSON.stringify({
        ok: false,
        message: err.message || "Server error"
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
}
