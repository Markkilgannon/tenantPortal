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
    throw new Error("Missing Auth0 env vars (AUTH0_ISSUER, AUTH0_AUDIENCE).");
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

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const accessToken = getAuth0TokenFromRequest(request);
    const payload = await verifyAccessToken(accessToken, env);

    const body = await request.json().catch(() => ({}));

    const sfAuth = await getSalesforceAccessToken(env);

    const sfResp = await fetch(
      `${sfAuth.instance_url}/services/apexrest/portal/profile`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${sfAuth.access_token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          sub: payload.sub,
          email: body.email,
          phone: body.phone
        })
      }
    );

    const text = await sfResp.text();

    return new Response(text, {
      status: sfResp.status,
      headers: {
        "Content-Type": "application/json"
      }
    });
  } catch (e) {
    const message = e?.message || "Server error";

    const status =
      message === "Missing bearer token" ? 401 : 500;

    return new Response(
      JSON.stringify({
        ok: false,
        message
      }),
      {
        status,
        headers: {
          "Content-Type": "application/json"
        }
      }
    );
  }
}
