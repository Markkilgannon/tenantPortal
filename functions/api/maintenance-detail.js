import { getSalesforceAccessToken } from "./_sf";

const AUTH0_ISSUER = "https://dev-v3g60bdgfjg7walx.us.auth0.com/";
const JWKS_URL = "https://dev-v3g60bdgfjg7walx.us.auth0.com/.well-known/jwks.json";

async function verifyJwt(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    throw new Error("Missing bearer token");
  }

  const { jwtVerify, createRemoteJWKSet } = await import("jose");
  const JWKS = createRemoteJWKSet(new URL(JWKS_URL));

  const { payload } = await jwtVerify(token, JWKS, {
    issuer: env.AUTH0_ISSUER || AUTH0_ISSUER,
    audience: env.AUTH0_AUDIENCE
  });

  return payload;
}

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    const payload = await verifyJwt(request, env);
    const sub = payload.sub;

    if (!sub) {
      return new Response(JSON.stringify({ ok: false, message: "Missing subject" }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }

    const url = new URL(request.url);
    const maintenanceId = url.searchParams.get("id");

    if (!maintenanceId) {
      return new Response(JSON.stringify({ ok: false, message: "Missing maintenance id" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    const sfAuth = await getSalesforceAccessToken(env);

    const apexUrl =
      `${sfAuth.instance_url}` +
      `/services/apexrest/portal/maintenance/detail` +
      `?sub=${encodeURIComponent(sub)}` +
      `&id=${encodeURIComponent(maintenanceId)}`;

    const sfRes = await fetch(apexUrl, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${sfAuth.access_token}`,
        Accept: "application/json"
      }
    });

    const text = await sfRes.text();

    return new Response(text, {
      status: sfRes.status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
      }
    });
  } catch (error) {
    return new Response(
      JSON.stringify({
        ok: false,
        message: error.message || "Server error"
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
}
