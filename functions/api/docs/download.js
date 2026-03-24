import { jwtVerify, createRemoteJWKSet } from "jose";
import { getSalesforceAccessToken } from "../_sf.js";

function getBearerToken(request) {
  const h = request.headers.get("authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

async function verifyAuth0Jwt(token, env) {
  const issuer = env.AUTH0_ISSUER;
  const audience = env.AUTH0_AUDIENCE;
  const jwks = createRemoteJWKSet(new URL(`${issuer}.well-known/jwks.json`));
  const { payload } = await jwtVerify(token, jwks, { issuer, audience });
  return payload;
}

export async function onRequestGet({ request, env }) {
  try {
    const token = getBearerToken(request);
    if (!token) {
      return new Response(JSON.stringify({ ok: false, error: "Missing Bearer token" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    const payload = await verifyAuth0Jwt(token, env);
    const sub = payload.sub;

    const url = new URL(request.url);
    const contentVersionId = url.searchParams.get("contentVersionId");

    if (!contentVersionId) {
      return new Response(JSON.stringify({ ok: false, error: "Missing contentVersionId" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const { access_token, instance_url } = await getSalesforceAccessToken(env);

    const sfResp = await fetch(`${instance_url}/services/apexrest/portal/docs2/download`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ sub, contentVersionId }),
    });

    const headers = new Headers();
    headers.set("Content-Type", sfResp.headers.get("content-type") || "application/octet-stream");

    const cd = sfResp.headers.get("content-disposition");
    if (cd) headers.set("Content-Disposition", cd);

    return new Response(sfResp.body, {
      status: sfResp.status,
      headers,
    });

  } catch (e) {
    return new Response(JSON.stringify({
      ok: false,
      error: "Server error",
      details: String(e?.message || e),
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}
