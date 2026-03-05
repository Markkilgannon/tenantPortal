import { jwtVerify, createRemoteJWKSet } from "jose";
import { getSalesforceAccessToken } from "../_sf.js"; // note path: download.js is inside docs/

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
    if (!token) return new Response("Missing Bearer token", { status: 401 });

    // Verify token (we don't need sub for this call if SF endpoint is protected by Cloudflare)
    await verifyAuth0Jwt(token, env);

    const url = new URL(request.url);
    const contentDocumentId = url.searchParams.get("contentDocumentId");
    if (!contentDocumentId) return new Response("Missing contentDocumentId", { status: 400 });

    const { access_token, instance_url } = await getSalesforceAccessToken(env);

    const sfResp = await fetch(
      `${instance_url}/services/apexrest/portal/docs/download?contentDocumentId=${encodeURIComponent(contentDocumentId)}`,
      { headers: { Authorization: `Bearer ${access_token}` } }
    );

    // Stream bytes through
    const headers = new Headers();
    const ct = sfResp.headers.get("content-type") || "application/octet-stream";
    headers.set("Content-Type", ct);

    const cd = sfResp.headers.get("content-disposition");
    if (cd) headers.set("Content-Disposition", cd);

    return new Response(sfResp.body, { status: sfResp.status, headers });

  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: "Server error", details: String(e?.message || e) }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}
