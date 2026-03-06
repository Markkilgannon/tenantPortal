import { jwtVerify, createRemoteJWKSet } from "jose";
import { getSalesforceAccessToken } from "./_sf.js";

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

    const payload = await verifyAuth0Jwt(token, env);
    const sub = payload.sub;

    const url = new URL(request.url);
    const contentDocumentId = url.searchParams.get("contentDocumentId");
    if (!contentDocumentId) return new Response("Missing contentDocumentId", { status: 400 });

    const { access_token, instance_url } = await getSalesforceAccessToken(env);

    // POST to Salesforce download endpoint so SF can validate tenancy access
    const sfResp = await fetch(`${instance_url}/services/apexrest/portal/docs2/download`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ sub, contentDocumentId }),
    });

    // Stream response
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
