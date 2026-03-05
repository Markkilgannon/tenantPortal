import { jwtVerify, createRemoteJWKSet } from "jose";
import { getSalesforceAccessToken } from "./_sf.js";

function getBearerToken(request) {
  const h = request.headers.get("authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

async function verifyAuth0Jwt(token, env) {
  const issuer = env.AUTH0_ISSUER; // must end with '/'
  const audience = env.AUTH0_AUDIENCE;

  const jwks = createRemoteJWKSet(new URL(`${issuer}.well-known/jwks.json`));
  const { payload } = await jwtVerify(token, jwks, { issuer, audience });
  return payload;
}

async function callSfPortalContext(env, sub) {
  const { access_token, instance_url } = await getSalesforceAccessToken(env);

  const resp = await fetch(`${instance_url}/services/apexrest/portal/context`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${access_token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ sub }),
  });

  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    return { ok: false, sfStatus: resp.status, sfBody: json };
  }
  return json;
}

export async function onRequestGet({ request, env }) {
  try {
    const token = getBearerToken(request);
    if (!token) {
      return new Response(JSON.stringify({ ok: false, error: "Missing Bearer token" }), { status: 401 });
    }

    const payload = await verifyAuth0Jwt(token, env);
    const sub = payload.sub;

    const sf = await callSfPortalContext(env, sub);

    return new Response(JSON.stringify({ ok: true, sub, sf }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: "Server error", details: String(e?.message || e) }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}
