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

async function sfPost(instanceUrl, accessToken, path, body) {
  const resp = await fetch(`${instanceUrl}${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  const ct = resp.headers.get("content-type") || "";
  const text = await resp.text();
  const parsed = ct.includes("application/json") ? (JSON.parse(text || "{}")) : null;

  if (!resp.ok) {
    return {
      ok: false,
      sfStatus: resp.status,
      sfContentType: ct,
      sfBody: parsed ?? text,   // <-- this is the key
    };
  }
  return parsed ?? { ok: true, raw: text };
}

export async function onRequestPost({ request, env }) {
  try {
    const token = getBearerToken(request);
    if (!token) {
      return new Response(JSON.stringify({ ok: false, error: "Missing Bearer token" }), { status: 401 });
    }

    const payload = await verifyAuth0Jwt(token, env);
    const sub = payload.sub;

    const body = await request.json();
    const subject = (body?.subject || "").trim();
    const description = (body?.description || "").trim();
    const photos = Array.isArray(body?.photos) ? body.photos : [];

    if (!subject || !description) {
      return new Response(JSON.stringify({ ok: false, error: "Missing subject/description" }), { status: 400 });
    }

    const { access_token, instance_url } = await getSalesforceAccessToken(env);

    // 1) Get tenancyId securely from portal context
    const ctx = await sfPost(instance_url, access_token, "/services/apexrest/portal/context", { sub });
    if (!ctx?.ok || !ctx?.tenancy?.id) {
      return new Response(JSON.stringify({ ok: false, error: "No active tenancy context", ctx }), { status: 403 });
    }

    // 2) Create maintenance via V2 endpoint
    const created = await sfPost(instance_url, access_token, "/services/apexrest/portal/maintenance2", {
      sub,
      tenancyId: ctx.tenancy.id,
      subject,
      description,
      photos,
    });

    const status = created?.ok === false ? 502 : 200;
    return new Response(JSON.stringify(created), {
      status,
      headers: { "Content-Type": "application/json" },
    });

  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: "Server error", details: String(e?.message || e) }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

export async function onRequestGet({ request, env }) {
  try {
    const token = getBearerToken(request);
    if (!token) return new Response(JSON.stringify({ ok: false, error: "Missing Bearer token" }), { status: 401 });

    const payload = await verifyAuth0Jwt(token, env);
    const sub = payload.sub;

    const { access_token, instance_url } = await getSalesforceAccessToken(env);

    const resp = await fetch(
      `${instance_url}/services/apexrest/portal/maintenance/list?sub=${encodeURIComponent(sub)}`,
      { headers: { Authorization: `Bearer ${access_token}` } }
    );

    const ct = resp.headers.get("content-type") || "";
    const text = await resp.text();
    const data = ct.includes("application/json") ? JSON.parse(text || "[]") : [];

    if (!resp.ok) {
      return new Response(JSON.stringify({ ok: false, sfStatus: resp.status, sfBody: data || text }), {
        status: 502,
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify(data), {
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
