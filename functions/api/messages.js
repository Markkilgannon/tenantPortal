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

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    const payload = await verifyJwt(request, env);
    const sub = payload.sub;

    if (!sub) {
      return jsonResponse(
        { ok: false, message: "Missing subject" },
        401
      );
    }

    const url = new URL(request.url);
    const maintenanceId = url.searchParams.get("maintenanceId");

    if (!maintenanceId) {
      return jsonResponse(
        { ok: false, message: "Missing maintenanceId" },
        400
      );
    }

    const sfAuth = await getSalesforceAccessToken(env);

    const apexUrl =
      `${sfAuth.instance_url}` +
      `/services/apexrest/portal/messages` +
      `?sub=${encodeURIComponent(sub)}` +
      `&maintenanceId=${encodeURIComponent(maintenanceId)}`;

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
    return jsonResponse(
      {
        ok: false,
        message: error.message || "Server error"
      },
      500
    );
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const payload = await verifyJwt(request, env);
    const sub = payload.sub;

    if (!sub) {
      return jsonResponse(
        { ok: false, message: "Missing subject" },
        401
      );
    }

    const body = await request.json().catch(() => null);

    if (!body) {
      return jsonResponse(
        { ok: false, message: "Invalid JSON body" },
        400
      );
    }

    const maintenanceId = body.maintenanceId;
    const message = String(body.message || "").trim();

    if (!maintenanceId) {
      return jsonResponse(
        { ok: false, message: "Missing maintenanceId" },
        400
      );
    }

    if (!message) {
      return jsonResponse(
        { ok: false, message: "Message is required" },
        400
      );
    }

    if (message.length > 1000) {
      return jsonResponse(
        { ok: false, message: "Message must be 1000 characters or less" },
        400
      );
    }

    const sfAuth = await getSalesforceAccessToken(env);

    const apexUrl =
      `${sfAuth.instance_url}` +
      `/services/apexrest/portal/messages`;

    const sfRes = await fetch(apexUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${sfAuth.access_token}`,
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: JSON.stringify({
        sub,
        maintenanceId,
        message
      })
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
    return jsonResponse(
      {
        ok: false,
        message: error.message || "Server error"
      },
      500
    );
  }
}
