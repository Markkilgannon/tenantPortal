import { getSalesforceAccessToken } from "../_sf";

const SF_PATH = "/services/apexrest/portal/notifications";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}

async function verifyPortalJwt(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice("Bearer ".length)
    : null;

  if (!token) {
    return { ok: false, status: 401, message: "Missing bearer token." };
  }

  try {
    const jwt = await import("jose");
    const JWKS = jwt.createRemoteJWKSet(
      new URL(`https://${env.AUTH0_DOMAIN}/.well-known/jwks.json`)
    );

    const { payload } = await jwt.jwtVerify(token, JWKS, {
      issuer: `https://${env.AUTH0_DOMAIN}/`,
      audience: env.AUTH0_AUDIENCE
    });

    return { ok: true, payload };
  } catch (error) {
    return { ok: false, status: 401, message: "Invalid or expired token." };
  }
}

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    const auth = await verifyPortalJwt(request, env);
    if (!auth.ok) {
      return json({ ok: false, message: auth.message }, auth.status);
    }

    const portalSub = auth.payload?.sub;
    if (!portalSub) {
      return json({ ok: false, message: "Authenticated user subject was missing." }, 401);
    }

    const sf = await getSalesforceAccessToken(env);
    const url = `${sf.instance_url}${SF_PATH}`;

    const response = await fetch(url, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${sf.access_token}`,
        "Content-Type": "application/json",
        "x-portal-sub": portalSub
      }
    });

    const rawText = await response.text();

    let data = null;
    try {
      data = rawText ? JSON.parse(rawText) : {};
    } catch {
      return json(
        {
          ok: false,
          message: "Salesforce returned non-JSON for notifications.",
          raw: rawText.slice(0, 500)
        },
        502
      );
    }

    return json(data, response.status);
  } catch (error) {
    return json(
      {
        ok: false,
        message: error?.message || "Unable to load notifications."
      },
      500
    );
  }
}
