import { jwtVerify, createRemoteJWKSet } from "jose";

export async function onRequestGet(context) {
  try {
    const auth = context.request.headers.get("authorization") || "";
    const match = auth.match(/^Bearer\s+(.+)$/i);
    if (!match) {
      return new Response(JSON.stringify({ error: "missing_bearer_token" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      });
    }

    const token = match[1];

    // Set these in Cloudflare Pages -> Settings -> Environment variables
    const ISSUER = context.env.AUTH0_ISSUER;   // e.g. https://your-tenant.eu.auth0.com/
    const AUDIENCE = context.env.AUTH0_AUDIENCE; // e.g. https://api.yourapp.com

    if (!ISSUER || !AUDIENCE) {
      return new Response(JSON.stringify({ error: "missing_env_vars", ISSUER: !!ISSUER, AUDIENCE: !!AUDIENCE }), {
        status: 500,
        headers: { "content-type": "application/json" },
      });
    }

    const jwks = createRemoteJWKSet(new URL(`${ISSUER}.well-known/jwks.json`));

    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      issuer: ISSUER,
      audience: AUDIENCE,
    });

    return new Response(
      JSON.stringify({
        ok: true,
        header: protectedHeader,
        // common useful claims:
        sub: payload.sub,
        email: payload.email,
        scope: payload.scope,
        aud: payload.aud,
        iss: payload.iss,
        exp: payload.exp,
        iat: payload.iat,
        payload,
      }),
      { status: 200, headers: { "content-type": "application/json" } }
    );
  } catch (e) {
    return new Response(
      JSON.stringify({
        ok: false,
        error: "jwt_verify_failed",
        message: e?.message || String(e),
      }),
      { status: 401, headers: { "content-type": "application/json" } }
    );
  }
}
