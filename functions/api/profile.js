import { verifyAccessToken, salesforceRequest } from "./_sf.js";

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const authHeader = request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return new Response("Unauthorized", { status: 401 });
    }

    const token = authHeader.slice("Bearer ".length);
    const { payload } = await verifyAccessToken(token, env);

    const body = await request.json();

    const sfRes = await salesforceRequest(
      env,
      "/services/apexrest/portal/profile",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          sub: payload.sub,
          email: body.email,
          phone: body.phone
        })
      }
    );

    const text = await sfRes.text();

    return new Response(text, {
      status: sfRes.status,
      headers: {
        "Content-Type": "application/json"
      }
    });
  } catch (e) {
    return new Response(
      JSON.stringify({ ok: false, message: e.message || "Server error" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
}
