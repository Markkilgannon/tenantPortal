import { corsHeaders, verifyAuth0JWT, callSalesforceApex } from "./_utils.js";

export async function onRequestOptions({ env }) {
  return new Response("", { status: 204, headers: corsHeaders(env) });
}

export async function onRequestGet({ request, env }) {
  const ch = corsHeaders(env);

  try {
    // 1) Verify Auth0 token
    const jwt = await verifyAuth0JWT(env, request);

    // 2) Call Salesforce Apex REST
    const r = await callSalesforceApex(env, "GET", "/portal/me", jwt.sub);

    return new Response(JSON.stringify(r.json ?? {}), {
      status: r.status,
      headers: { ...ch, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(
      JSON.stringify({ error: "UNAUTHORIZED", message: e.message }),
      { status: 401, headers: { ...ch, "Content-Type": "application/json" } }
    );
  }
}
