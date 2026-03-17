function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}

function getEnv(name, env) {
  const value = env?.[name];
  if (!value) {
    throw new Error(`Missing environment variable: ${name}`);
  }
  return value;
}

function getBearerToken(request) {
  const authHeader = request.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ")) {
    return null;
  }
  return authHeader.slice(7).trim();
}

async function verifyPortalUser(request, env) {
  const token = getBearerToken(request);

  if (!token) {
    return {
      ok: false,
      response: json({ message: "Missing bearer token." }, 401)
    };
  }

  const authVerifyUrl = `${new URL(request.url).origin}/api/me`;

  try {
    const meResponse = await fetch(authVerifyUrl, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    if (!meResponse.ok) {
      const text = await meResponse.text();
      return {
        ok: false,
        response: json(
          {
            message: "Unauthorised portal session.",
            details: text || "Unable to verify user session."
          },
          401
        )
      };
    }

    const meData = await meResponse.json().catch(() => null);

    return {
      ok: true,
      token,
      meData
    };
  } catch (error) {
    return {
      ok: false,
      response: json(
        {
          message: "Failed to verify portal session.",
          details: error.message
        },
        500
      )
    };
  }
}

async function getSalesforceAccessToken(env) {
  const loginUrl = getEnv("SF_LOGIN_URL", env);
  const clientId = getEnv("SF_CLIENT_ID", env);
  const clientSecret = getEnv("SF_CLIENT_SECRET", env);
  const username = getEnv("SF_USERNAME", env);
  const password = getEnv("SF_PASSWORD", env);

  const body = new URLSearchParams({
    grant_type: "password",
    client_id: clientId,
    client_secret: clientSecret,
    username,
    password
  });

  const response = await fetch(`${loginUrl}/services/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });

  const text = await response.text();
  let data = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }

  if (!response.ok) {
    throw new Error(
      data?.error_description ||
        data?.error ||
        `Salesforce token request failed with status ${response.status}`
    );
  }

  if (!data?.access_token || !data?.instance_url) {
    throw new Error("Salesforce token response was incomplete.");
  }

  return {
    accessToken: data.access_token,
    instanceUrl: data.instance_url
  };
}

async function callSalesforce({ env, method, path, body }) {
  const { accessToken, instanceUrl } = await getSalesforceAccessToken(env);

  const response = await fetch(`${instanceUrl}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: body ? JSON.stringify(body) : undefined
  });

  const rawText = await response.text();

  let data = null;
  try {
    data = rawText ? JSON.parse(rawText) : null;
  } catch {
    data = null;
  }

  if (!response.ok) {
    return {
      ok: false,
      status: response.status,
      rawText,
      data
    };
  }

  return {
    ok: true,
    status: response.status,
    rawText,
    data
  };
}

function validateMaintenanceOwnership(maintenanceId, meData) {
  const items = Array.isArray(meData)
    ? meData
    : Array.isArray(meData?.items)
    ? meData.items
    : Array.isArray(meData?.maintenance)
    ? meData.maintenance
    : Array.isArray(meData?.sf?.maintenance)
    ? meData.sf.maintenance
    : null;

  if (!items) {
    return true;
  }

  return items.some((item) => {
    const id = item?.id || item?.maintenanceId;
    return String(id) === String(maintenanceId);
  });
}

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    const authCheck = await verifyPortalUser(request, env);
    if (!authCheck.ok) return authCheck.response;

    const url = new URL(request.url);
    const maintenanceId = url.searchParams.get("maintenanceId");

    if (!maintenanceId) {
      return json({ message: "maintenanceId is required." }, 400);
    }

    const allowed = validateMaintenanceOwnership(maintenanceId, authCheck.meData);
    if (!allowed) {
      return json(
        { message: "You do not have access to this maintenance request." },
        403
      );
    }

    const sfResult = await callSalesforce({
      env,
      method: "GET",
      path: `/services/apexrest/portal/messages?maintenanceId=${encodeURIComponent(
        maintenanceId
      )}`
    });

    if (!sfResult.ok) {
      return json(
        {
          message:
            sfResult.data?.message ||
            `Salesforce messages GET failed with status ${sfResult.status}`,
          details: sfResult.rawText?.slice(0, 1000) || null
        },
        sfResult.status || 500
      );
    }

    return json(
      {
        messages: Array.isArray(sfResult.data?.messages)
          ? sfResult.data.messages
          : []
      },
      200
    );
  } catch (error) {
    return json(
      {
        message: "Failed to load messages.",
        details: error.message
      },
      500
    );
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const authCheck = await verifyPortalUser(request, env);
    if (!authCheck.ok) return authCheck.response;

    const payload = await request.json().catch(() => null);

    if (!payload) {
      return json({ message: "A valid JSON body is required." }, 400);
    }

    const maintenanceId = payload.maintenanceId;
    const message = String(payload.message || "").trim();

    if (!maintenanceId) {
      return json({ message: "maintenanceId is required." }, 400);
    }

    if (!message) {
      return json({ message: "message is required." }, 400);
    }

    if (message.length > 1000) {
      return json({ message: "message must be 1000 characters or less." }, 400);
    }

    const allowed = validateMaintenanceOwnership(maintenanceId, authCheck.meData);
    if (!allowed) {
      return json(
        { message: "You do not have access to this maintenance request." },
        403
      );
    }

    const sfResult = await callSalesforce({
      env,
      method: "POST",
      path: `/services/apexrest/portal/messages`,
      body: {
        maintenanceId,
        message
      }
    });

    if (!sfResult.ok) {
      return json(
        {
          message:
            sfResult.data?.message ||
            `Salesforce messages POST failed with status ${sfResult.status}`,
          details: sfResult.rawText?.slice(0, 1000) || null
        },
        sfResult.status || 500
      );
    }

    return json(
      {
        success: sfResult.data?.success === true,
        messageRecord: sfResult.data?.messageRecord || null
      },
      200
    );
  } catch (error) {
    return json(
      {
        message: "Failed to send message.",
        details: error.message
      },
      500
    );
  }
}
