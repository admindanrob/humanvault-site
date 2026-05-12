// Cloudflare Pages Function — POST /api/contact
// File location in your repo: functions/api/contact.js
// Cloudflare Pages automatically exposes this at: https://humanvault.xyz/api/contact
//
// Required env vars (set in Cloudflare Pages → Settings → Environment variables → Production):
//   AWS_ACCESS_KEY_ID      (Secret)
//   AWS_SECRET_ACCESS_KEY  (Secret)
//   AWS_REGION             e.g. eu-west-1
//   SES_FROM_EMAIL         verified SES sender, e.g. info@humanvault.xyz
//   CONTACT_TO_EMAIL       info@humanvault.xyz
//   TURNSTILE_SECRET       (Secret, optional — only if Turnstile is enabled)

export async function onRequest(context) {
  if (context.request.method !== "POST") {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: { allow: "POST" },
    });
  }
  return handle(context);
}

async function handle({ request, env }) {
  const respond = (data, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
    });

  const ct = request.headers.get("content-type") || "";
  if (!ct.includes("application/json"))
    return respond({ ok: false, error: "invalid_content_type" }, 415);

  let body;
  try { body = await request.json(); }
  catch { return respond({ ok: false, error: "invalid_json" }, 400); }

  const name    = String(body.name    ?? "").trim();
  const email   = String(body.email   ?? "").trim();
  const subject = String(body.subject ?? "").trim() || "New message from humanvault.xyz";
  const message = String(body.message ?? "").trim();
  const website = String(body.website ?? "").trim();
  const tsToken = String(body["cf-turnstile-response"] ?? "").trim();

  if (website) return respond({ ok: true });

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
  if (!name || !emailOk || !message)
    return respond({ ok: false, error: "validation" }, 400);

  if (name.length > 120 || email.length > 200 || subject.length > 200 || message.length > 5000)
    return respond({ ok: false, error: "too_long" }, 400);

  if (env.TURNSTILE_SECRET) {
    if (!tsToken) return respond({ ok: false, error: "captcha_required" }, 400);
    const ip = request.headers.get("cf-connecting-ip") || "";
    const v = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: tsToken, remoteip: ip }),
    }).then(r => r.json()).catch(() => ({ success: false }));
    if (!v.success) return respond({ ok: false, error: "captcha_failed" }, 400);
  }

  const region = env.AWS_REGION       || "eu-west-1";
  const from   = env.SES_FROM_EMAIL   || "info@humanvault.xyz";
  const to     = env.CONTACT_TO_EMAIL || "info@humanvault.xyz";
  const ak     = env.AWS_ACCESS_KEY_ID;
  const sk     = env.AWS_SECRET_ACCESS_KEY;

  if (!ak || !sk) {
    console.error("ses: missing credentials");
    return respond({ ok: false, error: "server_misconfigured" }, 500);
  }

  const textBody = [
    "New contact form submission", "",
    `Name:    ${name}`, `Email:   ${email}`, `Subject: ${subject}`, "",
    "Message:", message,
  ].join("\n");

  const htmlBody = `<div style="font:14px/1.6 -apple-system,Segoe UI,sans-serif;color:#11110f;max-width:600px">
<h2 style="font-size:15px;margin:0 0 12px">New contact form submission — humanvault.xyz</h2>
<p style="margin:0 0 8px"><strong>Name:</strong> ${esc(name)}</p>
<p style="margin:0 0 8px"><strong>Email:</strong> ${esc(email)}</p>
<p style="margin:0 0 16px"><strong>Subject:</strong> ${esc(subject)}</p>
<div style="border-top:1px solid #ddd;padding-top:12px;white-space:pre-wrap">${esc(message)}</div>
</div>`;

  const sesPayload = {
    FromEmailAddress: from,
    Destination: { ToAddresses: [to] },
    ReplyToAddresses: [email],
    Content: {
      Simple: {
        Subject: { Data: `[HumanVault] ${subject}`, Charset: "UTF-8" },
        Body: {
          Text: { Data: textBody, Charset: "UTF-8" },
          Html:  { Data: htmlBody, Charset: "UTF-8" },
        },
      },
    },
  };

  const host    = `email.${region}.amazonaws.com`;
  const path    = "/v2/email/outbound-emails";
  const url     = `https://${host}${path}`;
  const reqBody = JSON.stringify(sesPayload);

  let signedHeaders;
  try {
    signedHeaders = await sigV4({
      method: "POST", host, path, region, service: "ses",
      accessKeyId: ak, secretAccessKey: sk,
      payload: reqBody,
      extraHeaders: { "content-type": "application/json" },
    });
  } catch (e) {
    console.error("sigv4 error:", e);
    return respond({ ok: false, error: "server_error" }, 500);
  }

  try {
    const r = await fetch(url, { method: "POST", headers: signedHeaders, body: reqBody });
    if (!r.ok) {
      const detail = await r.text();
      console.error("ses error", r.status, detail);
      return respond({ ok: false, error: "send_failed" }, 502);
    }
    return respond({ ok: true });
  } catch (e) {
    console.error("ses fetch exception:", e);
    return respond({ ok: false, error: "server_error" }, 500);
  }
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

async function sigV4({ method, host, path, region, service, accessKeyId, secretAccessKey, payload, extraHeaders = {} }) {
  const enc = new TextEncoder();
  const now = new Date();
  const amzDate  = now.toISOString().replace(/[-:]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = await sha256hex(payload);

  const allHeaders = {
    host,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
    ...extraHeaders,
  };

  const sortedKeys = Object.keys(allHeaders).map(k => k.toLowerCase()).sort();
  const lookupKey  = k => Object.keys(allHeaders).find(x => x.toLowerCase() === k);
  const canonHeaders = sortedKeys
    .map(k => `${k}:${String(allHeaders[lookupKey(k)]).trim()}\n`)
    .join("");
  const signedHeaders = sortedKeys.join(";");

  const canonRequest = [method.toUpperCase(), path, "", canonHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, await sha256hex(canonRequest)].join("\n");

  const kDate    = await hmac(enc.encode("AWS4" + secretAccessKey), dateStamp);
  const kRegion  = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  const kSigning = await hmac(kService, "aws4_request");
  const signature = toHex(await hmac(kSigning, stringToSign));

  return {
    ...allHeaders,
    authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

async function sha256hex(data) {
  const buf = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return toHex(await crypto.subtle.digest("SHA-256", buf));
}

async function hmac(key, msg) {
  const k = key instanceof Uint8Array ? key : new Uint8Array(key);
  const cryptoKey = await crypto.subtle.importKey("raw", k, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(msg)));
}

function toHex(buf) {
  const b = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
}
