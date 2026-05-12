// Vercel Serverless Function — POST /api/contact
// File location in your repo: api/contact.js
//
// Add in Vercel Dashboard → Project → Settings → Environment Variables → Production:
//   RESEND_API_KEY   (Sensitive) — your Resend API key
//   SES_FROM_EMAIL   (Plain)     — verified sender, e.g. info@humanvault.xyz
//   CONTACT_TO_EMAIL (Plain)     — info@humanvault.xyz

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ ok: false, error: "method_not_allowed" });
  }

  const body = req.body || {};

  const name    = String(body.name    ?? "").trim();
  const email   = String(body.email   ?? "").trim();
  const subject = String(body.subject ?? "").trim() || "New message from humanvault.xyz";
  const message = String(body.message ?? "").trim();
  const website = String(body.website ?? "").trim(); // honeypot

  // Honeypot — silently pass so bots think they succeeded
  if (website) return res.status(200).json({ ok: true });

  // Validate required fields
  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
  if (!name || !emailOk || !message) {
    return res.status(400).json({ ok: false, error: "validation" });
  }
  if (name.length > 120 || email.length > 200 || subject.length > 200 || message.length > 5000) {
    return res.status(400).json({ ok: false, error: "too_long" });
  }

const apiKey = process.env.RESEND_API_KEY;
const from = process.env.SES_FROM_EMAIL || "info@humanvault.xyz";
const to = process.env.CONTACT_TO_EMAIL || "info@humanvault.xyz";

  if (!apiKey) {
    console.error("resend: missing RESEND_API_KEY");
    return res.status(500).json({ ok: false, error: "server_misconfigured" });
  }

  const text = [
    "New contact form submission",
    "",
    `Name:    ${name}`,
    `Email:   ${email}`,
    `Subject: ${subject}`,
    "",
    "Message:",
    message,
  ].join("\n");

  const html = `<div style="font:14px/1.6 -apple-system,Segoe UI,sans-serif;color:#11110f;max-width:600px">
<h2 style="font-size:15px;margin:0 0 12px">New contact form submission — humanvault.xyz</h2>
<p style="margin:0 0 8px"><strong>Name:</strong> ${esc(name)}</p>
<p style="margin:0 0 8px"><strong>Email:</strong> ${esc(email)}</p>
<p style="margin:0 0 16px"><strong>Subject:</strong> ${esc(subject)}</p>
<div style="border-top:1px solid #ddd;padding-top:12px;white-space:pre-wrap">${esc(message)}</div>
</div>`;

  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "authorization": `Bearer ${apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        from,
        to: [to],
        reply_to: email,
        subject: `[HumanVault] ${subject}`,
        text,
        html,
      }),
    });

    if (!r.ok) {
      const detail = await r.text();
      console.error("resend error", r.status, detail);
      return res.status(502).json({ ok: false, error: "send_failed" });
    }

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error("resend exception:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}
