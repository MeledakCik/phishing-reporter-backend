import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { Resend } from 'resend';
import { google } from 'googleapis';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const resend = new Resend(process.env.RESEND_API_KEY);

// ---------------------------------------------------------------------------
// Gmail dispatch - used ONLY for the Kominfo Aduan Konten channel.
//
// Why Gmail at all: Kominfo's mail gateway consistently soft-bounces mail
// sent through Resend/Amazon SES (shared IP pool), even with valid
// SPF/DKIM/DMARC on the sending domain - confirmed by testing the exact same
// report content sent manually from a personal Gmail account, which was
// delivered without issue. All other channels (registrar/hosting abuse
// desks, APWG, Vercel abuse) continue to use Resend as before, since those
// deliver fine.
//
// Why the Gmail REST API instead of SMTP: many PaaS hosts (Render, Railway,
// Fly.io free tiers, etc.) block outbound SMTP ports (25/465/587) entirely,
// which made the previous nodemailer-over-SMTP implementation hang or fail
// to connect regardless of credentials. The Gmail REST API
// (https://gmail.googleapis.com) is called like any other Google API - a
// plain HTTPS POST on port 443 - so it works on hosts that block SMTP.
//
// Configure with an OAuth2 client (GMAIL_CLIENT_ID + GMAIL_CLIENT_SECRET,
// from a project in Google Cloud Console with the Gmail API enabled) plus a
// GMAIL_REFRESH_TOKEN obtained once via the OAuth consent flow for the
// sending mailbox (scope: https://www.googleapis.com/auth/gmail.send), and
// GMAIL_USER (the mailbox address the refresh token belongs to, used as the
// From address).
// ---------------------------------------------------------------------------

let gmailOAuth2Client = null;

function getGmailClient() {
  const user = process.env.GMAIL_USER;
  const clientId = process.env.GMAIL_CLIENT_ID;
  const clientSecret = process.env.GMAIL_CLIENT_SECRET;
  const refreshToken = process.env.GMAIL_REFRESH_TOKEN;
  if (!user || !clientId || !clientSecret || !refreshToken) return null;

  if (!gmailOAuth2Client) {
    gmailOAuth2Client = new google.auth.OAuth2(clientId, clientSecret);
    gmailOAuth2Client.setCredentials({ refresh_token: refreshToken });
  }
  return google.gmail({ version: 'v1', auth: gmailOAuth2Client });
}

// Encodes a string using RFC 2047 so non-ASCII subjects survive MIME headers.
function encodeMimeHeader(str) {
  return `=?UTF-8?B?${Buffer.from(str, 'utf8').toString('base64')}?=`;
}

// Builds a raw RFC 2822 MIME message (plain text + optional single
// attachment) and base64url-encodes it, as required by the Gmail API's
// messages.send `raw` field.
function buildRawMimeMessage({ from, to, subject, body, attachmentPath, attachmentName }) {
  const boundary = `----=_ThreatReports_${Date.now()}`;
  const headers = [
    `From: "Threat Reports" <${from}>`,
    `To: ${to}`,
    `Subject: ${encodeMimeHeader(subject)}`,
    'MIME-Version: 1.0'
  ];

  let raw;
  if (attachmentPath && fs.existsSync(attachmentPath)) {
    const attachmentData = fs.readFileSync(attachmentPath).toString('base64');
    const name = attachmentName || path.basename(attachmentPath);
    headers.push(`Content-Type: multipart/mixed; boundary="${boundary}"`);
    raw = [
      ...headers,
      '',
      `--${boundary}`,
      'Content-Type: text/plain; charset="UTF-8"',
      'Content-Transfer-Encoding: 7bit',
      '',
      body,
      '',
      `--${boundary}`,
      `Content-Type: image/jpeg; name="${name}"`,
      'Content-Transfer-Encoding: base64',
      `Content-Disposition: attachment; filename="${name}"`,
      '',
      attachmentData,
      '',
      `--${boundary}--`
    ].join('\r\n');
  } else {
    headers.push('Content-Type: text/plain; charset="UTF-8"');
    raw = [...headers, '', body].join('\r\n');
  }

  return Buffer.from(raw)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function dispatchEmailViaGmail({ to, subject, body, attachmentPath, attachmentName }) {
  const user = process.env.GMAIL_USER;

  console.log(`\n==================================================`);
  console.log(`[Mailer/Gmail] TO: ${to}`);
  console.log(`[Mailer/Gmail] SUBJECT: ${subject}`);
  console.log(`[Mailer/Gmail] BODY:\n${body}`);
  console.log(`==================================================\n`);

  // Always keep a local audit copy regardless of send outcome.
  try {
    const mailDir = path.join(__dirname, '../dispatched_emails');
    if (!fs.existsSync(mailDir)) {
      fs.mkdirSync(mailDir, { recursive: true });
    }
    const mailFilePath = path.join(mailDir, `${Date.now()}_${to.replace(/[^a-z0-9]/gi, '_')}.txt`);
    fs.writeFileSync(mailFilePath, `To: ${to}\nSubject: ${subject}\nVia: Gmail API (HTTPS)\n\n${body}`, 'utf8');
    console.log(`[Mailer/Gmail] Local audit copy saved: ${mailFilePath}`);
  } catch (err) {
    console.error(`[Mailer/Gmail] Failed to save local audit copy:`, err.message);
  }

  const gmail = getGmailClient();
  if (!gmail) {
    console.warn(`[Mailer/Gmail] GMAIL_USER/GMAIL_CLIENT_ID/GMAIL_CLIENT_SECRET/GMAIL_REFRESH_TOKEN not fully configured - email was NOT actually sent, only logged/saved locally.`);
    return { to, subject, body, status: 'SIMULATED_NOT_SENT', reason: 'Gmail OAuth2 env vars missing' };
  }

  try {
    const raw = buildRawMimeMessage({ from: user, to, subject, body, attachmentPath, attachmentName });

    const res = await gmail.users.messages.send({
      userId: 'me',
      requestBody: { raw },
      // Bound the request so a slow/unreachable Google API call can't hang
      // the approve endpoint indefinitely.
      // (googleapis forwards this to the underlying gaxios request)
      timeout: 15000
    });

    console.log(`[Mailer/Gmail] Email actually dispatched via Gmail API (HTTPS). Message ID: ${res.data.id}`);
    return { to, subject, body, status: 'SENT', message_id: res.data.id };
  } catch (err) {
    const errMsg = err?.response?.data?.error?.message || err.message;
    console.error(`[Mailer/Gmail] Gmail API send failed:`, errMsg);
    return { to, subject, body, status: 'FAILED', error: errMsg };
  }
}

// ---------------------------------------------------------------------------
// Real email dispatch via the Resend API (https://resend.com).
// Configure with RESEND_API_KEY + MAIL_FROM env vars.
//
// If RESEND_API_KEY is not configured, emails are NOT sent - they are only
// logged and saved to disk, and the result is explicitly marked
// status: 'SIMULATED_NOT_SENT' so callers never mistake a local log write
// for a real delivery.
// ---------------------------------------------------------------------------

async function dispatchEmail({ to, subject, body, attachmentPath, attachmentName }) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.MAIL_FROM || 'Threat Reports <onboarding@resend.dev>';

  console.log(`\n==================================================`);
  console.log(`[Mailer] TO: ${to}`);
  console.log(`[Mailer] SUBJECT: ${subject}`);
  console.log(`[Mailer] BODY:\n${body}`);
  console.log(`==================================================\n`);

  // Always keep a local audit copy regardless of send outcome.
  try {
    const mailDir = path.join(__dirname, '../dispatched_emails');
    if (!fs.existsSync(mailDir)) {
      fs.mkdirSync(mailDir, { recursive: true });
    }
    const mailFilePath = path.join(mailDir, `${Date.now()}_${to.replace(/[^a-z0-9]/gi, '_')}.txt`);
    fs.writeFileSync(mailFilePath, `To: ${to}\nSubject: ${subject}\n\n${body}`, 'utf8');
    console.log(`[Mailer] Local audit copy saved: ${mailFilePath}`);
  } catch (err) {
    console.error(`[Mailer] Failed to save local audit copy:`, err.message);
  }

  if (!apiKey) {
    console.warn(`[Mailer] RESEND_API_KEY not configured - email was NOT actually sent, only logged/saved locally.`);
    return { to, subject, body, status: 'SIMULATED_NOT_SENT', reason: 'RESEND_API_KEY missing' };
  }

  try {
    const payload = { from, to: [to], subject, text: body };

    if (attachmentPath && fs.existsSync(attachmentPath)) {
      const fileBuffer = fs.readFileSync(attachmentPath);
      payload.attachments = [
        { filename: attachmentName || path.basename(attachmentPath), content: fileBuffer.toString('base64') }
      ];
    }

    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15000) // fail fast instead of hanging the approve request
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      console.error(`[Mailer] Resend API rejected the email (HTTP ${res.status}):`, data);
      return { to, subject, body, status: 'FAILED', http_status: res.status, error: data };
    }

    console.log(`[Mailer] Email actually dispatched via Resend. Message ID: ${data.id}`);
    return { to, subject, body, status: 'SENT', message_id: data.id };
  } catch (err) {
    console.error(`[Mailer] Resend API request failed:`, err.message);
    return { to, subject, body, status: 'FAILED', error: err.message };
  }
}

function buildOutgoingLinksText(report) {
  let outgoingLinksText = 'None detected';
  try {
    const links = JSON.parse(report.outgoing_links || '[]');
    if (links.length > 0) {
      outgoingLinksText = links.map(l => `- [Type: ${l.type.toUpperCase()}] ${l.url}`).join('\n');
    }
  } catch (e) {
    // Ignore JSON parsing errors
  }
  return outgoingLinksText;
}

function screenshotFilePath(report) {
  if (!report.screenshot_url) return null;
  // screenshot_url is stored as "/screenshots/<id>.jpg"
  return path.join(__dirname, '../public', report.screenshot_url);
}

// 1. Registrar / hosting-provider abuse report (real send)
export async function sendAbuseReport(report) {
  const hostname = new URL(report.reported_url).hostname;
  const to = report.abuse_email || 'abuse@domain-registrar.com';
  const subject = `URGENT: Phishing Site Takedown Request - ${hostname}`;
  const outgoingLinksText = buildOutgoingLinksText(report);

  const gsbLine = report.gsb_status === 'FLAGGED'
    ? `\nThis URL is independently confirmed as malicious by Google Safe Browsing (threat types: ${report.gsb_threat_types || 'unknown'}).\n`
    : '';

  const body = `Dear Security / Abuse Team,

We would like to report a phishing website hosted on your network/IP infrastructure:

- Target URL: ${report.reported_url}
- Brand Impersonated: ${report.target_brand_raw}
- Server IP Address: ${report.ip_address || 'Unknown'}
- Network/Host Provider: ${report.hosting_provider || 'Unknown'}
${gsbLine}
This site acts as a malicious threat to local users. It harvests credentials/personal data and coordinates scams using the following external outgoing channels:
${outgoingLinksText}

We have captured and preserved a full-page mobile-rendered screenshot of this site as forensic evidence (attached).

Please investigate and suspend this service immediately to prevent further damage to users.

Best regards,
Local Anti-Phishing & Takedown Community Hub
(Automated Threat Intelligence Dispatcher)`;

  const shot = screenshotFilePath(report);
  return dispatchEmail({ to, subject, body, attachmentPath: shot, attachmentName: `${report.id}.jpg` });
}

// 1b. Vercel abuse-desk report (real send via Resend SDK).
// Vercel has no public "report abuse" API - the documented/legitimate
// channel is emailing abuse@vercel.com directly, so this bypasses
// dispatchEmail() and calls the Resend SDK's HTML send path.
export async function reportToVercelAbuse(phishingUrl) {
  const from = process.env.MAIL_FROM;
  const to = 'abuse@vercel.com';
  const subject = `Phishing Takedown - ${phishingUrl}`;
  const timestamp = new Date().toISOString();

  const html = `
    <div style="font-family: Arial, sans-serif; font-size: 14px; color: #111;">
      <h2>Phishing Takedown Request</h2>
      <p>We are reporting a phishing site hosted on Vercel's infrastructure.</p>
      <table cellpadding="6" cellspacing="0" style="border-collapse: collapse;">
        <tr>
          <td style="border: 1px solid #ddd;"><strong>Phishing URL</strong></td>
          <td style="border: 1px solid #ddd;">${phishingUrl}</td>
        </tr>
        <tr>
          <td style="border: 1px solid #ddd;"><strong>Reported At (UTC)</strong></td>
          <td style="border: 1px solid #ddd;">${timestamp}</td>
        </tr>
      </table>
      <p>
        This URL is being used to impersonate a legitimate brand and harvest
        user credentials/personal data. Please investigate and take down this
        deployment as soon as possible.
      </p>
      <p>Thank you for your prompt attention to this matter.</p>
    </div>
  `;

  try {
    const { data, error } = await resend.emails.send({
      from,
      to: [to],
      subject,
      html,
    });

    if (error) {
      console.error(`[Mailer] Resend SDK error reporting to Vercel abuse:`, error);
      return { to, subject, status: 'FAILED', error };
    }

    console.log(`[Mailer] Vercel abuse report sent. Message ID: ${data?.id}`);
    return { to, subject, status: 'SENT', ...data };
  } catch (err) {
    console.error(`[Mailer] Resend SDK request failed:`, err.message);
    return { to, subject, status: 'FAILED', error: err.message };
  }
}

// 1c. APWG (Anti-Phishing Working Group) - real send via Resend.
// APWG has no public submission API; reportphishing@apwg.org is the
// documented automatable intake address used by browsers/security vendors
// to feed the eCrime Exchange threat-sharing clearinghouse.
export async function sendApwgReport(report) {
  const to = process.env.APWG_REPORT_EMAIL || 'reportphishing@apwg.org';
  const hostname = new URL(report.reported_url).hostname;
  const subject = `Phishing Report - ${hostname}`;
  const outgoingLinksText = buildOutgoingLinksText(report);

  const gsbLine = report.gsb_status === 'FLAGGED'
    ? `\nThis URL is independently confirmed as malicious by Google Safe Browsing (threat types: ${report.gsb_threat_types || 'unknown'}).\n`
    : '';

  const body = `To the APWG eCrime Exchange,

We are reporting a phishing website for inclusion in the shared threat feed:

- Phishing URL: ${report.reported_url}
- Brand Impersonated: ${report.target_brand_raw}
- Server IP Address: ${report.ip_address || 'Unknown'}
- Hosting Provider: ${report.hosting_provider || 'Unknown'}
${gsbLine}
This site harvests credentials/personal data and coordinates scams using the following external outgoing channels:
${outgoingLinksText}

A full-page rendered screenshot is attached as forensic evidence.

Regards,
Local Anti-Phishing & Takedown Community Hub
(Automated Threat Intelligence Dispatcher)`;

  const shot = screenshotFilePath(report);
  return dispatchEmail({ to, subject, body, attachmentPath: shot, attachmentName: `${report.id}.jpg` });
}

// 2. Kominfo (Indonesian Ministry of Communication) content-abuse intake.
// Real intake channel: aduankonten@kominfo.go.id. Note: the aduankonten.id
// *website* requires an account + CAPTCHA and cannot be automated - this
// email channel is the legitimate automatable path.
export async function sendKominfoReport(report) {
  const to = process.env.KOMINFO_ADUAN_EMAIL || 'aduankonten@kominfo.go.id';
  const subject = `Aduan Konten Negatif: Situs Terindikasi Judi Online/Penipuan - ${report.reported_url}`;
  const outgoingLinksText = buildOutgoingLinksText(report);

  const body = `Kepada Yth. Tim Aduan Konten Kominfo,

Kami ingin melaporkan situs yang terindikasi sebagai konten negatif (judi online / penipuan daring):

- URL Situs: ${report.reported_url}
- Brand/Merek yang Ditiru: ${report.target_brand_raw}
- Alamat IP Server: ${report.ip_address || 'Tidak diketahui'}
- Penyedia Hosting/Registrar: ${report.hosting_provider || 'Tidak diketahui'}

Situs ini mengumpulkan data pribadi/kredensial pengguna dan/atau mengarahkan ke kanal berikut:
${outgoingLinksText}

Tangkapan layar (screenshot) situs terlampir sebagai bukti forensik.

Mohon kiranya laporan ini dapat ditindaklanjuti untuk proses pemblokiran (trust positif).

Hormat kami,
Local Anti-Phishing & Takedown Community Hub`;

  const shot = screenshotFilePath(report);
  // Routed via Gmail SMTP (not Resend) - see dispatchEmailViaGmail() comment
  // near the top of this file for why: Kominfo's mail gateway bounces mail
  // sent via Resend/Amazon SES even with valid SPF/DKIM/DMARC, but accepts
  // the identical content sent via Gmail SMTP (confirmed by manual test).
  // The forensic screenshot is attached exactly as it was before.
  return dispatchEmailViaGmail({ to, subject, body, attachmentPath: shot, attachmentName: `${report.id}.jpg` });
}
