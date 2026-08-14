import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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
      body: JSON.stringify(payload)
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
  return dispatchEmail({ to, subject, body, attachmentPath: shot, attachmentName: `${report.id}.jpg` });
}
