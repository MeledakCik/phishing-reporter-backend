import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function sendAbuseReport(report) {
  const hostname = new URL(report.reported_url).hostname;
  
  const to = report.abuse_email || 'abuse@domain-registrar.com';
  const subject = `URGENT: Phishing Site Takedown Request - ${hostname}`;
  
  // Format outgoing links for the email
  let outgoingLinksText = 'None detected';
  try {
    const links = JSON.parse(report.outgoing_links || '[]');
    if (links.length > 0) {
      outgoingLinksText = links.map(l => `- [Type: ${l.type.toUpperCase()}] ${l.url}`).join('\n');
    }
  } catch (e) {
    // Ignore JSON parsing errors
  }

  const body = `Dear Security / Abuse Team,

We would like to report a phishing website hosted on your network/IP infrastructure:

- Target URL: ${report.reported_url}
- Brand Impersonated: ${report.target_brand_raw}
- Server IP Address: ${report.ip_address || 'Unknown'}
- Network/Host Provider: ${report.hosting_provider || 'Unknown'}

This site acts as a malicious threat to local users. It harvests credentials/personal data and coordinates scams using the following external outgoing channels:
${outgoingLinksText}

We have captured and preserved a full-page mobile-rendered screenshot of this site as forensic evidence.

Please investigate and suspend this service immediately to prevent further damage to users.

Best regards,
Local Anti-Phishing & Takedown Community Hub
(Automated Threat Intelligence Dispatcher)`;

  console.log(`\n==================================================`);
  console.log(`[Mailer] SENDING ABUSE REPORT TO: ${to}`);
  console.log(`[Mailer] SUBJECT: ${subject}`);
  console.log(`[Mailer] BODY:\n${body}`);
  console.log(`==================================================\n`);

  // Write file locally to log dispatched emails
  try {
    const mailDir = path.join(__dirname, '../dispatched_emails');
    if (!fs.existsSync(mailDir)) {
      fs.mkdirSync(mailDir, { recursive: true });
    }
    
    const mailFilename = `${report.id}.txt`;
    const mailFilePath = path.join(mailDir, mailFilename);
    const fileContent = `To: ${to}\nSubject: ${subject}\n\n${body}`;
    
    fs.writeFileSync(mailFilePath, fileContent, 'utf8');
    console.log(`[Mailer] Draft saved to file: ${mailFilePath}`);
  } catch (err) {
    console.error(`[Mailer] Failed to save email draft file:`, err.message);
  }

  return { to, subject, body };
}
