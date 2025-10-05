import { app } from '@azure/functions';
import crypto from 'crypto';
import { DefaultAzureCredential } from '@azure/identity';
import { TableClient, odata } from '@azure/data-tables';
import { EmailClient } from '@azure/communication-email';
import bcrypt from 'bcryptjs';
import { getCorsHeaders, handleCorsOptions } from './utils/cors.js';

// ENVIRONMENT VARIABLES
const accountName = process.env.STORAGE_ACCOUNT_NAME;
const communicationConnectionString = process.env.AZURE_COMMUNICATION_CONNECTION_STRING;
const senderEmail = process.env.SENDER_EMAIL;
const frontendDomain = process.env.FRONTEND_DOMAIN ?? 'https://www.onlinetherapytools.com';

if (!accountName || !communicationConnectionString || !senderEmail) {
  throw new Error('Missing required environment variables: STORAGE_ACCOUNT_NAME, AZURE_COMMUNICATION_CONNECTION_STRING, or SENDER_EMAIL.');
}

// CLIENT INITIALIZATION
const tableEndpoint = `https://${accountName}.table.core.windows.net`;
const credential = new DefaultAzureCredential();
const prospectsTable = new TableClient(tableEndpoint, 'prospects', credential);
const resetRequestsTable = new TableClient(tableEndpoint, 'resetrequests', credential);

// HELPER FUNCTIONS
const normalize = (s) => String(s || '').trim().toLowerCase();
const isValidEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalize(e));
const maskEmail = (email) => {
  const [user, domain] = email.split('@');
  const visible = user.slice(0, Math.min(2, user.length));
  const stars = '*'.repeat(Math.max(3, user.length - visible.length));
  return `${visible}${stars}@${domain}`;
};

// PASSWORD VALIDATION - Enhanced security with frontend compatibility
const isValidPassword = (password) => {
  if (!password || typeof password !== 'string') return false;
  if (password.length < 8 || password.length > 128) return false;
  // HTML injection prevention (matching frontend)
  if (/[<>&"']/.test(password)) return false;
  // Require uppercase, lowercase, and digit for security
  if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) return false;
  return true;
};

// ================================================
// FUNCTION 1: REQUEST PASSWORD RESET
// ================================================
app.http(
  'requestpasswordreset',
  {
    methods: ['POST', 'OPTIONS'],
    authLevel: 'function',
    route: 'requestpasswordreset',
  },
  async (req, _context) => {
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
      return handleCorsOptions();
    }

    const commonHeaders = getCorsHeaders();

    // 1. Parse & validate email
    let email;
    try {
      ({ email } = await req.json());
      email = normalize(email);
    } catch {
      return {
        status: 400,
        headers: commonHeaders,
        body: { success: false, message: 'Invalid request format.' },
      };
    }
    if (!isValidEmail(email)) {
      return {
        status: 400,
        headers: commonHeaders,
        body: { success: false, message: 'A valid email is required.' },
      };
    }

    // 2. Lookup user by email (direct O(1) lookup)
    let user;
    try {
      user = await prospectsTable.getEntity(email, email);
    } catch (err) {
      // User lookup failed
      return {
        status: 200,
        headers: commonHeaders,
        body: {
          success: false,
          message: 'Account not found.',
          redirectTo: '/subscribe',
        },
      };
    }

    const therapistId = user.therapistId;
    const now = new Date();

    // Cleanup expired tokens and enforce rate limit
    const active = [];
    const batchDeletes = [];
    try {
      const filter = odata`PartitionKey eq 'reset' and therapistId eq ${therapistId}`;
      for await (const ent of resetRequestsTable.queryEntities({ filter })) {
        const exp = new Date(ent.expiresAt);
        if (!ent.used && exp > now) {
          active.push(ent);
        } else {
          batchDeletes.push([
            'delete',
            { partitionKey: 'reset', rowKey: ent.rowKey },
          ]);
        }
      }
      if (batchDeletes.length) {
        await resetRequestsTable.submitTransaction(batchDeletes);
      }
      if (active.length >= 2) {
        return {
          status: 429,
          headers: commonHeaders,
          body: {
            success: false,
            message: 'Too many recent reset requests. Please wait before trying again.',
          },
        };
      }
    } catch (err) {
      // Rate-limit cleanup failed - continue
    }

    // Generate and store new 6-digit code (15-min expiry)
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(now.getTime() + 15 * 60_000).toISOString();
    const record = {
      partitionKey: 'reset',
      rowKey: code,
      therapistId,
      email,
      createdAt: now.toISOString(),
      expiresAt,
      used: false,
    };
    try {
      await resetRequestsTable.upsertEntity(record, 'Merge');
    } catch (err) {
      return {
        status: 500,
        headers: commonHeaders,
        body: {
          success: false,
          message: 'Could not generate reset token.',
        },
      };
    }

    // Send email via Azure Communication Services
    try {
      const emailClient = new EmailClient(communicationConnectionString);
      
      const emailMessage = {
        senderAddress: senderEmail,
        content: {
          subject: 'Password Reset Code - Online Therapy Tools',
          html: `
            <!DOCTYPE html>
            <html>
            <head>
              <style>
                body { 
                  font-family: Arial, sans-serif; 
                  line-height: 1.6; 
                  color: #333; 
                  max-width: 600px; 
                  margin: 0 auto; 
                  padding: 20px; 
                }
                .header { 
                  background-color: #007cba; 
                  color: white; 
                  padding: 20px; 
                  text-align: center; 
                  border-radius: 8px 8px 0 0; 
                }
                .content { 
                  background-color: #f9f9f9; 
                  padding: 30px; 
                  border-radius: 0 0 8px 8px; 
                }
                .code { 
                  background-color: #007cba; 
                  color: white; 
                  padding: 20px; 
                  text-align: center; 
                  font-size: 32px; 
                  font-weight: bold;
                  letter-spacing: 8px;
                  border-radius: 5px; 
                  margin: 20px 0;
                  font-family: monospace;
                }
                .footer { 
                  margin-top: 30px; 
                  font-size: 12px; 
                  color: #666; 
                  border-top: 1px solid #eee; 
                  padding-top: 20px; 
                }
              </style>
            </head>
            <body>
              <div class="header">
                <h1>Password Reset Code</h1>
              </div>
              <div class="content">
                <p>Hello,</p>
                <p>You requested a password reset for your Online Therapy Tools account (${maskEmail(email)}).</p>
                <p>Enter this code on the password reset page:</p>
                <div class="code">${code}</div>
                <p><strong>This code will expire in 15 minutes.</strong></p>
                <p>If you didn't request this password reset, please ignore this email. Your account remains secure.</p>
                <div class="footer">
                  <p><strong>Online Therapy Tools</strong><br>
                  Visit our website to complete your password reset.</p>
                </div>
              </div>
            </body>
            </html>
          `,
          plainText: `
Password Reset Code - Online Therapy Tools

You requested a password reset for your account (${maskEmail(email)}).

Your reset code is: ${code}

Enter this code on the password reset page to create a new password.

This code will expire in 15 minutes.

If you didn't request this, please ignore this email.

---
Online Therapy Tools
          `
        },
        recipients: {
          to: [{ address: email }]
        }
      };

      const poller = await emailClient.beginSend(emailMessage);
      await poller.pollUntilDone();
    } catch (err) {
      // Email send failed - continue silently
    }

    // Final response
    return {
      status: 200,
      headers: commonHeaders,
      body: {
        success: true,
        message: 'If your account exists, a reset link has been sent to your email.',
      },
    };
  }
);

// ================================================
// FUNCTION 2: RESET PASSWORD
// ================================================
app.http(
  'resetpassword',
  {
    methods: ['POST', 'OPTIONS'],
    authLevel: 'function',
    route: 'resetpassword',
  },
  async (req, _context) => {
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
      return handleCorsOptions();
    }

    const commonHeaders = getCorsHeaders();

    // Parse JSON
    let email, code, newPassword;
    try {
      ({ email, code, newPassword } = await req.json());
      email = normalize(email);
    } catch {
      return {
        status: 400,
        headers: commonHeaders,
        body: { success: false, message: 'Invalid request format.' },
      };
    }

    // Basic validation
    if (!email || !isValidEmail(email)) {
      return {
        status: 400,
        headers: commonHeaders,
        body: { success: false, message: 'Valid email is required.' },
      };
    }
    if (!code || !/^\d{6}$/.test(code)) {
      return {
        status: 400,
        headers: commonHeaders,
        body: { success: false, message: 'Valid 6-digit code is required.' },
      };
    }
    if (!isValidPassword(newPassword)) {
      return {
        status: 400,
        headers: commonHeaders,
        body: { success: false, message: 'Password must be 8-128 characters with at least one uppercase letter, one lowercase letter, and one digit. HTML characters are not allowed.' },
      };
    }

    // Fetch and validate code record
    let codeRec;
    try {
      codeRec = await resetRequestsTable.getEntity('reset', code);
      // Verify email matches the code record
      if (normalize(codeRec.email) !== email) {
        return {
          status: 400,
          headers: commonHeaders,
          body: { success: false, message: 'Invalid code or email.' },
        };
      }
    } catch (err) {
      return {
        status: 400,
        headers: commonHeaders,
        body: { success: false, message: 'Invalid or expired code.' },
      };
    }

    const now = new Date();
    if (new Date(codeRec.expiresAt) <= now || codeRec.used) {
      await resetRequestsTable.deleteEntity('reset', code).catch(() => {});
      return {
        status: 400,
        headers: commonHeaders,
        body: { success: false, message: 'Code has expired or already been used.' },
      };
    }

    const therapistId = codeRec.therapistId;

    // Mark code used
    try {
      await resetRequestsTable.updateEntity(
        {
          partitionKey: 'reset',
          rowKey: code,
          used: true,
          etag: '*'
        },
        'Merge'
      );
    } catch (err) {
      return {
        status: 500,
        headers: commonHeaders,
        body: { success: false, message: 'Server error.' },
      };
    }

    // Fetch user record (we already have therapistId from token validation)
    let user;
    try {
      // Find user by therapistId - need to query since we only have therapistId from token
      const filter = odata`therapistId eq ${therapistId}`;
      for await (const ent of prospectsTable.queryEntities({ filter })) {
        user = ent;
        break;
      }
      if (!user) throw new Error('User not found');
    } catch {
      return {
        status: 400,
        headers: commonHeaders,
        body: { success: false, message: 'Account not found.' },
      };
    }

    // Hash and update password
    try {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await prospectsTable.updateEntity(
        {
          partitionKey: user.email,
          rowKey: user.email,
          hashedPassword,
          etag: '*'
        },
        'Merge'
      );
    } catch (err) {
      return {
        status: 500,
        headers: commonHeaders,
        body: { success: false, message: 'Failed to update password.' },
      };
    }

    // Success
    return {
      status: 200,
      headers: commonHeaders,
      body: { success: true, message: 'Password reset successfully.' },
    };
  }
);