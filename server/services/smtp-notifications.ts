import { createTransport, type Transporter } from 'nodemailer';
import type { AuthNotification } from '../auth/types.js';

/**
 * SMTP `AuthNotification` (System Design §8). Plain SMTP only — no Resend
 * SDK, no Resend HTTP API. The official cloud points it at Resend SMTP
 * (smtp.resend.com:465, user `resend`, password = Resend API key), but any
 * SMTP provider works: these are just the standard SMTP settings.
 *
 * Settings precedence follows System Design §8: values stored in the
 * `server_settings` table (changed via the admin console) override the
 * environment defaults. Settings are re-resolved on every send, so an admin
 * change applies without a restart.
 */
export interface SmtpEnvironment {
  readonly SMTP_HOST?: string;
  readonly SMTP_PORT?: string;
  readonly SMTP_USER?: string;
  readonly SMTP_PASS?: string;
  readonly SMTP_FROM?: string;
  readonly SMTP_SECURE?: string;
}

export interface SmtpNotificationOptions {
  /** Defaults to `process.env`. */
  readonly env?: SmtpEnvironment;
  /**
   * Reads the `server_settings` rows. When provided, DB values override env
   * for smtp_host / smtp_port / smtp_user / smtp_pass / smtp_from /
   * smtp_secure. A failed read falls back to env so one bad query cannot
   * block all mail.
   */
  readonly getDatabaseSettings?: () => Promise<Readonly<Record<string, string>>>;
  /** Injected transport (tests). When set, no real SMTP connection is made. */
  readonly transport?: Transporter;
  /** Display name for the From header. Default `Sealero`. */
  readonly fromName?: string;
}

interface ResolvedSmtp {
  readonly host: string;
  readonly port: number;
  readonly user: string | null;
  readonly pass: string | null;
  readonly from: string;
  readonly secure: boolean;
}

function parsePort(raw: string | undefined): number | null {
  if (raw === undefined || raw.trim() === '') return null;
  if (!/^[0-9]+$/.test(raw.trim())) return null;
  const port = Number(raw.trim());
  return port >= 1 && port <= 65535 ? port : null;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

export class SmtpNotifications implements AuthNotification {
  private readonly env: SmtpEnvironment;
  private readonly getDatabaseSettings:
    | (() => Promise<Readonly<Record<string, string>>>)
    | undefined;
  private readonly injectedTransport: Transporter | undefined;
  private readonly fromName: string;
  private cachedTransport?: { readonly key: string; readonly transport: Transporter };

  constructor(options: SmtpNotificationOptions = {}) {
    this.env = options.env ?? process.env;
    this.getDatabaseSettings = options.getDatabaseSettings;
    this.injectedTransport = options.transport;
    this.fromName = options.fromName ?? 'Sealero';
  }

  async sendVerificationCode(input: {
    readonly email: string;
    readonly code: string;
    readonly expiresAt: Date;
  }): Promise<void> {
    const minutes = this.expiryMinutes(input.expiresAt);
    await this.sendMail({
      to: input.email,
      subject: 'Your Sealero verification code',
      text:
        `Your Sealero verification code is ${input.code}.\n\n` +
        `It expires in ${minutes} minutes. If you did not request this, ignore this email.`,
      html:
        `<p>Your Sealero verification code is <strong>${input.code}</strong>.</p>` +
        `<p>It expires in ${minutes} minutes. If you did not request this, ignore this email.</p>`,
    });
  }

  async sendPasswordResetCode(input: {
    readonly email: string;
    readonly code: string;
    readonly expiresAt: Date;
  }): Promise<void> {
    const minutes = this.expiryMinutes(input.expiresAt);
    await this.sendMail({
      to: input.email,
      subject: 'Reset your Sealero login password',
      text:
        `Your Sealero password reset code is ${input.code}.\n\n` +
        `It expires in ${minutes} minutes. If you did not request this, ignore this email. ` +
        `Your vault and master password are not affected.`,
      html:
        `<p>Your Sealero password reset code is <strong>${input.code}</strong>.</p>` +
        `<p>It expires in ${minutes} minutes. If you did not request this, ignore this email. ` +
        `Your vault and master password are not affected.</p>`,
    });
  }

  async sendDeleteAccountCode(input: {
    readonly email: string;
    readonly code: string;
    readonly expiresAt: Date;
  }): Promise<void> {
    const minutes = this.expiryMinutes(input.expiresAt);
    await this.sendMail({
      to: input.email,
      subject: 'Confirm deleting your Sealero account',
      text:
        `Your Sealero account deletion code is ${input.code}.\n\n` +
        `It expires in ${minutes} minutes. Deleting your account is immediate and permanent. ` +
        `If you did not request this, ignore this email and change your login password.`,
      html:
        `<p>Your Sealero account deletion code is <strong>${input.code}</strong>.</p>` +
        `<p>It expires in ${minutes} minutes. Deleting your account is immediate and permanent. ` +
        `If you did not request this, ignore this email and change your login password.</p>`,
    });
  }

  async sendNewDeviceLogin(input: {
    readonly email: string;
    readonly userId: string;
    readonly deviceId: string;
    readonly deviceName: string;
    readonly occurredAt: Date;
  }): Promise<void> {
    const when = input.occurredAt.toISOString();
    await this.sendMail({
      to: input.email,
      subject: 'New sign-in to your Sealero account',
      text:
        `A new device signed in to your Sealero account.\n\n` +
        `Device: ${input.deviceName}\nTime: ${when}\n\n` +
        `If this was not you, change your login password and revoke the device in Settings.`,
      html:
        `<p>A new device signed in to your Sealero account.</p>` +
        `<p>Device: ${escapeHtml(input.deviceName)}<br>Time: ${when}</p>` +
        `<p>If this was not you, change your login password and revoke the device in Settings.</p>`,
    });
  }

  async sendRefreshReuseAlert(input: {
    readonly email: string;
    readonly userId: string;
    readonly deviceId: string;
    readonly occurredAt: Date;
  }): Promise<void> {
    const when = input.occurredAt.toISOString();
    await this.sendMail({
      to: input.email,
      subject: 'Security alert: your Sealero session was reused',
      text:
        `A refresh token for your Sealero account was used twice, which should not happen.\n\n` +
        `Time: ${when}\n\n` +
        `All sessions on the affected device were revoked as a precaution. ` +
        `If this was not you, change your login password immediately.`,
      html:
        `<p>A refresh token for your Sealero account was used twice, which should not happen.</p>` +
        `<p>Time: ${when}</p>` +
        `<p>All sessions on the affected device were revoked as a precaution. ` +
        `If this was not you, change your login password immediately.</p>`,
    });
  }

  private expiryMinutes(expiresAt: Date): number {
    return Math.max(1, Math.round((expiresAt.getTime() - Date.now()) / 60_000));
  }

  private async resolveSettings(): Promise<ResolvedSmtp> {
    let host = this.env['SMTP_HOST']?.trim() || null;
    let port = parsePort(this.env['SMTP_PORT']);
    let user = this.env['SMTP_USER']?.trim() || null;
    let pass = this.env['SMTP_PASS'] !== undefined && this.env['SMTP_PASS'] !== ''
      ? this.env['SMTP_PASS']
      : null;
    let from = this.env['SMTP_FROM']?.trim() || null;
    let secure = this.env['SMTP_SECURE']?.trim().toLowerCase() === 'true';

    if (this.getDatabaseSettings !== undefined) {
      let database: Readonly<Record<string, string>> = {};
      try {
        database = await this.getDatabaseSettings();
      } catch {
        // Fall back to env; a failed settings read must not block all mail.
        console.error(JSON.stringify({ level: 'error', event: 'smtp_settings_read_failed' }));
      }
      if (database['smtp_host'] !== undefined) host = database['smtp_host'].trim() || null;
      if (database['smtp_port'] !== undefined) port = parsePort(database['smtp_port']);
      if (database['smtp_user'] !== undefined) user = database['smtp_user'].trim() || null;
      if (database['smtp_pass'] !== undefined) {
        pass = database['smtp_pass'] !== '' ? database['smtp_pass'] : null;
      }
      if (database['smtp_from'] !== undefined) from = database['smtp_from'].trim() || null;
      if (database['smtp_secure'] !== undefined) {
        secure = database['smtp_secure'].trim().toLowerCase() === 'true';
      }
    }

    if (host === null || port === null || from === null) {
      throw new Error('SMTP is not configured: smtp_host, smtp_port and smtp_from are required.');
    }
    if (user !== null && pass === null) {
      throw new Error('SMTP is not configured: smtp_user requires smtp_pass.');
    }
    return { host, port, user, pass, from, secure };
  }

  private transportFor(settings: ResolvedSmtp): Transporter {
    if (this.injectedTransport !== undefined) return this.injectedTransport;
    const key = JSON.stringify({
      host: settings.host,
      port: settings.port,
      user: settings.user,
      secure: settings.secure,
    });
    if (this.cachedTransport !== undefined && this.cachedTransport.key === key) {
      return this.cachedTransport.transport;
    }
    const transport = createTransport({
      host: settings.host,
      port: settings.port,
      secure: settings.secure,
      auth: settings.user === null
        ? undefined
        : { user: settings.user, pass: settings.pass ?? '' },
    });
    this.cachedTransport = { key, transport };
    return transport;
  }

  private async sendMail(input: {
    readonly to: string;
    readonly subject: string;
    readonly text: string;
    readonly html: string;
  }): Promise<void> {
    const settings = await this.resolveSettings();
    const transport = this.transportFor(settings);
    await transport.sendMail({
      from: { name: this.fromName, address: settings.from },
      to: input.to,
      subject: input.subject,
      text: input.text,
      html: input.html,
    });
  }
}
