import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SmtpNotifications } from '../services/smtp-notifications.js';

const { sentMails, createTransportMock } = vi.hoisted(() => {
  const sentMails: Array<{ options: unknown; mail: Record<string, unknown> }> = [];
  const createTransportMock = vi.fn((options: unknown) => ({
    sendMail: async (mail: Record<string, unknown>) => {
      sentMails.push({ options, mail });
      return { messageId: 'test-message-id' };
    },
  }));
  return { sentMails, createTransportMock };
});

vi.mock('nodemailer', () => ({ createTransport: createTransportMock }));

const ENV = {
  SMTP_HOST: 'smtp.resend.com',
  SMTP_PORT: '465',
  SMTP_USER: 'resend',
  SMTP_PASS: 're_env_key',
  SMTP_FROM: 'noreply@email.a1l.xyz',
  SMTP_SECURE: 'true',
};

beforeEach(() => {
  sentMails.splice(0);
  createTransportMock.mockClear();
});

describe('SmtpNotifications', () => {
  it('sends a verification code via SMTP with the env settings', async () => {
    const notifications = new SmtpNotifications({ env: ENV });
    await notifications.sendVerificationCode({
      email: 'user@example.com',
      code: '123456',
      expiresAt: new Date(Date.now() + 15 * 60_000),
    });
    expect(createTransportMock).toHaveBeenCalledOnce();
    expect(createTransportMock).toHaveBeenCalledWith({
      host: 'smtp.resend.com',
      port: 465,
      secure: true,
      auth: { user: 'resend', pass: 're_env_key' },
    });
    expect(sentMails).toHaveLength(1);
    const mail = sentMails[0]?.mail as Record<string, unknown>;
    expect(mail['to']).toBe('user@example.com');
    expect(mail['from']).toEqual({ name: 'Sealero', address: 'noreply@email.a1l.xyz' });
    expect(String(mail['subject'])).toContain('verification code');
    expect(String(mail['text'])).toContain('123456');
    expect(String(mail['text'])).toContain('15 minutes');
    expect(String(mail['html'])).toContain('123456');
  });

  it('lets database settings override env (per-key precedence)', async () => {
    const notifications = new SmtpNotifications({
      env: ENV,
      getDatabaseSettings: async () => ({
        smtp_host: 'mail.example.com',
        smtp_port: '587',
        smtp_secure: 'false',
        smtp_from: 'other@example.com',
      }),
    });
    await notifications.sendPasswordResetCode({
      email: 'user@example.com',
      code: '654321',
      expiresAt: new Date(Date.now() + 30 * 60_000),
    });
    expect(createTransportMock).toHaveBeenCalledWith({
      host: 'mail.example.com',
      port: 587,
      secure: false,
      auth: { user: 'resend', pass: 're_env_key' },
    });
    const mail = sentMails[0]?.mail as Record<string, unknown>;
    expect(mail['from']).toEqual({ name: 'Sealero', address: 'other@example.com' });
    expect(String(mail['text'])).toContain('654321');
    expect(String(mail['text'])).toContain('30 minutes');
  });

  it('lets a stored smtp_pass override the env password', async () => {
    const notifications = new SmtpNotifications({
      env: ENV,
      getDatabaseSettings: async () => ({ smtp_pass: 'db-stored-pass' }),
    });
    await notifications.sendDeleteAccountCode({
      email: 'user@example.com',
      code: '000999',
      expiresAt: new Date(Date.now() + 15 * 60_000),
    });
    expect(createTransportMock).toHaveBeenCalledWith({
      host: 'smtp.resend.com',
      port: 465,
      secure: true,
      auth: { user: 'resend', pass: 'db-stored-pass' },
    });
  });

  it('fails closed when SMTP is not configured', async () => {
    const notifications = new SmtpNotifications({ env: {} });
    await expect(notifications.sendVerificationCode({
      email: 'user@example.com',
      code: '123456',
      expiresAt: new Date(Date.now() + 15 * 60_000),
    })).rejects.toThrow('SMTP is not configured');
    expect(sentMails).toHaveLength(0);
  });

  it('fails closed when smtp_user has no password', async () => {
    const { SMTP_PASS: _omitted, ...envWithoutPass } = ENV;
    const notifications = new SmtpNotifications({
      env: envWithoutPass,
    });
    await expect(notifications.sendVerificationCode({
      email: 'user@example.com',
      code: '123456',
      expiresAt: new Date(Date.now() + 15 * 60_000),
    })).rejects.toThrow('smtp_user requires smtp_pass');
  });

  it('sends new-device and reuse alerts with device context', async () => {
    const notifications = new SmtpNotifications({ env: ENV });
    await notifications.sendNewDeviceLogin({
      email: 'user@example.com',
      userId: 'user-1',
      deviceId: 'device-1',
      deviceName: 'Tai’s MacBook',
      occurredAt: new Date('2026-11-26T08:00:00.000Z'),
    });
    await notifications.sendRefreshReuseAlert({
      email: 'user@example.com',
      userId: 'user-1',
      deviceId: 'device-1',
      occurredAt: new Date('2026-11-26T08:05:00.000Z'),
    });
    expect(sentMails).toHaveLength(2);
    expect(String(sentMails[0]?.mail['subject'])).toContain('New sign-in');
    expect(String(sentMails[0]?.mail['text'])).toContain('Tai’s MacBook');
    expect(String(sentMails[1]?.mail['subject'])).toContain('Security alert');
  });

  it('reuses one transport per settings set', async () => {
    const notifications = new SmtpNotifications({ env: ENV });
    const at = new Date(Date.now() + 15 * 60_000);
    await notifications.sendVerificationCode({ email: 'a@example.com', code: '111111', expiresAt: at });
    await notifications.sendVerificationCode({ email: 'b@example.com', code: '222222', expiresAt: at });
    expect(createTransportMock).toHaveBeenCalledOnce();
    expect(sentMails).toHaveLength(2);
  });
});
