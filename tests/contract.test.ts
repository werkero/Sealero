import assert from 'node:assert/strict'
import test from 'node:test'
import {
  ADMIN_AUDIT_ACTIONS,
  ADMIN_DEVICE_ACTIONS,
  ADMIN_SETTING_FIELDS,
  ADMIN_USER_ACTIONS,
  ADMIN_USER_DEVICE_COLUMNS,
  ADMIN_USER_FILTER_OPTIONS,
  ADMIN_USER_LIST_COLUMNS,
  ADMIN_USER_LOGIN_COLUMNS,
  ADMIN_USER_PASSWORD_ACTIONS,
  sanitizeAuditMetadata,
} from '../src/features/admin/contract.ts'

test('admin settings UI exposes exactly the 13 contract allowlist keys and no retention override', () => {
  assert.deepEqual(ADMIN_SETTING_FIELDS.map(({ key }) => key), [
    'server_name',
    'allow_registration',
    'require_email_verification',
    'max_vault_size_mb',
    'smtp_host',
    'smtp_port',
    'smtp_user',
    'smtp_pass',
    'smtp_from',
    'smtp_secure',
    'min_app_version_android',
    'min_app_version_ios',
    'min_app_version_web',
  ])
  assert.equal(ADMIN_SETTING_FIELDS.length, 13)
  assert.equal(ADMIN_SETTING_FIELDS.some(({ key }) => key === 'tombstone_retention_days'), false)
})

test('SMTP password is classified write-only and never part of the returned settings type', () => {
  const smtpPassword = ADMIN_SETTING_FIELDS.find(({ key }) => key === 'smtp_pass')
  assert.equal(smtpPassword?.kind, 'write-only-secret')
  assert.equal(smtpPassword?.defaultValue, null)
})

test('settings audit metadata contains only unique keys from the settings allowlist', () => {
  assert.deepEqual(sanitizeAuditMetadata('settings_update', {
    keys_changed: ['smtp_host', 'smtp_pass', 'smtp_host', 'password'],
    smtp_pass: 'must-not-render',
    smtp_user: 'also-secret',
  }), { keys_changed: ['smtp_host', 'smtp_pass'] })
})

test('device revoke metadata contains only a valid device UUID', () => {
  const deviceId = '2d647bb6-74b3-4f90-a5b8-4cf5dc41fef0'
  assert.deepEqual(sanitizeAuditMetadata('device_revoke', { device_id: deviceId, token: 'not-allowed' }), { device_id: deviceId })
  assert.deepEqual(sanitizeAuditMetadata('device_revoke', { device_id: 'not-a-uuid' }), {})
})

test('unlisted audit actions and malformed metadata fail closed to an empty object', () => {
  assert.deepEqual(sanitizeAuditMetadata('unknown_action', { metadata: 'private', password: 'secret' }), {})
  assert.deepEqual(sanitizeAuditMetadata('settings_update', null), {})
  assert.deepEqual(sanitizeAuditMetadata('settings_update', { keys_changed: 'smtp_pass' }), {})
})

test('admin user list exposes only the v1.46 aggregate profile fields, never vault entry fields', () => {
  assert.deepEqual(ADMIN_USER_LIST_COLUMNS, [
    'email',
    'created_at',
    'last_login_at',
    'email_verified_at',
    'is_admin',
    'is_super_admin',
    'disabled_at',
    'device_count',
    'ciphertext_total_bytes',
  ])
  assert.equal(ADMIN_USER_LIST_COLUMNS.some((field) => /item|url|password|secret|ciphertext$/.test(field)), false)
})

test('admin user filters match the contract values and are conjunctive', () => {
  assert.deepEqual(ADMIN_USER_FILTER_OPTIONS, {
    status: ['all', 'active', 'disabled'],
    verified: ['all', 'verified', 'unverified'],
    role: ['all', 'admin', 'user'],
  })
})

test('admin user detail tables use only documented device and separate login-history fields', () => {
  assert.deepEqual(ADMIN_USER_DEVICE_COLUMNS, ['device_name', 'device_type', 'created_at', 'last_login_at', 'revoked_at'])
  assert.deepEqual(ADMIN_USER_LOGIN_COLUMNS, ['created_at', 'device_name', 'device_id', 'ip_address', 'user_agent', 'result', 'failure_code'])
})

test('admin user action preview omits super-admin transfer and credential-reset actions', () => {
  assert.deepEqual(ADMIN_USER_ACTIONS, [
    'disable',
    'enable',
    'delete',
    'make_admin',
    'remove_admin',
  ])
  assert.deepEqual(ADMIN_DEVICE_ACTIONS, ['revoke'])
})

test('password-protected user actions are tracked separately from the pinned action list', () => {
  assert.deepEqual(ADMIN_USER_PASSWORD_ACTIONS, ['delete', 'revoke_all_devices'])
  assert.equal((ADMIN_USER_ACTIONS as readonly string[]).includes('revoke_all_devices'), false)
})

test('admin audit action options contain only event types written by current admin routes', () => {
  assert.deepEqual(ADMIN_AUDIT_ACTIONS, [
    'user_disable',
    'user_enable',
    'user_delete',
    'device_revoke',
    'settings_update',
    'make_admin',
    'remove_admin',
  ])
})
