import assert from 'node:assert/strict'
import test from 'node:test'

/**
 * Storage helpers for the 15-minute idle lock with refresh persistence
 * (System Design §3.3). The unlock blob lives in sessionStorage (dies
 * with the tab) and the last-activity timestamp in localStorage (shared
 * across tabs, survives refresh). Storage is Map-backed here because
 * node has neither global.
 */

function mapStorage(): { store: Map<string, string>, storage: Storage } {
  const store = new Map<string, string>()
  const storage = {
    get length() { return store.size },
    clear: () => store.clear(),
    getItem: (key: string) => store.get(key) ?? null,
    key: (index: number) => [...store.keys()][index] ?? null,
    removeItem: (key: string) => { store.delete(key) },
    setItem: (key: string, value: string) => { store.set(key, value) },
  } as Storage
  return { store, storage }
}

test('session blob round-trips per user, clears on demand, and corrupt values read as absent', async () => {
  const session = mapStorage()
  const local = mapStorage()
  Object.assign(globalThis, { sessionStorage: session.storage, localStorage: local.storage })
  const mod = await import('../src/hooks/vault-session-storage.ts')
  const blob = {
    dek: 'ZGVr',
    kek: 'a2Vr',
    version: 3,
    record: {
      wrapped_dek: 'w', nonce: 'n', kdf_salt: 's', kdf_params: '{}',
      dek_version: 3, master_password_version: 1, wrapping_state_hash: 'h',
    },
  }

  assert.equal(mod.readUnlockedSession('u1'), null)
  mod.saveUnlockedSession('u1', blob)
  assert.deepEqual(mod.readUnlockedSession('u1'), blob)
  assert.equal(mod.readUnlockedSession('u2'), null)
  mod.clearUnlockedSession('u1')
  assert.equal(mod.readUnlockedSession('u1'), null)

  assert.equal(mod.readLastActiveAt(), null)
  mod.writeLastActiveAt(1_700_000_000_000)
  assert.equal(mod.readLastActiveAt(), 1_700_000_000_000)
  mod.clearLastActiveAt()
  assert.equal(mod.readLastActiveAt(), null)

  local.store.set('sealero.vault.lastActiveAt', 'not-a-number')
  assert.equal(mod.readLastActiveAt(), null)
  session.store.set('sealero.vault.session.u1', '{bad json')
  assert.equal(mod.readUnlockedSession('u1'), null)
  session.store.set('sealero.vault.session.u1', JSON.stringify({ dek: 'x' }))
  assert.equal(mod.readUnlockedSession('u1'), null)
})
