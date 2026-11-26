import { useEffect, useState } from 'react'
import { ArrowUpRight, Info, KeyRound, Lock, Star } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { VaultIdentity, VaultItem, VaultItemInput, VaultListItem } from '../client/contracts'
import { PasswordHealthInline } from '../features/password-security/PasswordSecurity'
import { CopyIcon, SecretRow, VaultLayout, hostname, iconTone } from '../App'
import type { AppearancePreference } from '../features/settings/preferences'
import { ItemEditor } from './ItemEditor'
import { Button } from '../components/ui/button'

export function ItemDetail({ user, item, itemCount, items, isAdmin, loadItem, onNavigate, onLock, onLogout, appearancePreference, onAppearanceChange, onCopy, onUpdateItem, onDeleteItem }: {
  user: VaultIdentity
  item: VaultItem
  itemCount: number
  items: VaultListItem[]
  isAdmin?: boolean
  loadItem: (itemId: string) => Promise<VaultItem>
  onNavigate: (path: string) => void
  onLock: () => void
  onLogout: () => void
  appearancePreference: AppearancePreference
  onAppearanceChange: (preference: AppearancePreference) => void
  onCopy: (value: string, label: string) => void
  onUpdateItem: (itemId: string, input: VaultItemInput) => Promise<VaultItem | null>
  onDeleteItem: (itemId: string) => Promise<boolean>
}) {
  const { t } = useTranslation(['common', 'vault'])
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [totp, setTotp] = useState('------')
  const [totpSeconds, setTotpSeconds] = useState(30)
  const [recoveryVisible, setRecoveryVisible] = useState(false)
  // Marking a code used is session-only UI state; it is never written to the stored item.
  const [usedCodes, setUsedCodes] = useState<Set<string>>(() => new Set<string>())
  const [mnemonicVisible, setMnemonicVisible] = useState(false)
  const [editing, setEditing] = useState(false)
  const [confirmingDelete, setConfirmingDelete] = useState(false)
  const [deleteFailed, setDeleteFailed] = useState(false)

  useEffect(() => {
    if (!item.totpSecret) return
    let lastStep = -1
    let active = true

    const updateTotp = async () => {
      const nowSeconds = Math.floor(Date.now() / 1000)
      const step = Math.floor(nowSeconds / 30)
      setTotpSeconds(30 - (nowSeconds % 30))
      if (step === lastStep) return
      lastStep = step
      const nextCode = await generateTotp(item.totpSecret!)
      if (active) setTotp(nextCode)
    }

    void updateTotp()
    const timer = window.setInterval(() => void updateTotp(), 1000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [item.id, item.totpSecret])

  const remainingCodes = (item.recoveryCodes?.length ?? 0) - usedCodes.size

  if (editing) {
    return (
      <VaultLayout user={user} filter="all" itemCount={itemCount} isAdmin={isAdmin} onFilterChange={() => onNavigate(`/users/${user.id}`)} onNavigate={onNavigate} onLock={onLock} onLogout={onLogout} appearancePreference={appearancePreference} onAppearanceChange={onAppearanceChange}>
        <div className="detail-content">
          <button className="back-button detail-back" type="button" onClick={() => setEditing(false)}><span aria-hidden="true">←</span>{t('vault:backToVault')}</button>
          <ItemEditor
            initial={item}
            onSave={async (input) => {
              const updated = await onUpdateItem(item.id, input)
              if (updated) {
                setEditing(false)
                window.dispatchEvent(new CustomEvent('sealero:toast', { detail: t('vault:itemUpdated') }))
              }
            }}
            onCancel={() => setEditing(false)}
          />
        </div>
      </VaultLayout>
    )
  }

  return (
    <VaultLayout user={user} filter="all" itemCount={itemCount} isAdmin={isAdmin} onFilterChange={() => onNavigate(`/users/${user.id}`)} onNavigate={onNavigate} onLock={onLock} onLogout={onLogout} appearancePreference={appearancePreference} onAppearanceChange={onAppearanceChange}>
      <div className="detail-content">
        <button className="back-button detail-back" type="button" onClick={() => onNavigate(`/users/${user.id}`)}><span aria-hidden="true">←</span>{t('vault:backToVault')}</button>
        <div className="detail-title-row">
          <span className={`detail-app-icon ${iconTone(item.icon)}`}>{item.icon}</span>
          <div className="detail-title-copy">
            <p className="eyebrow">{t('vault:detailEyebrow')}</p>
            <h1>{item.name}</h1>
            <a href={item.url} target="_blank" rel="noreferrer" className="detail-website">{hostname(item.url)}<span aria-hidden="true"><ArrowUpRight size={12} aria-hidden="true" /></span></a>
          </div>
          {item.favorite ? <span className="detail-favorite-pill"><Star size={10} aria-hidden="true" /> {t('vault:favorite')}</span> : null}
        </div>
        <div className="security-list-actions">
          <Button className="security-button" type="button" onClick={() => setEditing(true)}>{t('vault:editItem')}</Button>
          {confirmingDelete ? (
            <>
              <span className="inline-warning" role="alert">{t('vault:deleteItemConfirm')}</span>
              <Button
                variant="destructive"
                className="security-button"
                type="button"
                onClick={() => {
                  void onDeleteItem(item.id).then((deleted) => {
                    if (deleted) {
                      window.dispatchEvent(new CustomEvent('sealero:toast', { detail: t('vault:itemDeleted') }))
                    } else {
                      setDeleteFailed(true)
                      setConfirmingDelete(false)
                    }
                  }).catch(() => {
                    setDeleteFailed(true)
                    setConfirmingDelete(false)
                  })
                }}
              >{t('vault:confirmDelete')}</Button>
              <Button className="security-button security-button--quiet" type="button" onClick={() => setConfirmingDelete(false)}>{t('vault:cancelEdit')}</Button>
            </>
          ) : (
            <Button className="security-button security-button--quiet" type="button" onClick={() => { setDeleteFailed(false); setConfirmingDelete(true) }}>{t('vault:deleteItem')}</Button>
          )}
          {deleteFailed ? <span className="inline-warning" role="alert">{t('vault:deleteFailed')}</span> : null}
        </div>
        <div className="detail-grid">
          <section className="detail-card" aria-labelledby="login-details-title">
            <div className="detail-card-heading"><div><h2 id="login-details-title">{t('vault:loginDetails')}</h2><p>{t('vault:loginDetailsSubtitle')}</p></div><span className="detail-card-lock" aria-hidden="true"><Lock size={16} aria-hidden="true" /></span></div>
            <div className="detail-fields">
              <SecretRow label={t('vault:username')} value={item.username} maskedValue={item.username} onCopy={() => onCopy(item.username, t('vault:username'))} copyLabel={t('vault:username')} />
              <SecretRow
                label={t('vault:password')}
                value={item.password}
                maskedValue="••••••••••••••••"
                visible={passwordVisible}
                onToggle={() => setPasswordVisible((visible) => !visible)}
                onCopy={() => onCopy(item.password, t('vault:password'))}
                copyLabel={t('vault:password')}
              />
              <PasswordHealthInline itemId={item.id} password={item.password} itemName={item.name} items={items} loadItem={loadItem} />
              <div className="detail-field detail-field-url">
                <div className="detail-field-label">{t('vault:website')}</div>
                <a className="detail-field-url-value" href={item.url} target="_blank" rel="noreferrer">{item.url}<span aria-hidden="true"><ArrowUpRight size={12} aria-hidden="true" /></span></a>
                <span className="detail-field-actions"><button className="copy-button" type="button" onClick={() => onCopy(item.url, t('vault:website'))} aria-label={`${t('common:copy')} ${t('vault:website')}`}><CopyIcon /></button></span>
              </div>
              <div className="detail-field detail-note-field"><div className="detail-field-label">{t('vault:note')}</div><p>{item.note || t('vault:noNotes')}</p></div>
            </div>
            <div className="detail-metadata"><span><span>{t('vault:category')}</span>{item.category}</span><span><span>{t('vault:tags')}</span>{item.tags.map((tag) => <i key={tag}>{tag}</i>)}</span></div>
          </section>
          <div className="detail-secondary-column">
            {item.totpSecret ? (
              <section className="detail-card compact-detail-card" aria-labelledby="totp-title">
                <div className="detail-card-heading"><div><h2 id="totp-title">{t('vault:authenticatorCode')}</h2><p>{t('vault:totpSubtitle')}</p></div><span className="totp-badge">{t('vault:totp')}</span></div>
                <div className="totp-code-row"><strong aria-live="polite">{totp}</strong><span className="totp-countdown">{totpSeconds}<small>s</small></span><button className="copy-button" type="button" onClick={() => onCopy(totp, t('vault:authenticatorCode'))} aria-label={`${t('common:copy')} ${t('vault:authenticatorCode')}`}><CopyIcon /></button></div>
                <div className="totp-progress"><span style={{ width: `${(totpSeconds / 30) * 100}%` }} /></div>
              </section>
            ) : null}
            {item.passkey ? (
              <section className="detail-card compact-detail-card" aria-labelledby="passkey-title">
                <div className="detail-card-heading"><div><h2 id="passkey-title">{t('vault:passkey')}</h2><p>{t('vault:passkeySubtitle')}</p></div><span className="passkey-symbol" aria-hidden="true"><KeyRound size={16} aria-hidden="true" /></span></div>
                <div className="passkey-info"><span>{t('vault:relyingParty')}</span><strong>{item.passkey.rpId}</strong><span>{t('vault:credentialId')}</span><code>{item.passkey.credentialId}</code><span>{t('vault:publicKey')}</span><code className="public-key-value">{item.passkey.publicKey}</code></div>
                <p className="security-note"><span aria-hidden="true"><Info size={12} aria-hidden="true" /></span>{t('vault:privateKeyNeverSaved')}</p>
              </section>
            ) : null}
            {item.recoveryCodes?.length ? (
              <section className="detail-card compact-detail-card" aria-labelledby="recovery-title">
                <div className="detail-card-heading"><div><h2 id="recovery-title">{t('vault:recoveryCodes')}</h2><p>{t('vault:remainingCodes', { count: remainingCodes })}</p></div><button className="quiet-button" type="button" onClick={() => setRecoveryVisible((visible) => !visible)}>{recoveryVisible ? t('common:hide') : t('common:show')}</button></div>
                <div className="recovery-list">
                  {item.recoveryCodes.map((code) => {
                    const isUsed = usedCodes.has(code.id)
                    return (
                      <div className={`recovery-row ${isUsed ? 'is-used' : ''}`} key={code.id}>
                        <span className="recovery-code">{recoveryVisible ? code.value : '•••• •••• ••••'}</span>
                        <button className="recovery-use-button" type="button" onClick={() => { const nextUsed = !usedCodes.has(code.id); setUsedCodes((current) => { const next = new Set(current); if (nextUsed) next.add(code.id); else next.delete(code.id); return next }) }} aria-pressed={isUsed}>{isUsed ? t('vault:used') : t('vault:markUsed')}</button>
                        <button className="copy-button" type="button" onClick={() => onCopy(code.value, t('vault:recoveryCode'))} aria-label={`${t('common:copy')} ${t('vault:recoveryCode')}`}><CopyIcon /></button>
                      </div>
                    )
                  })}
                </div>
                <p className="security-note warning-note">{t('vault:recoveryCodePreviewNote')}</p>
              </section>
            ) : null}
            {item.mnemonic?.length ? (
              <section className="detail-card compact-detail-card" aria-labelledby="mnemonic-title">
                <div className="detail-card-heading"><div><h2 id="mnemonic-title">{t('vault:mnemonic')}</h2><p>{t('vault:mnemonicSubtitle', { count: item.mnemonic.length })}</p></div><button className="quiet-button" type="button" onClick={() => setMnemonicVisible((visible) => !visible)}>{mnemonicVisible ? t('common:hide') : t('common:show')}</button></div>
                <div className="mnemonic-grid">
                  {item.mnemonic.map((word, index) => <div className="mnemonic-word" key={`${word}-${index}`}><span>{index + 1}</span><strong>{mnemonicVisible ? word : '••••••'}</strong><button type="button" className="word-copy" onClick={() => onCopy(word, `${t('vault:mnemonic')} ${index + 1}`)} aria-label={`${t('common:copy')} ${t('vault:mnemonic')} ${index + 1}`}><CopyIcon /></button></div>)}
                </div>
                <button className="mnemonic-copy-all" type="button" onClick={() => onCopy(item.mnemonic!.join(' '), t('vault:mnemonic'))}><CopyIcon />{t('vault:copyPhrase')}</button>
                <p className="security-note warning-note"><span aria-hidden="true">!</span>{t('vault:mnemonicRisk')}</p>
              </section>
            ) : null}
          </div>
        </div>
        <p className="detail-footnote"><span aria-hidden="true"><Info size={12} aria-hidden="true" /></span>{t('vault:clipboardAutoClear')}</p>
      </div>
    </VaultLayout>
  )
}

function base32ToBytes(value: string) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const character of value.replace(/=+$/g, '').toUpperCase()) {
    const position = alphabet.indexOf(character)
    if (position < 0) throw new Error('invalid_totp_secret')
    bits += position.toString(2).padStart(5, '0')
  }
  const bytes: number[] = []
  for (let cursor = 0; cursor + 8 <= bits.length; cursor += 8) {
    bytes.push(Number.parseInt(bits.slice(cursor, cursor + 8), 2))
  }
  return new Uint8Array(bytes)
}

async function generateTotp(secret: string) {
  try {
    const counter = Math.floor(Date.now() / 30_000)
    const counterBytes = new Uint8Array(8)
    new DataView(counterBytes.buffer).setBigUint64(0, BigInt(counter))
    const key = await crypto.subtle.importKey('raw', base32ToBytes(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
    const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes))
    const offset = signature[signature.length - 1] & 0x0f
    const binary = ((signature[offset] & 0x7f) << 24) | ((signature[offset + 1] & 0xff) << 16) | ((signature[offset + 2] & 0xff) << 8) | (signature[offset + 3] & 0xff)
    return (binary % 1_000_000).toString().padStart(6, '0')
  } catch {
    return '------'
  }
}
