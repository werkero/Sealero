import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import type { VaultItem, VaultItemInput } from '../client/contracts'

function errorCode(error: unknown): string | null {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const code = (error as { code?: unknown }).code
    return typeof code === 'string' ? code : null
  }
  return null
}

/** Create/edit form for one vault item, in the existing detail-card style. */
export function ItemEditor({ initial, onSave, onCancel }: {
  /** Null for a new item; the loaded item when editing (passkey is preserved, not edited). */
  initial: VaultItem | null
  onSave: (input: VaultItemInput) => Promise<void>
  onCancel: () => void
}) {
  const { t } = useTranslation(['common', 'vault'])
  const [name, setName] = useState(initial?.name ?? '')
  const [url, setUrl] = useState(initial?.url ?? '')
  const [username, setUsername] = useState(initial?.username ?? '')
  const [password, setPassword] = useState(initial?.password ?? '')
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [note, setNote] = useState(initial?.note ?? '')
  const [category, setCategory] = useState(initial?.category ?? '')
  const [tagsText, setTagsText] = useState(initial?.tags.join(', ') ?? '')
  const [favorite, setFavorite] = useState(initial?.favorite ?? false)
  const [totpSecret, setTotpSecret] = useState(initial?.totpSecret ?? '')
  const [recoveryText, setRecoveryText] = useState(initial?.recoveryCodes?.map((code) => code.value).join('\n') ?? '')
  const [mnemonicText, setMnemonicText] = useState(initial?.mnemonic?.join(' ') ?? '')
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (saving) return
    const trimmedName = name.trim()
    if (!trimmedName) return
    setSaving(true)
    setSaveError(null)
    const input: VaultItemInput = {
      name: trimmedName,
      url: url.trim(),
      username: username.trim(),
      password,
      note,
      category: category.trim(),
      tags: tagsText.split(',').map((tag) => tag.trim()).filter(Boolean),
      favorite,
      icon: trimmedName.slice(0, 1).toUpperCase(),
      ...(totpSecret.trim() ? { totpSecret: totpSecret.trim() } : {}),
      ...(initial?.passkey ? { passkey: initial.passkey } : {}),
      ...(recoveryText.trim()
        ? { recoveryCodes: recoveryText.split('\n').map((value) => value.trim()).filter(Boolean).map((value) => ({ id: crypto.randomUUID(), value })) }
        : {}),
      ...(mnemonicText.trim() ? { mnemonic: mnemonicText.split(/\s+/).filter(Boolean) } : {}),
    }
    try {
      await onSave(input)
    } catch (error) {
      setSaveError(errorCode(error) === 'conflict' ? t('vault:conflictMessage') : t('vault:saveFailed'))
      setSaving(false)
    }
  }

  return (
    <section className="detail-card" aria-labelledby="item-editor-title">
      <div className="detail-card-heading">
        <div>
          <h2 id="item-editor-title">{initial ? t('vault:editItem') : t('vault:newItem')}</h2>
          <p>{initial ? initial.name : t('vault:collectionSubtitle')}</p>
        </div>
      </div>
      <form className="auth-form" onSubmit={submit}>
        <label className="field-label" htmlFor="item-name">{t('vault:name')}</label>
        <input className="text-input" id="item-name" name="name" type="text" autoComplete="off" value={name} onChange={(event) => setName(event.target.value)} required disabled={saving} />
        <label className="field-label" htmlFor="item-url">{t('vault:website')}</label>
        <input className="text-input" id="item-url" name="url" type="text" autoComplete="off" placeholder="https://" value={url} onChange={(event) => setUrl(event.target.value)} disabled={saving} />
        <label className="field-label" htmlFor="item-username">{t('vault:username')}</label>
        <input className="text-input" id="item-username" name="username" type="text" autoComplete="off" value={username} onChange={(event) => setUsername(event.target.value)} disabled={saving} />
        <label className="field-label" htmlFor="item-password">{t('vault:password')}</label>
        <div className="password-input-wrap">
          <input className="text-input" id="item-password" name="password" type={passwordVisible ? 'text' : 'password'} autoComplete="off" value={password} onChange={(event) => setPassword(event.target.value)} required disabled={saving} />
          <button className="input-action" type="button" onClick={() => setPasswordVisible((visible) => !visible)} aria-label={passwordVisible ? t('common:hide') : t('common:show')} disabled={saving}>
            {passwordVisible ? t('common:hide') : t('common:show')}
          </button>
        </div>
        <label className="field-label" htmlFor="item-note">{t('vault:note')}</label>
        <textarea className="text-input" id="item-note" name="note" rows={3} value={note} onChange={(event) => setNote(event.target.value)} disabled={saving} />
        <label className="field-label" htmlFor="item-category">{t('vault:category')}</label>
        <input className="text-input" id="item-category" name="category" type="text" autoComplete="off" value={category} onChange={(event) => setCategory(event.target.value)} disabled={saving} />
        <label className="field-label" htmlFor="item-tags">{t('vault:tags')}</label>
        <input className="text-input" id="item-tags" name="tags" type="text" autoComplete="off" value={tagsText} onChange={(event) => setTagsText(event.target.value)} disabled={saving} />
        <p className="field-hint">{t('vault:tagsHint')}</p>
        <label className="field-label" htmlFor="item-totp">{t('vault:totpSecretLabel')}</label>
        <input className="text-input" id="item-totp" name="totpSecret" type="text" autoComplete="off" value={totpSecret} onChange={(event) => setTotpSecret(event.target.value)} disabled={saving} />
        <label className="field-label" htmlFor="item-recovery">{t('vault:recoveryCodesLabel')}</label>
        <textarea className="text-input" id="item-recovery" name="recoveryCodes" rows={3} value={recoveryText} onChange={(event) => setRecoveryText(event.target.value)} disabled={saving} />
        <p className="field-hint">{t('vault:recoveryCodesHint')}</p>
        <label className="field-label" htmlFor="item-mnemonic">{t('vault:mnemonicLabel')}</label>
        <textarea className="text-input" id="item-mnemonic" name="mnemonic" rows={2} value={mnemonicText} onChange={(event) => setMnemonicText(event.target.value)} disabled={saving} />
        <label className="field-label" htmlFor="item-favorite">
          <input id="item-favorite" name="favorite" type="checkbox" checked={favorite} onChange={(event) => setFavorite(event.target.checked)} disabled={saving} />
          {' '}{t('vault:favorite')}
        </label>
        {saveError ? <p className="inline-warning" role="alert">{saveError}</p> : null}
        <div className="detail-card-heading">
          <button className="button button-primary" type="submit" disabled={saving}>{t('vault:saveItem')}</button>
          <button className="quiet-button" type="button" onClick={onCancel} disabled={saving}>{t('vault:cancelEdit')}</button>
        </div>
      </form>
    </section>
  )
}
