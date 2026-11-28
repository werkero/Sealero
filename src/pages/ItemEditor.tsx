import { useEffect, useState, type FormEvent } from 'react'
import { Lock, ShieldCheck, Tag } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { VaultItem, VaultItemInput } from '../client/contracts'
import { Alert, AlertDescription } from '../components/ui/alert'
import { Button } from '../components/ui/button'
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Checkbox } from '../components/ui/checkbox'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'

function errorCode(error: unknown): string | null {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const code = (error as { code?: unknown }).code
    return typeof code === 'string' ? code : null
  }
  return null
}

/** Create/edit form for one vault item, as a shadcn Card. */
export function ItemEditor({ initial, onSave, onCancel, bare, onSavingChange }: {
  /** Null for a new item; the loaded item when editing (passkey is preserved, not edited). */
  initial: VaultItem | null
  onSave: (input: VaultItemInput) => Promise<void>
  onCancel: () => void
  /** Render only the form, without the Card shell (for use inside a Dialog). */
  bare?: boolean
  /** Reports the saving state, so a parent that renders Save/Cancel outside the form can disable them. */
  onSavingChange?: (saving: boolean) => void
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

  useEffect(() => {
    onSavingChange?.(saving)
  }, [saving, onSavingChange])

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

  const loginFields = (
    <>
      <div className="grid gap-1.5">
        <Label htmlFor="item-name">{t('vault:name')}</Label>
        <Input id="item-name" name="name" type="text" autoComplete="off" value={name} onChange={(event) => setName(event.target.value)} required disabled={saving} />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="item-url">{t('vault:website')}</Label>
        <Input id="item-url" name="url" type="text" autoComplete="off" placeholder="https://" value={url} onChange={(event) => setUrl(event.target.value)} disabled={saving} />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="item-username">{t('vault:usernameLabel')}</Label>
        <Input id="item-username" name="username" type="text" autoComplete="off" value={username} onChange={(event) => setUsername(event.target.value)} disabled={saving} />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="item-password">{t('vault:password')}</Label>
        <div className="relative">
          <Input id="item-password" name="password" type={passwordVisible ? 'text' : 'password'} autoComplete="off" value={password} onChange={(event) => setPassword(event.target.value)} required disabled={saving} className="pr-16" />
          <Button variant="ghost" size="sm" className="absolute right-1 top-1/2 -translate-y-1/2" type="button" onClick={() => setPasswordVisible((visible) => !visible)} aria-label={passwordVisible ? t('common:hide') : t('common:show')} disabled={saving}>
            {passwordVisible ? t('common:hide') : t('common:show')}
          </Button>
        </div>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="item-note">{t('vault:note')}</Label>
        <Textarea id="item-note" name="note" rows={3} value={note} onChange={(event) => setNote(event.target.value)} disabled={saving} />
      </div>
    </>
  )

  const categoryFields = (
    <>
      <div className="grid gap-1.5">
        <Label htmlFor="item-category">{t('vault:category')}</Label>
        <Input id="item-category" name="category" type="text" autoComplete="off" value={category} onChange={(event) => setCategory(event.target.value)} disabled={saving} />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="item-tags">{t('vault:tags')}</Label>
        <Input id="item-tags" name="tags" type="text" autoComplete="off" value={tagsText} onChange={(event) => setTagsText(event.target.value)} disabled={saving} />
        <p className="text-xs leading-relaxed text-muted-foreground">{t('vault:tagsHint')}</p>
      </div>
      <Label htmlFor="item-favorite" className="flex cursor-pointer items-center gap-2 font-normal">
        <Checkbox id="item-favorite" name="favorite" checked={favorite} onCheckedChange={(checked) => setFavorite(checked === true)} disabled={saving} />
        {t('vault:favorite')}
      </Label>
    </>
  )

  const securityFields = (
    <>
      <div className="grid gap-1.5">
        <Label htmlFor="item-totp">{t('vault:totpSecretLabel')}</Label>
        <Input id="item-totp" name="totpSecret" type="text" autoComplete="off" value={totpSecret} onChange={(event) => setTotpSecret(event.target.value)} disabled={saving} />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="item-recovery">{t('vault:recoveryCodesLabel')}</Label>
        <Textarea id="item-recovery" name="recoveryCodes" rows={3} value={recoveryText} onChange={(event) => setRecoveryText(event.target.value)} disabled={saving} />
        <p className="text-xs leading-relaxed text-muted-foreground">{t('vault:recoveryCodesHint')}</p>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="item-mnemonic">{t('vault:mnemonicLabel')}</Label>
        <Textarea id="item-mnemonic" name="mnemonic" rows={2} value={mnemonicText} onChange={(event) => setMnemonicText(event.target.value)} disabled={saving} />
      </div>
    </>
  )

  const saveErrorAlert = saveError ? <Alert variant="destructive"><AlertDescription>{saveError}</AlertDescription></Alert> : null
  const actions = (
    <div className="flex gap-2">
      <Button type="submit" disabled={saving}>{t('vault:saveItem')}</Button>
      <Button variant="outline" type="button" onClick={onCancel} disabled={saving}>{t('vault:cancelEdit')}</Button>
    </div>
  )

  // Dialog mode: a single-column form (the dialog is too narrow for columns).
  if (bare) {
    return (
      <form className="grid gap-4" onSubmit={submit}>
        {loginFields}
        {categoryFields}
        {securityFields}
        {saveErrorAlert}
        {actions}
      </form>
    )
  }

  // Full-page mode: sectioned cards mirroring the detail page —
  // login + category in the main column, security in the sidebar.
  // Save/Cancel live in the top bar (rendered by the parent) and
  // submit this form via its id.
  return (
    <form id="item-editor-form" onSubmit={submit}>
      <div className="grid grid-cols-[minmax(0,1fr)_340px] items-start gap-4 max-[1100px]:grid-cols-1">
        <div className="flex min-w-0 flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle id="login-details-title">{t('vault:loginDetails')}</CardTitle>
              <CardAction><Lock size={16} className="text-muted-foreground" aria-hidden="true" /></CardAction>
            </CardHeader>
            <CardContent className="grid gap-4">{loginFields}</CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>{t('vault:categoryAndTags')}</CardTitle>
              <CardAction><Tag size={16} className="text-muted-foreground" aria-hidden="true" /></CardAction>
            </CardHeader>
            <CardContent className="grid gap-4">{categoryFields}</CardContent>
          </Card>
          {saveErrorAlert}
        </div>
        <div className="flex min-w-0 flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>{t('vault:securitySection')}</CardTitle>
              <CardAction><ShieldCheck size={16} className="text-muted-foreground" aria-hidden="true" /></CardAction>
            </CardHeader>
            <CardContent className="grid gap-4">{securityFields}</CardContent>
          </Card>
        </div>
      </div>
    </form>
  )
}
