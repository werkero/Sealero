import { useEffect, useState } from 'react'
import { ArrowUpRight, ChevronLeft, Info, KeyRound, Lock, Star } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { VaultIdentity, VaultItem, VaultItemInput, VaultListItem } from '../client/contracts'
import { PasswordHealthInline } from '../features/password-security/PasswordSecurity'
import { CopyIcon, SecretRow, VaultLayout, hostname, iconTone } from '../App'
import type { AppearancePreference } from '../features/settings/preferences'
import { ItemEditor } from './ItemEditor'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'

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
        <div className="w-full space-y-4 px-[clamp(20px,4vw,48px)] pb-10 pt-8">
          <Button variant="ghost" className="w-fit" type="button" onClick={() => setEditing(false)}><ChevronLeft size={16} aria-hidden="true" />{t('vault:backToVault')}</Button>
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
      <div className="w-full space-y-4 px-[clamp(20px,4vw,48px)] pb-10 pt-8">
        <Button variant="ghost" className="w-fit" type="button" onClick={() => onNavigate(`/users/${user.id}`)}><ChevronLeft size={16} aria-hidden="true" />{t('vault:backToVault')}</Button>
        <div className="flex items-start gap-4">
          <span className={`grid size-[54px] shrink-0 place-items-center rounded-[15px] text-xl font-bold ${iconTone(item.icon)}`}>{item.icon}</span>
          <div className="min-w-0 flex-1">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{t('vault:detailEyebrow')}</p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight text-foreground">{item.name}</h1>
            <a href={item.url} target="_blank" rel="noreferrer" className="mt-1 inline-flex items-center gap-1 text-sm text-primary hover:underline">{hostname(item.url)}<ArrowUpRight size={12} aria-hidden="true" /></a>
          </div>
          {item.favorite ? <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-muted px-2.5 py-1 text-xs font-medium text-muted-foreground"><Star size={10} aria-hidden="true" /> {t('vault:favorite')}</span> : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" onClick={() => setEditing(true)}>{t('vault:editItem')}</Button>
          {confirmingDelete ? (
            <>
              <span className="text-xs font-medium text-destructive" role="alert">{t('vault:deleteItemConfirm')}</span>
              <Button
                variant="destructive"
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
              <Button variant="outline" type="button" onClick={() => setConfirmingDelete(false)}>{t('vault:cancelEdit')}</Button>
            </>
          ) : (
            <Button variant="outline" type="button" onClick={() => { setDeleteFailed(false); setConfirmingDelete(true) }}>{t('vault:deleteItem')}</Button>
          )}
          {deleteFailed ? <span className="text-xs font-medium text-destructive" role="alert">{t('vault:deleteFailed')}</span> : null}
        </div>
        <div className="grid grid-cols-[minmax(0,1fr)_340px] items-start gap-4 max-[1100px]:grid-cols-1">
          <Card>
            <CardHeader>
              <CardTitle id="login-details-title">{t('vault:loginDetails')}</CardTitle>
              <CardDescription>{t('vault:loginDetailsSubtitle')}</CardDescription>
              <CardAction><Lock size={16} className="text-muted-foreground" aria-hidden="true" /></CardAction>
            </CardHeader>
            <CardContent className="grid gap-4">
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
              <div className="grid gap-1">
                <div className="text-xs font-medium text-muted-foreground">{t('vault:website')}</div>
                <div className="flex items-center gap-2">
                  <a className="min-w-0 flex-1 truncate text-sm text-primary hover:underline" href={item.url} target="_blank" rel="noreferrer">{item.url}<ArrowUpRight size={12} className="ml-1 inline" aria-hidden="true" /></a>
                  <Button variant="ghost" size="icon" className="size-7 shrink-0" type="button" onClick={() => onCopy(item.url, t('vault:website'))} aria-label={`${t('common:copy')} ${t('vault:website')}`}><CopyIcon /></Button>
                </div>
              </div>
              <div className="grid gap-1"><div className="text-xs font-medium text-muted-foreground">{t('vault:note')}</div><p className="text-sm text-foreground">{item.note || t('vault:noNotes')}</p></div>
              <div className="flex flex-wrap gap-x-6 gap-y-2 text-xs"><span><span className="text-muted-foreground">{t('vault:category')} </span>{item.category}</span><span className="flex flex-wrap items-center gap-1.5"><span className="text-muted-foreground">{t('vault:tags')} </span>{item.tags.map((tag) => <Badge key={tag} variant="secondary">{tag}</Badge>)}</span></div>
            </CardContent>
          </Card>
          <div className="flex flex-col gap-4">
            {item.totpSecret ? (
              <Card>
                <CardHeader>
                  <CardTitle id="totp-title">{t('vault:authenticatorCode')}</CardTitle>
                  <CardDescription>{t('vault:totpSubtitle')}</CardDescription>
                  <CardAction><Badge variant="secondary">{t('vault:totp')}</Badge></CardAction>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center gap-3"><strong className="font-mono text-2xl font-semibold tracking-widest" aria-live="polite">{totp}</strong><span className="text-sm text-muted-foreground">{totpSeconds}<small>s</small></span><Button variant="ghost" size="icon" className="ml-auto size-7" type="button" onClick={() => onCopy(totp, t('vault:authenticatorCode'))} aria-label={`${t('common:copy')} ${t('vault:authenticatorCode')}`}><CopyIcon /></Button></div>
                  <div className="h-1 overflow-hidden rounded-full bg-muted"><span className="block h-full bg-primary" style={{ width: `${(totpSeconds / 30) * 100}%` }} /></div>
                </CardContent>
              </Card>
            ) : null}
            {item.passkey ? (
              <Card>
                <CardHeader>
                  <CardTitle id="passkey-title">{t('vault:passkey')}</CardTitle>
                  <CardDescription>{t('vault:passkeySubtitle')}</CardDescription>
                  <CardAction><KeyRound size={16} className="text-muted-foreground" aria-hidden="true" /></CardAction>
                </CardHeader>
                <CardContent className="space-y-3">
                  <dl className="grid gap-2 text-sm">
                    <div className="grid gap-0.5"><dt className="text-xs text-muted-foreground">{t('vault:relyingParty')}</dt><dd className="font-medium">{item.passkey.rpId}</dd></div>
                    <div className="grid gap-0.5"><dt className="text-xs text-muted-foreground">{t('vault:credentialId')}</dt><dd><code className="break-all font-mono text-xs">{item.passkey.credentialId}</code></dd></div>
                    <div className="grid gap-0.5"><dt className="text-xs text-muted-foreground">{t('vault:publicKey')}</dt><dd><code className="break-all font-mono text-xs">{item.passkey.publicKey}</code></dd></div>
                  </dl>
                  <p className="flex items-start gap-1.5 text-xs leading-relaxed text-muted-foreground"><Info size={12} className="mt-0.5 shrink-0" aria-hidden="true" />{t('vault:privateKeyNeverSaved')}</p>
                </CardContent>
              </Card>
            ) : null}
            {item.recoveryCodes?.length ? (
              <Card>
                <CardHeader>
                  <CardTitle id="recovery-title">{t('vault:recoveryCodes')}</CardTitle>
                  <CardDescription>{t('vault:remainingCodes', { count: remainingCodes })}</CardDescription>
                  <CardAction><Button variant="ghost" size="sm" type="button" onClick={() => setRecoveryVisible((visible) => !visible)}>{recoveryVisible ? t('common:hide') : t('common:show')}</Button></CardAction>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex flex-col gap-2">
                  {item.recoveryCodes.map((code) => {
                    const isUsed = usedCodes.has(code.id)
                    return (
                      <div className={`flex items-center gap-2 rounded-lg bg-muted px-3 py-2 ${isUsed ? 'opacity-60' : ''}`} key={code.id}>
                        <span className="flex-1 font-mono text-sm">{recoveryVisible ? code.value : '•••• •••• ••••'}</span>
                        <Button variant="ghost" size="sm" type="button" onClick={() => { const nextUsed = !usedCodes.has(code.id); setUsedCodes((current) => { const next = new Set(current); if (nextUsed) next.add(code.id); else next.delete(code.id); return next }) }} aria-pressed={isUsed}>{isUsed ? t('vault:used') : t('vault:markUsed')}</Button>
                        <Button variant="ghost" size="icon" className="size-7 shrink-0" type="button" onClick={() => onCopy(code.value, t('vault:recoveryCode'))} aria-label={`${t('common:copy')} ${t('vault:recoveryCode')}`}><CopyIcon /></Button>
                      </div>
                    )
                  })}
                  </div>
                  <p className="text-xs leading-relaxed text-amber-600 dark:text-amber-400">{t('vault:recoveryCodePreviewNote')}</p>
                </CardContent>
              </Card>
            ) : null}
            {item.mnemonic?.length ? (
              <Card>
                <CardHeader>
                  <CardTitle id="mnemonic-title">{t('vault:mnemonic')}</CardTitle>
                  <CardDescription>{t('vault:mnemonicSubtitle', { count: item.mnemonic.length })}</CardDescription>
                  <CardAction><Button variant="ghost" size="sm" type="button" onClick={() => setMnemonicVisible((visible) => !visible)}>{mnemonicVisible ? t('common:hide') : t('common:show')}</Button></CardAction>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-3 gap-2">
                    {item.mnemonic.map((word, index) => <div className="flex items-center gap-2 rounded-lg bg-muted px-2.5 py-2" key={`${word}-${index}`}><span className="text-xs text-muted-foreground">{index + 1}</span><strong className="min-w-0 flex-1 truncate text-sm font-medium">{mnemonicVisible ? word : '••••••'}</strong><Button variant="ghost" size="icon" className="size-6 shrink-0" type="button" onClick={() => onCopy(word, `${t('vault:mnemonic')} ${index + 1}`)} aria-label={`${t('common:copy')} ${t('vault:mnemonic')} ${index + 1}`}><CopyIcon /></Button></div>)}
                  </div>
                  <Button variant="outline" size="sm" type="button" onClick={() => onCopy(item.mnemonic!.join(' '), t('vault:mnemonic'))}><CopyIcon />{t('vault:copyPhrase')}</Button>
                  <p className="flex items-start gap-1.5 text-xs leading-relaxed text-amber-600 dark:text-amber-400"><span aria-hidden="true">!</span>{t('vault:mnemonicRisk')}</p>
                </CardContent>
              </Card>
            ) : null}
          </div>
        </div>
        <p className="flex items-start gap-1.5 text-xs leading-relaxed text-muted-foreground"><Info size={12} className="mt-0.5 shrink-0" aria-hidden="true" />{t('vault:clipboardAutoClear')}</p>
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
