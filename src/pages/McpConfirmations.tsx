import { useCallback, useEffect, useMemo, useState } from 'react'
import { Check, TriangleExclamationPoint } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { VaultIdentity, VaultListItem } from '../client/contracts'
import {
  createMcpConfirmationClient,
  type McpConfirmationClient,
  type McpConfirmationItem,
} from '../client/mcp-confirmations'
import { VaultLayout, hostname } from '../App'
import type { AppearancePreference } from '../features/settings/preferences'
import { Alert, AlertDescription } from '../components/ui/alert'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, CardContent } from '../components/ui/card'

/**
 * Trusted-confirmation page (SD §5.3). Lists the AI connector requests
 * waiting for this user and lets only the user approve or deny them. The
 * item name and domain are resolved locally from the unlocked vault —
 * the server never decrypts anything for this page.
 */
export function McpConfirmations({ user, items, isAdmin, autoLockMinutes, onNavigate, onLock, onLogout, appearancePreference, onAppearanceChange, getAccessToken, refreshAccessToken }: {
  user: VaultIdentity
  items: VaultListItem[]
  isAdmin?: boolean
  autoLockMinutes: number
  onNavigate: (path: string) => void
  onLock: () => void
  onLogout: () => void
  appearancePreference: AppearancePreference
  onAppearanceChange: (preference: AppearancePreference) => void
  getAccessToken: () => string | null
  /** Shared token refresher (the vault adapter's); the client calls it on 401. */
  refreshAccessToken: (signal?: AbortSignal) => Promise<string>
}) {
  const { t } = useTranslation(['common', 'vault'])
  const client: McpConfirmationClient = useMemo(
    () => createMcpConfirmationClient({ getAccessToken, refreshAccessToken }),
    [getAccessToken, refreshAccessToken],
  )
  const [confirmations, setConfirmations] = useState<McpConfirmationItem[] | null>(null)
  const [loadError, setLoadError] = useState(false)
  const [actionError, setActionError] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const [actingId, setActingId] = useState<string | null>(null)

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoadError(false)
    try {
      const response = await client.listConfirmations(signal)
      setConfirmations(response.confirmations)
    } catch {
      if (signal?.aborted) return
      setLoadError(true)
    }
  }, [client])

  useEffect(() => {
    const controller = new AbortController()
    void load(controller.signal)
    return () => controller.abort()
  }, [load])

  const itemsById = useMemo(() => new Map(items.map((item) => [item.id, item])), [items])

  async function decide(confirmation: McpConfirmationItem, decision: 'approve' | 'deny') {
    setActingId(confirmation.confirmation_id)
    setActionError(false)
    setNotice(null)
    try {
      if (decision === 'approve') {
        await client.approveConfirmation(confirmation.confirmation_id)
        setNotice(t('vault:mcpConfirmations.approvedMessage'))
      } else {
        await client.denyConfirmation(confirmation.confirmation_id)
        setNotice(t('vault:mcpConfirmations.deniedMessage'))
      }
      await load()
    } catch {
      setActionError(true)
    } finally {
      setActingId(null)
    }
  }

  function minutesLeft(expiresAt: string): number {
    return Math.max(0, Math.round((new Date(expiresAt).getTime() - Date.now()) / 60000))
  }

  return (
    <VaultLayout autoLockMinutes={autoLockMinutes} user={user} filter="all" activeNav="confirmations" isAdmin={isAdmin} title={t('vault:mcpConfirmations.title')} onFilterChange={() => onNavigate(`/users/${user.id}`)} onNavigate={onNavigate} onLock={onLock} onLogout={onLogout} appearancePreference={appearancePreference} onAppearanceChange={onAppearanceChange}>
      <div className="w-full space-y-4 px-[clamp(20px,4vw,48px)] pb-10 pt-8">
        {notice ? <Alert><AlertDescription>{notice}</AlertDescription></Alert> : null}
        {actionError ? <Alert variant="destructive"><AlertDescription>{t('vault:mcpConfirmations.actionFailed')}</AlertDescription></Alert> : null}
        {confirmations === null ? (
          loadError ? (
            <div className="flex flex-col items-center px-4 py-16 text-center">
              <span className="mb-3 flex size-10 items-center justify-center rounded-full bg-muted text-muted-foreground" aria-hidden="true"><TriangleExclamationPoint size={20} aria-hidden="true" /></span>
              <h2 className="text-base font-semibold text-foreground">{t('vault:mcpConfirmations.loadFailed')}</h2>
              <Button variant="link" className="mt-3" type="button" onClick={() => void load()}>{t('vault:mcpConfirmations.retry')}</Button>
            </div>
          ) : (
            <p className="py-16 text-center text-sm text-muted-foreground" role="status" aria-live="polite">{t('vault:mcpConfirmations.loading')}</p>
          )
        ) : confirmations.length === 0 ? (
          <div className="flex flex-col items-center px-4 py-16 text-center">
            <span className="mb-3 flex size-10 items-center justify-center rounded-full bg-muted text-muted-foreground" aria-hidden="true"><Check size={20} aria-hidden="true" /></span>
            <h2 className="text-base font-semibold text-foreground">{t('vault:mcpConfirmations.emptyTitle')}</h2>
            <p className="mt-1 text-sm text-muted-foreground">{t('vault:mcpConfirmations.emptyBody')}</p>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {confirmations.map((confirmation) => {
              const item = itemsById.get(confirmation.item_id)
              const pending = confirmation.status === 'pending'
              return (
                <Card key={confirmation.confirmation_id}>
                  <CardContent className="flex flex-wrap items-center gap-4">
                    <span className="min-w-0 flex-1">
                      <strong className="block truncate text-sm font-medium text-foreground">{item ? item.name : t('vault:mcpConfirmations.unknownItem')}</strong>
                      <small className="mt-0.5 block truncate text-xs text-muted-foreground">
                        {item ? hostname(item.url) : confirmation.item_id}
                        <span className="mx-1">·</span>
                        {t('vault:mcpConfirmations.clientLabel')}: {confirmation.client_name ?? confirmation.client_id}
                      </small>
                    </span>
                    <Badge variant="secondary">
                      {pending ? t('vault:mcpConfirmations.pendingBadge') : t('vault:mcpConfirmations.approvedBadge')}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {t('vault:mcpConfirmations.expiresInMinutes', { minutes: minutesLeft(confirmation.expires_at) })}
                    </span>
                    {pending ? (
                      <span className="flex gap-2">
                        <Button
                          type="button"
                          disabled={actingId === confirmation.confirmation_id}
                          onClick={() => void decide(confirmation, 'approve')}
                        >
                          {t('vault:mcpConfirmations.allow')}
                        </Button>
                        <Button
                          variant="outline"
                          type="button"
                          disabled={actingId === confirmation.confirmation_id}
                          onClick={() => void decide(confirmation, 'deny')}
                        >
                          {t('vault:mcpConfirmations.deny')}
                        </Button>
                      </span>
                    ) : null}
                  </CardContent>
                </Card>
              )
            })}
          </div>
        )}
      </div>
    </VaultLayout>
  )
}
