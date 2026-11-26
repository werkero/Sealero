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

/**
 * Trusted-confirmation page (SD §5.3). Lists the AI connector requests
 * waiting for this user and lets only the user approve or deny them. The
 * item name and domain are resolved locally from the unlocked vault —
 * the server never decrypts anything for this page.
 */
export function McpConfirmations({ user, items, isAdmin, onNavigate, onLogout, getAccessToken, refreshAccessToken }: {
  user: VaultIdentity
  items: VaultListItem[]
  isAdmin?: boolean
  onNavigate: (path: string) => void
  onLogout: () => void
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
    <VaultLayout user={user} filter="all" itemCount={items.length} isAdmin={isAdmin} onFilterChange={() => onNavigate(`/users/${user.id}`)} onNavigate={onNavigate} onLogout={onLogout}>
      <div className="vault-content">
        <div className="vault-title-row">
          <div>
            <p className="eyebrow">{t('vault:mcpConfirmations.title')}</p>
            <h1>{t('vault:mcpConfirmations.title')}</h1>
            <p className="vault-page-subtitle">{t('vault:mcpConfirmations.subtitle')}</p>
          </div>
          <button className="security-button security-button--quiet" type="button" onClick={() => onNavigate(`/users/${user.id}`)}>
            {t('vault:mcpConfirmations.backToVault')}
          </button>
        </div>
        {notice ? <p className="detail-loading" role="status">{notice}</p> : null}
        {actionError ? <p className="detail-loading" role="alert">{t('vault:mcpConfirmations.actionFailed')}</p> : null}
        {confirmations === null ? (
          loadError ? (
            <div className="empty-state">
              <span className="empty-state-icon" aria-hidden="true"><TriangleExclamationPoint size={20} aria-hidden="true" /></span>
              <h2>{t('vault:mcpConfirmations.loadFailed')}</h2>
              <button className="text-button" type="button" onClick={() => void load()}>{t('vault:mcpConfirmations.retry')}</button>
            </div>
          ) : (
            <div className="detail-loading" role="status" aria-live="polite">{t('vault:mcpConfirmations.loading')}</div>
          )
        ) : confirmations.length === 0 ? (
          <div className="empty-state">
            <span className="empty-state-icon" aria-hidden="true"><Check size={20} aria-hidden="true" /></span>
            <h2>{t('vault:mcpConfirmations.emptyTitle')}</h2>
            <p>{t('vault:mcpConfirmations.emptyBody')}</p>
          </div>
        ) : (
          <div className="item-list">
            {confirmations.map((confirmation) => {
              const item = itemsById.get(confirmation.item_id)
              const pending = confirmation.status === 'pending'
              return (
                <div key={confirmation.confirmation_id} className="vault-item-row">
                  <span className="item-row-copy">
                    <strong>{item ? item.name : t('vault:mcpConfirmations.unknownItem')}</strong>
                    <small>
                      {item ? hostname(item.url) : confirmation.item_id}
                      <span className="item-row-separator">·</span>
                      {t('vault:mcpConfirmations.clientLabel')}: {confirmation.client_name ?? confirmation.client_id}
                    </small>
                  </span>
                  <span className="item-row-category">
                    {pending ? t('vault:mcpConfirmations.pendingBadge') : t('vault:mcpConfirmations.approvedBadge')}
                  </span>
                  <span className="item-row-updated">
                    {t('vault:mcpConfirmations.expiresInMinutes', { minutes: minutesLeft(confirmation.expires_at) })}
                  </span>
                  {pending ? (
                    <span className="security-list-actions">
                      <button
                        className="security-button"
                        type="button"
                        disabled={actingId === confirmation.confirmation_id}
                        onClick={() => void decide(confirmation, 'approve')}
                      >
                        {t('vault:mcpConfirmations.allow')}
                      </button>
                      <button
                        className="security-button security-button--quiet"
                        type="button"
                        disabled={actingId === confirmation.confirmation_id}
                        onClick={() => void decide(confirmation, 'deny')}
                      >
                        {t('vault:mcpConfirmations.deny')}
                      </button>
                    </span>
                  ) : null}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </VaultLayout>
  )
}
