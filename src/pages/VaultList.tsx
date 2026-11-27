import { useEffect, useMemo, useRef, useState } from 'react'
import { ChevronRight, Search, Star, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { VaultIdentity, VaultItemInput, VaultListItem } from '../client/contracts'
import { VaultLayout, hostname, iconTone, type VaultFilter } from '../App'
import type { AppearancePreference } from '../features/settings/preferences'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { ItemEditor } from './ItemEditor'

export function VaultList({ user, items, isAdmin, onNavigate, onOpenItem, onCreateItem, onLock, onLogout, appearancePreference, onAppearanceChange }: {
  user: VaultIdentity
  items: VaultListItem[]
  isAdmin?: boolean
  onNavigate: (path: string) => void
  onOpenItem: (itemId: string) => void
  onCreateItem: (input: VaultItemInput) => Promise<unknown>
  onLock: () => void
  onLogout: () => void
  appearancePreference: AppearancePreference
  onAppearanceChange: (preference: AppearancePreference) => void
}) {
  const { t } = useTranslation(['common', 'vault'])
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<VaultFilter>('all')
  const [creating, setCreating] = useState(false)
  const searchInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const onShortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        searchInputRef.current?.focus()
      }
      if (event.key === 'Escape' && document.activeElement === searchInputRef.current) {
        setQuery('')
        searchInputRef.current?.blur()
      }
    }
    window.addEventListener('keydown', onShortcut)
    return () => window.removeEventListener('keydown', onShortcut)
  }, [])

  const visibleItems = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase()
    return items.filter((item) => {
      if (filter === 'favorites' && !item.favorite) return false
      if (!normalizedQuery) return true
      return [item.name, item.url, item.username].some((value) => value.toLocaleLowerCase().includes(normalizedQuery))
    })
  }, [filter, items, query])

  return (
    <VaultLayout user={user} filter={filter} itemCount={items.length} isAdmin={isAdmin} title={filter === 'favorites' ? t('vault:favorites') : t('vault:allItems')} onFilterChange={setFilter} onNavigate={onNavigate} onLock={onLock} onLogout={onLogout} appearancePreference={appearancePreference} onAppearanceChange={onAppearanceChange}>
      <div className="vault-content">
        <div className="security-list-actions">
          <Button type="button" onClick={() => setCreating(true)}>{t('vault:newItem')}</Button>
          <Button variant="secondary" type="button" onClick={() => onNavigate(`/users/${user.id}/generator`)}>{t('vault:generator.title')}</Button>
          <Button variant="secondary" type="button" onClick={() => onNavigate(`/users/${user.id}/settings`)}>{t('vault:health.title')}</Button>
          <span className="ml-auto self-center text-xs text-muted-foreground"><strong className="font-semibold text-foreground">{visibleItems.length}</strong> {t('vault:itemsLabel')}</span>
        </div>
        {creating ? (
          <ItemEditor
            initial={null}
            onSave={async (input) => {
              const created = await onCreateItem(input)
              if (!created) return
              setCreating(false)
              window.dispatchEvent(new CustomEvent('sealero:toast', { detail: t('vault:itemCreated') }))
            }}
            onCancel={() => setCreating(false)}
          />
        ) : null}
        <div className="vault-search-row">
          <div className="relative min-w-0 flex-1">
            <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" aria-hidden="true"><Search size={16} aria-hidden="true" /></span>
            <label className="visually-hidden" htmlFor="vault-search">{t('vault:searchLabel')}</label>
            <Input
              ref={searchInputRef}
              id="vault-search"
              type="search"
              placeholder={t('vault:searchPlaceholder')}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              autoComplete="off"
              className="pl-9 pr-11"
            />
            {query ? (
              <button className="absolute right-2 top-1/2 flex size-6 -translate-y-1/2 cursor-pointer items-center justify-center rounded-md border-0 bg-transparent text-muted-foreground hover:bg-accent hover:text-foreground" type="button" onClick={() => setQuery('')} aria-label={t('common:clearSearch')}>
                <X size={14} aria-hidden="true" />
              </button>
            ) : (
              <kbd className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 rounded border border-border bg-muted px-1.5 py-0.5 font-[inherit] text-[11px] text-muted-foreground">⌘ K</kbd>
            )}
          </div>
        </div>
        <div className="item-list-header"><span>{t('vault:entryColumn')}</span><span>{t('vault:categoryColumn')}</span><span>{t('vault:updatedColumn')}</span></div>
        <div className="item-list">
          {visibleItems.map((item) => (
            <button key={item.id} className="vault-item-row" type="button" onClick={() => onOpenItem(item.id)} aria-label={t('vault:openItem', { name: item.name })}>
              <span className={`app-icon ${iconTone(item.icon)}`}>{item.icon}</span>
              <span className="item-row-copy"><strong>{item.name}{item.favorite ? <span className="item-favorite-mark" aria-label={t('vault:favorite')}><Star size={10} aria-hidden="true" /></span> : null}</strong><small>{hostname(item.url)}<span className="item-row-separator">·</span>{item.username}</small></span>
              <span className="item-row-category"><Badge variant="secondary" className="max-w-full truncate">{item.category}</Badge></span>
              <span className="item-row-updated">{t('vault:updatedRecently')}</span>
              <span className="item-row-chevron" aria-hidden="true"><ChevronRight size={20} aria-hidden="true" /></span>
            </button>
          ))}
          {visibleItems.length === 0 ? (
            <div className="empty-state">
              <span className="empty-state-icon" aria-hidden="true"><Search size={20} aria-hidden="true" /></span>
              <h2>{query ? t('vault:noResultsTitle') : t('vault:emptyTitle')}</h2>
              <p>{query ? t('vault:noResultsBody') : t('vault:emptyBody')}</p>
              {query ? <Button variant="link" className="mt-3" type="button" onClick={() => setQuery('')}>{t('common:clearSearch')}</Button> : null}
            </div>
          ) : null}
        </div>
      </div>
    </VaultLayout>
  )
}
