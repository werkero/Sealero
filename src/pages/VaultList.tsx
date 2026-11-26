import { useEffect, useMemo, useRef, useState } from 'react'
import { ChevronRight, Info, Search, Star, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { VaultIdentity, VaultItemInput, VaultListItem } from '../client/contracts'
import { VaultLayout, hostname, iconTone, type VaultFilter } from '../App'
import { ItemEditor } from './ItemEditor'

export function VaultList({ user, items, isAdmin, onNavigate, onOpenItem, onCreateItem, onLogout }: {
  user: VaultIdentity
  items: VaultListItem[]
  isAdmin?: boolean
  onNavigate: (path: string) => void
  onOpenItem: (itemId: string) => void
  onCreateItem: (input: VaultItemInput) => Promise<unknown>
  onLogout: () => void
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
    <VaultLayout user={user} filter={filter} itemCount={items.length} isAdmin={isAdmin} onFilterChange={setFilter} onNavigate={onNavigate} onLogout={onLogout}>
      <div className="vault-content">
        <div className="vault-title-row">
          <div>
            <p className="eyebrow">{t('vault:collectionEyebrow')}</p>
            <h1>{filter === 'favorites' ? t('vault:favorites') : t('vault:allItems')}</h1>
            <p className="vault-page-subtitle">{t('vault:collectionSubtitle')}</p>
          </div>
          <div className="vault-items-count"><strong>{visibleItems.length}</strong><span>{t('vault:itemsLabel')}</span></div>
        </div>
        <div className="security-list-actions">
          <button className="security-button" type="button" onClick={() => setCreating(true)}>{t('vault:newItem')}</button>
          <button className="security-button security-button--quiet" type="button" onClick={() => onNavigate(`/users/${user.id}/generator`)}>{t('vault:generator.title')}</button>
          <button className="security-button security-button--quiet" type="button" onClick={() => onNavigate(`/users/${user.id}/settings`)}>{t('vault:health.title')}</button>
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
          <div className="search-box">
            <span className="search-glyph" aria-hidden="true"><Search size={16} aria-hidden="true" /></span>
            <label className="visually-hidden" htmlFor="vault-search">{t('vault:searchLabel')}</label>
            <input
              ref={searchInputRef}
              id="vault-search"
              type="search"
              placeholder={t('vault:searchPlaceholder')}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              autoComplete="off"
            />
            {query ? <button className="search-clear" type="button" onClick={() => setQuery('')} aria-label={t('common:clearSearch')}><X size={14} aria-hidden="true" /></button> : <kbd>⌘ K</kbd>}
          </div>
          <span className="search-scope">{t('vault:searchScope')}</span>
        </div>
        <div className="item-list-header"><span>{t('vault:entryColumn')}</span><span>{t('vault:categoryColumn')}</span><span>{t('vault:updatedColumn')}</span></div>
        <div className="item-list">
          {visibleItems.map((item) => (
            <button key={item.id} className="vault-item-row" type="button" onClick={() => onOpenItem(item.id)} aria-label={t('vault:openItem', { name: item.name })}>
              <span className={`app-icon ${iconTone(item.icon)}`}>{item.icon}</span>
              <span className="item-row-copy"><strong>{item.name}{item.favorite ? <span className="item-favorite-mark" aria-label={t('vault:favorite')}><Star size={10} aria-hidden="true" /></span> : null}</strong><small>{hostname(item.url)}<span className="item-row-separator">·</span>{item.username}</small></span>
              <span className="item-row-category">{item.category}</span>
              <span className="item-row-updated">{t('vault:updatedRecently')}</span>
              <span className="item-row-chevron" aria-hidden="true"><ChevronRight size={20} aria-hidden="true" /></span>
            </button>
          ))}
          {visibleItems.length === 0 ? (
            <div className="empty-state">
              <span className="empty-state-icon" aria-hidden="true"><Search size={20} aria-hidden="true" /></span>
              <h2>{query ? t('vault:noResultsTitle') : t('vault:emptyTitle')}</h2>
              <p>{query ? t('vault:noResultsBody') : t('vault:emptyBody')}</p>
              {query ? <button className="text-button" type="button" onClick={() => setQuery('')}>{t('common:clearSearch')}</button> : null}
            </div>
          ) : null}
        </div>
        <p className="list-footnote"><span aria-hidden="true"><Info size={12} aria-hidden="true" /></span>{t('vault:searchFootnote')}</p>
      </div>
    </VaultLayout>
  )
}
