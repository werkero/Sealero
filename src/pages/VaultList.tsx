import { useEffect, useMemo, useRef, useState } from 'react'
import { ChevronRight, Plus, Search, Star, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { VaultIdentity, VaultItemInput, VaultListItem } from '../client/contracts'
import { VaultLayout, hostname, iconTone, type VaultFilter } from '../App'
import type { AppearancePreference } from '../features/settings/preferences'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { ItemEditor } from './ItemEditor'

export function VaultList({ user, items, isAdmin, autoLockMinutes, onNavigate, onOpenItem, onCreateItem, onLock, onLogout, appearancePreference, onAppearanceChange }: {
  user: VaultIdentity
  items: VaultListItem[]
  isAdmin?: boolean
  autoLockMinutes: number
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
    <VaultLayout autoLockMinutes={autoLockMinutes} user={user} filter={filter} isAdmin={isAdmin} title={filter === 'favorites' ? t('vault:favorites') : t('vault:allItems')} topbarEndAction={filter === 'all' ? <Button variant="ghost" size="sm" type="button" aria-label={t('vault:add')} title={t('vault:add')} onClick={() => setCreating(true)}><Plus className="size-4" aria-hidden="true" /><span>{t('vault:add')}</span></Button> : undefined} onFilterChange={setFilter} onNavigate={onNavigate} onLock={onLock} onLogout={onLogout} appearancePreference={appearancePreference} onAppearanceChange={onAppearanceChange}>
      <div className="w-full space-y-4 px-[clamp(20px,4vw,48px)] pb-10 pt-8">
        <Dialog open={creating} onOpenChange={(open) => { if (!open) setCreating(false) }}>
          <DialogContent className="max-h-[calc(100dvh-4rem)] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>{t('vault:newItem')}</DialogTitle>
              <DialogDescription>{t('vault:collectionSubtitle')}</DialogDescription>
            </DialogHeader>
            <ItemEditor
              initial={null}
              bare
              onSave={async (input) => {
                const created = await onCreateItem(input)
                if (!created) return
                setCreating(false)
                window.dispatchEvent(new CustomEvent('sealero:toast', { detail: t('vault:itemCreated') }))
              }}
              onCancel={() => setCreating(false)}
            />
          </DialogContent>
        </Dialog>
        <div className="relative min-w-0 flex-1">
            <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" aria-hidden="true"><Search size={16} aria-hidden="true" /></span>
            <label className="sr-only" htmlFor="vault-search">{t('vault:searchLabel')}</label>
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
        <div className="hidden grid-cols-[minmax(0,1fr)_150px_95px_20px] gap-3 px-4 pb-2 pl-[58px] text-xs font-semibold tracking-wider text-muted-foreground sm:grid"><span>{t('vault:entryColumn')}</span><span>{t('vault:categoryColumn')}</span><span>{t('vault:updatedColumn')}</span></div>
        <div className="flex flex-col">
          {visibleItems.map((item) => (
            <button key={item.id} className="grid w-full min-h-[72px] grid-cols-[35px_minmax(0,1fr)_20px] items-center gap-3 rounded-lg px-2 py-2 text-left transition-colors hover:bg-muted sm:grid-cols-[35px_minmax(0,1fr)_150px_95px_20px] sm:px-4" type="button" onClick={() => onOpenItem(item.id)} aria-label={t('vault:openItem', { name: item.name })}>
              <span className={`grid size-[35px] shrink-0 place-items-center rounded-[11px] text-sm font-bold ${iconTone(item.icon)}`}>{item.icon}</span>
              <span className="min-w-0"><strong className="block truncate text-sm font-medium text-foreground">{item.name}{item.favorite ? <span className="ml-1.5 inline-flex align-middle text-amber-500" aria-label={t('vault:favorite')}><Star size={10} aria-hidden="true" /></span> : null}</strong><small className="mt-0.5 block truncate text-xs text-muted-foreground">{hostname(item.url)}<span className="mx-1">·</span>{item.username}</small></span>
              <span className="hidden sm:block"><Badge variant="secondary" className="max-w-full truncate">{item.category}</Badge></span>
              <span className="hidden text-xs text-muted-foreground sm:block">{t('vault:updatedRecently')}</span>
              <span className="text-muted-foreground" aria-hidden="true"><ChevronRight size={20} aria-hidden="true" /></span>
            </button>
          ))}
          {visibleItems.length === 0 ? (
            <div className="flex flex-col items-center px-4 py-16 text-center">
              <span className="mb-3 flex size-10 items-center justify-center rounded-full bg-muted text-muted-foreground" aria-hidden="true"><Search size={20} aria-hidden="true" /></span>
              <h2 className="text-base font-semibold text-foreground">{query ? t('vault:noResultsTitle') : t('vault:emptyTitle')}</h2>
              <p className="mt-1 text-sm text-muted-foreground">{query ? t('vault:noResultsBody') : t('vault:emptyBody')}</p>
              {query ? <Button variant="link" className="mt-3" type="button" onClick={() => setQuery('')}>{t('common:clearSearch')}</Button> : null}
            </div>
          ) : null}
        </div>
      </div>
    </VaultLayout>
  )
}
