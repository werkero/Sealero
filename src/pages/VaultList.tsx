import { useMemo, useState } from 'react'
import { ChevronRight, Plus, Search, Star } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { VaultIdentity, VaultItemInput, VaultListItem } from '../client/contracts'
import { VaultLayout, hostname, iconTone, type VaultFilter } from '../App'
import type { AppearancePreference } from '../features/settings/preferences'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
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
  const [filter, setFilter] = useState<VaultFilter>('all')
  const [creating, setCreating] = useState(false)

  const visibleItems = useMemo(() => {
    return items.filter((item) => filter !== 'favorites' || item.favorite)
  }, [filter, items])

  return (
    <VaultLayout autoLockMinutes={autoLockMinutes} user={user} items={items} filter={filter} isAdmin={isAdmin} title={filter === 'favorites' ? t('vault:favorites') : t('vault:allItems')} topbarEndAction={filter === 'all' ? <Button variant="ghost" size="sm" type="button" aria-label={t('vault:add')} title={t('vault:add')} onClick={() => setCreating(true)}><Plus className="size-5" aria-hidden="true" /><span className="text-[11px]">{t('vault:add')}</span></Button> : undefined} onFilterChange={setFilter} onNavigate={onNavigate} onLock={onLock} onLogout={onLogout} appearancePreference={appearancePreference} onAppearanceChange={onAppearanceChange}>
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
              <h2 className="text-base font-semibold text-foreground">{t('vault:emptyTitle')}</h2>
              <p className="mt-1 text-sm text-muted-foreground">{t('vault:emptyBody')}</p>
            </div>
          ) : null}
        </div>
      </div>
    </VaultLayout>
  )
}
