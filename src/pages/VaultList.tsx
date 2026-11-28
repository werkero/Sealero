import { useMemo, useRef, useState } from 'react'
import { Check, Copy, MoreVertical, Pencil, Plus, Search, Star, StarOff, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { VaultIdentity, VaultItem, VaultItemInput, VaultListItem } from '../client/contracts'
import { VaultLayout, iconTone, type VaultFilter } from '../App'
import type { AppearancePreference } from '../features/settings/preferences'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '../components/ui/alert-dialog'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '../components/ui/dropdown-menu'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '../components/ui/tooltip'
import { ItemEditor } from './ItemEditor'

/** Format an ISO timestamp as YYYY-MM-DD in local time. */
function formatDate(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const y = d.getFullYear()
  const m = String(d.getMonth() + 1).padStart(2, '0')
  const day = String(d.getDate()).padStart(2, '0')
  return `${y}-${m}-${day}`
}

export function VaultList({ user, items, isAdmin, autoLockMinutes, onNavigate, onOpenItem, onCreateItem, onCopy, onUpdateItem, onDeleteItem, loadItem, onLock, onLogout, appearancePreference, onAppearanceChange }: {
  user: VaultIdentity
  items: VaultListItem[]
  isAdmin?: boolean
  autoLockMinutes: number
  onNavigate: (path: string) => void
  onOpenItem: (itemId: string) => void
  onCreateItem: (input: VaultItemInput) => Promise<unknown>
  onCopy: (value: string, label: string) => void
  onUpdateItem: (itemId: string, input: VaultItemInput) => Promise<VaultItem | null>
  onDeleteItem: (itemId: string) => Promise<boolean>
  loadItem: (itemId: string) => Promise<VaultItem>
  onLock: () => void
  onLogout: () => void
  appearancePreference: AppearancePreference
  onAppearanceChange: (preference: AppearancePreference) => void
}) {
  const { t } = useTranslation(['common', 'vault'])
  const [filter, setFilter] = useState<VaultFilter>('all')
  const [creating, setCreating] = useState(false)
  const [editingItem, setEditingItem] = useState<VaultItem | null>(null)
  const [deletingItem, setDeletingItem] = useState<VaultListItem | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const copyTimer = useRef<number | null>(null)

  const visibleItems = useMemo(() => {
    return items.filter((item) => filter !== 'favorites' || item.favorite)
  }, [filter, items])

  const editorOpen = creating || editingItem !== null
  const closeEditor = () => {
    setCreating(false)
    setEditingItem(null)
  }

  const copyPassword = async (item: VaultListItem) => {
    try {
      const full = await loadItem(item.id)
      onCopy(full.password, t('vault:password'))
      setCopiedId(item.id)
      if (copyTimer.current !== null) window.clearTimeout(copyTimer.current)
      copyTimer.current = window.setTimeout(() => {
        setCopiedId((current) => (current === item.id ? null : current))
      }, 1500)
    } catch {
      // Loading the item failed; leave the row unchanged.
    }
  }

  const toggleFavorite = async (item: VaultListItem) => {
    try {
      const full = await loadItem(item.id)
      await onUpdateItem(item.id, {
        name: full.name,
        url: full.url,
        username: full.username,
        password: full.password,
        note: full.note,
        category: full.category,
        tags: full.tags,
        favorite: !full.favorite,
        icon: full.icon,
        totpSecret: full.totpSecret,
        passkey: full.passkey,
        recoveryCodes: full.recoveryCodes,
        mnemonic: full.mnemonic,
      })
    } catch {
      // Loading or saving failed; leave the row unchanged.
    }
  }

  const openEdit = async (item: VaultListItem) => {
    try {
      const full = await loadItem(item.id)
      setEditingItem(full)
    } catch {
      // Loading the item failed; leave the row unchanged.
    }
  }

  const handleDelete = () => {
    if (!deletingItem) return
    const target = deletingItem
    setDeletingItem(null)
    void onDeleteItem(target.id).then((deleted) => {
      if (deleted) {
        window.dispatchEvent(new CustomEvent('sealero:toast', { detail: t('vault:itemDeleted') }))
      }
    })
  }

  return (
    <VaultLayout autoLockMinutes={autoLockMinutes} user={user} items={items} filter={filter} isAdmin={isAdmin} title={filter === 'favorites' ? t('vault:favorites') : t('vault:allItems')} topbarEndAction={filter === 'all' ? <Button variant="ghost" size="sm" type="button" aria-label={t('vault:add')} title={t('vault:add')} onClick={() => setCreating(true)}><Plus className="size-5" aria-hidden="true" /><span className="text-[11px]">{t('vault:add')}</span></Button> : undefined} onFilterChange={setFilter} onNavigate={onNavigate} onLock={onLock} onLogout={onLogout} appearancePreference={appearancePreference} onAppearanceChange={onAppearanceChange}>
      <div className="w-full space-y-4 px-[clamp(20px,4vw,48px)] pb-10 pt-8">
        <Dialog open={editorOpen} onOpenChange={(open) => { if (!open) closeEditor() }}>
          <DialogContent className="max-h-[calc(100dvh-4rem)] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>{editingItem ? t('vault:editItem') : t('vault:newItem')}</DialogTitle>
              <DialogDescription>{t('vault:collectionSubtitle')}</DialogDescription>
            </DialogHeader>
            <ItemEditor
              key={editingItem?.id ?? 'new'}
              initial={editingItem}
              bare
              onSave={async (input) => {
                if (editingItem) {
                  const updated = await onUpdateItem(editingItem.id, input)
                  if (updated) {
                    closeEditor()
                    window.dispatchEvent(new CustomEvent('sealero:toast', { detail: t('vault:itemUpdated') }))
                  }
                } else {
                  const created = await onCreateItem(input)
                  if (!created) return
                  closeEditor()
                  window.dispatchEvent(new CustomEvent('sealero:toast', { detail: t('vault:itemCreated') }))
                }
              }}
              onCancel={closeEditor}
            />
          </DialogContent>
        </Dialog>
        <AlertDialog open={deletingItem !== null} onOpenChange={(open) => { if (!open) setDeletingItem(null) }}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{t('vault:deleteItem')}</AlertDialogTitle>
              <AlertDialogDescription>{t('vault:deleteItemConfirm')}</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>{t('vault:cancelEdit')}</AlertDialogCancel>
              <AlertDialogAction className="bg-destructive text-destructive-foreground hover:bg-destructive/90" onClick={handleDelete}>{t('vault:confirmDelete')}</AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
        {visibleItems.length === 0 ? (
          <div className="flex flex-col items-center px-4 py-16 text-center">
            <span className="mb-3 flex size-10 items-center justify-center rounded-full bg-muted text-muted-foreground" aria-hidden="true"><Search size={20} aria-hidden="true" /></span>
            <h2 className="text-base font-semibold text-foreground">{t('vault:emptyTitle')}</h2>
            <p className="mt-1 text-sm text-muted-foreground">{t('vault:emptyBody')}</p>
          </div>
        ) : (
          <TooltipProvider>
            <Card className="gap-0 overflow-hidden py-0">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>{t('vault:entryColumn')}</TableHead>
                    <TableHead className="hidden w-[140px] md:table-cell">{t('vault:categoryColumn')}</TableHead>
                    <TableHead className="hidden w-[180px] lg:table-cell">{t('vault:tagsColumn')}</TableHead>
                    <TableHead className="hidden w-[110px] md:table-cell">{t('vault:dateColumn')}</TableHead>
                    <TableHead className="w-[96px] text-right">{t('vault:optionsColumn')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visibleItems.map((item) => (
                    <TableRow
                      key={item.id}
                      className="group cursor-pointer"
                      tabIndex={0}
                      onClick={() => onOpenItem(item.id)}
                      onKeyDown={(e) => { if (e.key === 'Enter') onOpenItem(item.id) }}
                      aria-label={t('vault:openItem', { name: item.name })}
                    >
                      <TableCell>
                        <div className="flex min-w-0 items-center gap-3">
                          <span className={`grid size-[35px] shrink-0 place-items-center rounded-[11px] text-sm font-bold ${iconTone(item.icon)}`}>{item.icon}</span>
                          <span className="flex min-w-0 items-center gap-1">
                            <span className="min-w-0 truncate text-sm font-medium text-foreground">{item.name}</span>
                            <Button
                              variant="ghost"
                              size="icon"
                              className={`size-6 shrink-0 ${item.favorite ? 'text-amber-500 hover:text-amber-500' : 'text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100'}`}
                              type="button"
                              aria-label={item.favorite ? t('vault:unfavorite') : t('vault:favorite')}
                              title={item.favorite ? t('vault:unfavorite') : t('vault:favorite')}
                              onClick={(e) => { e.stopPropagation(); void toggleFavorite(item) }}
                              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') e.stopPropagation() }}
                            >
                              <Star size={16} className={item.favorite ? 'fill-current' : undefined} aria-hidden="true" />
                            </Button>
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="hidden md:table-cell">
                        <Badge variant="secondary" className="max-w-full truncate">{item.category}</Badge>
                      </TableCell>
                      <TableCell className="hidden lg:table-cell">
                        {item.tags.length === 0 ? (
                          <span className="text-xs text-muted-foreground">—</span>
                        ) : (
                          <span className="flex flex-wrap items-center gap-1">
                            {item.tags.slice(0, 2).map((tag) => <Badge key={tag} variant="secondary" className="max-w-[90px] truncate">{tag}</Badge>)}
                            {item.tags.length > 2 ? <Badge variant="secondary">+{item.tags.length - 2}</Badge> : null}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="hidden whitespace-nowrap text-xs text-muted-foreground md:table-cell">{formatDate(item.updatedAt)}</TableCell>
                      <TableCell className="text-right">
                        <div className="group/options flex items-center justify-end gap-1">
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="size-8 opacity-0 transition-opacity group-hover/options:opacity-100 focus-visible:opacity-100 max-sm:opacity-100"
                                type="button"
                                aria-label={t('vault:copyPassword')}
                                onClick={(e) => { e.stopPropagation(); void copyPassword(item) }}
                              >
                                {copiedId === item.id ? <Check size={16} className="text-primary" aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>{t('vault:copyPassword')}</TooltipContent>
                          </Tooltip>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="size-8"
                                type="button"
                                aria-label={t('vault:moreOptions')}
                                onClick={(e) => e.stopPropagation()}
                              >
                                <MoreVertical size={16} aria-hidden="true" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => void toggleFavorite(item)}>
                                {item.favorite ? <StarOff size={16} aria-hidden="true" /> : <Star size={16} aria-hidden="true" />}
                                {item.favorite ? t('vault:unfavorite') : t('vault:favorite')}
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => void openEdit(item)}>
                                <Pencil size={16} aria-hidden="true" />
                                {t('vault:edit')}
                              </DropdownMenuItem>
                              <DropdownMenuItem variant="destructive" onClick={() => setDeletingItem(item)}>
                                <Trash2 size={16} aria-hidden="true" />
                                {t('vault:delete')}
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          </TooltipProvider>
        )}
      </div>
    </VaultLayout>
  )
}
