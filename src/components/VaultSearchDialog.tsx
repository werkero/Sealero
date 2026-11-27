import { useEffect, useMemo, useState, type KeyboardEvent } from 'react'
import { Search } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { VaultListItem } from '../client/types'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from './ui/dialog'
import { Input } from './ui/input'

/**
 * Jump-to search: opened from the sidebar search field (or ⌘K) on any
 * backend page. Matches name, URL and username, the same fields as the
 * vault list's inline search; picking a result opens that item.
 */
export function VaultSearchDialog({ open, items, onOpenChange, onSelectItem }: {
  open: boolean
  items: VaultListItem[]
  onOpenChange: (open: boolean) => void
  onSelectItem: (itemId: string) => void
}) {
  const { t } = useTranslation(['vault'])
  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)

  const results = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase()
    if (!normalizedQuery) return []
    return items.filter((item) => [item.name, item.url, item.username].some((value) => value.toLocaleLowerCase().includes(normalizedQuery)))
  }, [items, query])

  useEffect(() => { setActiveIndex(0) }, [query])

  useEffect(() => {
    if (open) {
      setQuery('')
      setActiveIndex(0)
    }
  }, [open ])

  const select = (itemId: string) => {
    onSelectItem(itemId)
    onOpenChange(false)
  }

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setActiveIndex((index) => Math.min(index + 1, results.length - 1))
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      setActiveIndex((index) => Math.max(index - 1, 0))
    } else if (event.key === 'Enter') {
      const active = results[activeIndex]
      if (active) {
        event.preventDefault()
        select(active.id)
      }
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[calc(100dvh-4rem)] overflow-y-auto sm:max-w-lg" onKeyDown={onKeyDown}>
        <DialogHeader>
          <DialogTitle>{t('vault:searchLabel')}</DialogTitle>
        </DialogHeader>
        <div className="relative">
          <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" aria-hidden="true"><Search size={16} aria-hidden="true" /></span>
          <Input
            type="search"
            placeholder={t('vault:searchPlaceholder')}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            autoComplete="off"
            className="pl-9"
          />
        </div>
        {query.trim() !== '' ? (
          results.length === 0 ? (
            <div className="py-6 text-center">
              <h3 className="text-base font-semibold text-foreground">{t('vault:noResultsTitle')}</h3>
              <p className="mt-1 text-sm text-muted-foreground">{t('vault:noResultsBody')}</p>
            </div>
          ) : (
            <div className="flex flex-col">
              {results.map((item, index) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => select(item.id)}
                  onMouseEnter={() => setActiveIndex(index)}
                  className={`grid w-full min-w-0 grid-cols-[minmax(0,1fr)] items-center gap-0.5 rounded-lg px-3 py-2 text-left ${index === activeIndex ? 'bg-muted' : ''}`}
                >
                  <span className="truncate text-sm font-medium text-foreground">{item.name}</span>
                  {item.username || item.url ? <span className="truncate text-xs text-muted-foreground">{item.username || item.url}</span> : null}
                </button>
              ))}
            </div>
          )
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
