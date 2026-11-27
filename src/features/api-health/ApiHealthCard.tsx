import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '../../components/ui/button'
import { createApiHealthClient, type ApiHealthResponse } from '../../client/api-health'

const healthClient = createApiHealthClient({ apiBaseUrl: import.meta.env.VITE_API_BASE_URL ?? '' })

type HealthState =
  | { phase: 'checking' }
  | { phase: 'unavailable' }
  | { phase: 'online'; response: ApiHealthResponse }

export function ApiHealthCard() {
  const { t } = useTranslation('common')
  const [health, setHealth] = useState<HealthState>({ phase: 'checking' })
  const [retryCount, setRetryCount] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    let active = true

    void healthClient.getHealth(controller.signal)
      .then((response) => {
        if (active) setHealth({ phase: 'online', response })
      })
      .catch(() => {
        if (active && !controller.signal.aborted) setHealth({ phase: 'unavailable' })
      })

    return () => {
      active = false
      controller.abort()
    }
  }, [retryCount])

  const message = health.phase === 'checking'
    ? t('apiStatusChecking')
    : health.phase === 'online'
      ? t('apiStatusOnline')
      : t('apiStatusUnavailable')

  return (
    <aside className="flex items-center gap-3 rounded-lg border bg-card px-4 py-3 text-sm shadow-sm" aria-label={t('apiStatus')} role="status" aria-live="polite">
      <span className={`size-2 shrink-0 rounded-full ${health.phase === 'online' ? 'bg-emerald-500' : health.phase === 'unavailable' ? 'bg-destructive' : 'bg-amber-500'}`} aria-hidden="true" />
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1">
        <strong className="font-medium">{message}</strong>
        {health.phase === 'online' ? (
          <span className="text-xs text-muted-foreground">
            {t('apiStatusServer', { name: health.response.server_name })} · API {health.response.api_version}
          </span>
        ) : null}
        {health.phase === 'unavailable' ? (
          <Button
            variant="link"
            size="sm"
            className="h-auto p-0"
            type="button"
            onClick={() => {
              setHealth({ phase: 'checking' })
              setRetryCount((count) => count + 1)
            }}
          >
            {t('apiStatusRetry')}
          </Button>
        ) : null}
      </div>
    </aside>
  )
}
