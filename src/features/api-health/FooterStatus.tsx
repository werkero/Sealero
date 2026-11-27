import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { createApiHealthClient } from '../../client/api-health'

const healthClient = createApiHealthClient({ apiBaseUrl: import.meta.env.VITE_API_BASE_URL ?? '' })

type StatusPhase = 'checking' | 'online' | 'unavailable'

export function FooterStatus() {
  const { t } = useTranslation('common')
  const [phase, setPhase] = useState<StatusPhase>('checking')

  useEffect(() => {
    const controller = new AbortController()
    let active = true
    void healthClient.getHealth(controller.signal)
      .then(() => { if (active) setPhase('online') })
      .catch(() => { if (active && !controller.signal.aborted) setPhase('unavailable') })
    return () => {
      active = false
      controller.abort()
    }
  }, [])

  const message = phase === 'checking'
    ? t('footerStatusChecking')
    : phase === 'online'
      ? t('footerStatusOperational')
      : t('footerStatusUnavailable')

  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground" role="status">
      <span className={`size-1.5 rounded-full ${phase === 'online' ? 'bg-emerald-500' : phase === 'unavailable' ? 'bg-destructive' : 'bg-amber-500'}`} aria-hidden="true" />
      {message}
    </span>
  )
}
