import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { createApiHealthClient } from '../../client/api-health'
import './api-health.css'

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
    <span className={`footer-status footer-status--${phase}`} role="status">
      <span className="footer-status-dot" aria-hidden="true" />
      {message}
    </span>
  )
}
