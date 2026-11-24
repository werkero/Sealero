import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { createApiHealthClient, type ApiHealthResponse } from '../../client/api-health'
import './api-health.css'

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
    <aside className={`api-health-card api-health-card--${health.phase}`} aria-label={t('apiStatus')} role="status" aria-live="polite">
      <span className="api-health-card__indicator" aria-hidden="true" />
      <div className="api-health-card__content">
        <strong>{message}</strong>
        {health.phase === 'online' ? (
          <span className="api-health-card__details">
            {t('apiStatusServer', { name: health.response.server_name })} · API {health.response.api_version}
          </span>
        ) : null}
        {health.phase === 'unavailable' ? (
          <button
            className="api-health-card__retry"
            type="button"
            onClick={() => {
              setHealth({ phase: 'checking' })
              setRetryCount((count) => count + 1)
            }}
          >
            {t('apiStatusRetry')}
          </button>
        ) : null}
      </div>
    </aside>
  )
}
