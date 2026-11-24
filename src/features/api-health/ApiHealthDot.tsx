import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { createApiHealthClient, type ApiHealthResponse } from '../../client/api-health'
import './api-health.css'

const healthClient = createApiHealthClient({ apiBaseUrl: import.meta.env.VITE_API_BASE_URL ?? '' })

type HealthState =
  | { phase: 'checking' }
  | { phase: 'unavailable' }
  | { phase: 'online'; response: ApiHealthResponse }

export function ApiHealthDot() {
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

  if (health.phase === 'unavailable') {
    return (
      <button
        className={`api-health-dot api-health-dot--${health.phase}`}
        type="button"
        title={message}
        aria-label={`${t('apiStatus')}: ${message}`}
        onClick={() => {
          setHealth({ phase: 'checking' })
          setRetryCount((count) => count + 1)
        }}
      >
        <span aria-hidden="true" />
      </button>
    )
  }

  return (
    <span
      className={`api-health-dot api-health-dot--${health.phase}`}
      title={message}
      aria-label={`${t('apiStatus')}: ${message}`}
      role="status"
    >
      <span aria-hidden="true" />
    </span>
  )
}
