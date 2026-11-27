import { motion, useReducedMotion } from 'motion/react'
import { useTranslation } from 'react-i18next'

/** Blue seal bobbing in the center while an entry loads, with the loading text below it. */
export function DetailLoading() {
  const { t } = useTranslation('vault')
  const reduceMotion = useReducedMotion()
  return (
    <div className="detail-loading" role="status" aria-live="polite">
      <motion.img
        src="/sealero-logo.svg"
        alt=""
        aria-hidden="true"
        width="64"
        height="64"
        animate={reduceMotion ? undefined : { y: [0, -6, 0] }}
        transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
      />
      <span>{t('loadingEntry')}</span>
    </div>
  )
}
