import { motion, useReducedMotion } from 'motion/react'
import { useTranslation } from 'react-i18next'

/** Blue seal bobbing in the center while an entry loads, with the loading text below it. */
export function DetailLoading() {
  const { t } = useTranslation('vault')
  const reduceMotion = useReducedMotion()
  return (
    <div className="mx-auto flex min-h-[320px] w-[min(100%,1060px)] flex-col items-center justify-center gap-4 text-[13px] text-[#7c8796]" role="status" aria-live="polite">
      <motion.img
        src="/sealero-logo.svg"
        alt=""
        aria-hidden="true"
        width="64"
        height="64"
        className="motion-reduce:animate-none"
        animate={reduceMotion ? undefined : { y: [0, -6, 0] }}
        transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
      />
      <span>{t('loadingEntry')}</span>
    </div>
  )
}
