export function Brand({ onNavigate, iconOnly }: { onNavigate: (path: string) => void; iconOnly?: boolean }) {
  return (
    <a
      className="inline-flex items-center gap-2 text-[23px] font-[720] tracking-[-0.07em] leading-none text-foreground no-underline focus-visible:outline-3 focus-visible:outline-[#a9c3ff] focus-visible:outline-offset-[3px] max-[390px]:text-[20px]"
      href="/"
      aria-label="Sealero"
      onClick={(event) => {
        event.preventDefault()
        onNavigate('/')
      }}
    >
      <img className="h-8 w-auto shrink-0 dark:brightness-[1.7] dark:saturate-[1.25] max-[390px]:h-7" src="/sealero-logo.svg" alt="" aria-hidden="true" />
      {iconOnly ? null : <>sealero<span className="text-primary">.</span></>}
    </a>
  )
}
