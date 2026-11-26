export function Brand({ onNavigate, iconOnly }: { onNavigate: (path: string) => void; iconOnly?: boolean }) {
  return (
    <a
      className="wordmark"
      href="/"
      aria-label="Sealero"
      onClick={(event) => {
        event.preventDefault()
        onNavigate('/')
      }}
    >
      <img className="wordmark-logo" src="/sealero-logo.svg" alt="" aria-hidden="true" />
      {iconOnly ? null : <>sealero<span className="wordmark-period">.</span></>}
    </a>
  )
}
