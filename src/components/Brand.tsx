export function Brand({ onNavigate }: { onNavigate: (path: string) => void }) {
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
      sealero<span className="wordmark-period">.</span>
    </a>
  )
}
