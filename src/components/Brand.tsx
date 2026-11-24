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
      sealero<span className="wordmark-period">.</span>
    </a>
  )
}
