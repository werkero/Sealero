/**
 * Account avatar: the avatar image when the user set one, otherwise the
 * first letter of the display name (falling back to the email). Decorative:
 * the surrounding UI already names the account.
 */
export function UserAvatar({ displayName, avatarUrl, email, className }: {
  displayName?: string | null
  avatarUrl?: string | null
  email: string
  className?: string
}) {
  const initial = (displayName || email).slice(0, 1).toUpperCase()
  return (
    <span className={className} aria-hidden="true">
      {avatarUrl ? (
        <img src={avatarUrl} alt="" className="size-full rounded-[inherit] object-cover" />
      ) : initial}
    </span>
  )
}
