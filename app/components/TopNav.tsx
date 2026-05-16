/**
 * app/components/TopNav.tsx
 *
 * Fixed top-right nav — appears on every page via layout.tsx.
 *
 * Responsive considerations:
 * - Uses `pt-safe` via padding-top on body isn't available, so we rely on
 *   the existing page top-padding (py-10 = 40px) being enough clearance.
 * - On mobile the label collapses to just the icon to avoid overlapping
 *   the host page's own action row which wraps on narrow screens.
 * - z-50 keeps it above cards; pointer-events-none on the wrapper prevents
 *   blocking touch targets in the top-right quadrant when the link is tiny.
 */
import Link from 'next/link'

export function TopNav() {
  return (
    <nav className="fixed top-0 right-0 z-50 px-4 py-3 pointer-events-none">
      <Link
        href="/saved"
        className="pointer-events-auto inline-flex items-center gap-1.5
                   text-xs font-mono text-neon-red/40 hover:text-neon-red
                   transition-colors duration-150"
      >
        {/* Star glyph: use SVG so it renders identically across JetBrains Mono
            and fallback monospace fonts instead of relying on ★ (U+2605)
            which renders as a bullet in some monospace stacks. */}
        <svg
          viewBox="0 0 12 12"
          width="11"
          height="11"
          fill="currentColor"
          aria-hidden="true"
          className="shrink-0 translate-y-px"
        >
          <path d="M6 0l1.47 4.527H12L8.265 7.327 9.708 12 6 9.202 2.292 12l1.443-4.673L0 4.527h4.53z" />
        </svg>
        <span className="hidden sm:inline">saved</span>
      </Link>
    </nav>
  )
}
