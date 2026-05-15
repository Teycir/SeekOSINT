'use client'
/**
 * ExportButton — client component that downloads the current result as JSON.
 * Zero backend work: pure client-side JSON.stringify + Blob download.
 */

interface ExportButtonProps {
  // Pass the serialised result as a string to avoid server→client hydration
  // of a complex object. The host page JSON.stringify's it server-side.
  resultJson: string
  filename: string
}

export function ExportButton({ resultJson, filename }: ExportButtonProps) {
  function handleExport() {
    const blob = new Blob([resultJson], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <button
      onClick={handleExport}
      className="text-xs text-neutral-500 hover:text-neon-red font-mono transition-colors"
      title="Download full result as JSON"
    >
      ↓ export json
    </button>
  )
}
