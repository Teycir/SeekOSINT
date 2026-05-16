'use client'
/**
 * ExportButton — downloads the current result as JSON.
 */

import { Tooltip } from './Tooltip'

interface ExportButtonProps {
  resultJson: string
  filename:   string
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
    <Tooltip label={`Download as ${filename}`}>
      <button
        onClick={handleExport}
        className="text-xs text-neutral-500 hover:text-neon-red font-mono transition-colors"
      >
        ↓ export json
      </button>
    </Tooltip>
  )
}
