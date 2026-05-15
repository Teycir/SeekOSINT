/**
 * app/api/targets/[id]/route.ts
 *
 * DELETE /api/targets/:id — remove a saved target
 */
import { getCloudflareContext } from '@opennextjs/cloudflare'
import { removeTarget } from '../../../../lib/targets'
import { errorResponse, ErrorCode } from '../../../../lib/errors'
import type { Env } from '../../../../lib/types'

export async function DELETE(
  _req: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const { id } = await params
  if (!id) return errorResponse(ErrorCode.INVALID_QUERY, 'id is required', 400)

  try {
    const { env } = getCloudflareContext()
    const db = (env as unknown as Env).DB
    if (!db) return errorResponse(ErrorCode.INTERNAL_ERROR, 'D1 not available', 503)

    const deleted = await removeTarget(db, id)
    if (!deleted) return errorResponse(ErrorCode.INTERNAL_ERROR, 'target not found', 404)

    return new Response(null, { status: 204 })
  } catch (err) {
    console.error('[api/targets/[id]] DELETE failed', err)
    return errorResponse(ErrorCode.INTERNAL_ERROR, 'internal server error', 500)
  }
}
