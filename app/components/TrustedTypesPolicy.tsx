'use client';

import { useEffect } from 'react';

/**
 * TrustedTypesPolicy — registers a permissive default Trusted Types policy
 * so that React DOM's internal innerHTML/script injection (used during
 * hydration and for dangerouslySetInnerHTML) is not blocked by Chrome's
 * Trusted Types enforcement.
 *
 * This runs once on the client before any hydration side-effects fire.
 * It is intentionally permissive (identity policy) because React already
 * sanitizes its own output and we control all dangerouslySetInnerHTML call
 * sites (only JSON-LD in layout.tsx).
 *
 * See: https://react.dev/reference/react-dom/client/hydrateRoot#parameters
 * See: https://w3c.github.io/trusted-types/dist/spec/
 */

declare global {
  interface Window {
    trustedTypes?: {
      createPolicy: (name: string, policy: {
        createHTML?: (s: string) => string
        createScript?: (s: string) => string
        createScriptURL?: (s: string) => string
      }) => unknown
    }
  }
}

export function TrustedTypesPolicy() {
  useEffect(() => {
    if (
      typeof window === 'undefined' ||
      !window.trustedTypes ||
      !window.trustedTypes.createPolicy
    ) {
      return;
    }

    // Only register once — if 'default' already exists, skip silently.
    try {
      window.trustedTypes.createPolicy('default', {
        createHTML:      (s: string) => s,
        createScript:    (s: string) => s,
        createScriptURL: (s: string) => s,
      });
    } catch {
      // Policy already registered (e.g. HMR re-run) — not an error.
    }
  }, []);

  return null;
}
