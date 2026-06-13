// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import { useEffect, useRef, useState } from 'react'
import { setTurnstileTokenProvider } from '@/api'

declare global {
  interface Window {
    turnstile?: {
      render: (
        container: HTMLElement,
        options: {
          sitekey: string
          callback?: (token: string) => void
          'expired-callback'?: () => void
          'error-callback'?: () => void
          theme?: 'light' | 'dark' | 'auto'
          appearance?: 'always' | 'execute' | 'interaction-only'
          size?: 'normal' | 'flexible' | 'compact' | 'invisible'
        }
      ) => string
      reset: (widgetId?: string) => void
      remove: (widgetId?: string) => void
    }
    onloadTurnstileCallback?: () => void
  }
}

const TURNSTILE_SRC =
  'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=onloadTurnstileCallback'
const TURNSTILE_SCRIPT_ID = 'cf-turnstile-script'

function loadTurnstileScript(): Promise<void> {
  if (typeof window === 'undefined') {
    return Promise.resolve()
  }
  if (window.turnstile) {
    return Promise.resolve()
  }
  return new Promise((resolve, reject) => {
    const existing = document.getElementById(TURNSTILE_SCRIPT_ID)
    if (existing) {
      existing.addEventListener('load', () => resolve(), { once: true })
      existing.addEventListener(
        'error',
        () => reject(new Error('turnstile script failed to load')),
        { once: true }
      )
      return
    }
    window.onloadTurnstileCallback = () => resolve()
    const script = document.createElement('script')
    script.id = TURNSTILE_SCRIPT_ID
    script.src = TURNSTILE_SRC
    script.async = true
    script.defer = true
    script.addEventListener(
      'error',
      () => reject(new Error('turnstile script failed to load')),
      { once: true }
    )
    document.head.appendChild(script)
  })
}

type TurnstileProps = {
  siteKey: string
  appearance?: 'always' | 'execute' | 'interaction-only'
}

export function Turnstile({
  siteKey,
  appearance = 'always',
}: TurnstileProps): React.ReactElement {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const widgetIdRef = useRef<string | null>(null)
  const tokenRef = useRef<string | null>(null)
  const [status, setStatus] = useState<'idle' | 'ready' | 'error'>('idle')

  useEffect(() => {
    let cancelled = false
    setTurnstileTokenProvider(() => tokenRef.current)
    loadTurnstileScript()
      .then(() => {
        if (cancelled || !window.turnstile || !containerRef.current) {
          return
        }
        widgetIdRef.current = window.turnstile.render(containerRef.current, {
          sitekey: siteKey,
          appearance,
          callback: (token: string) => {
            tokenRef.current = token
            setStatus('ready')
          },
          'expired-callback': () => {
            tokenRef.current = null
            setStatus('idle')
          },
          'error-callback': () => {
            tokenRef.current = null
            setStatus('error')
          },
        })
      })
      .catch(() => {
        if (!cancelled) {
          setStatus('error')
        }
      })
    return () => {
      cancelled = true
      setTurnstileTokenProvider(null)
      if (widgetIdRef.current && window.turnstile) {
        window.turnstile.remove(widgetIdRef.current)
        widgetIdRef.current = null
      }
      tokenRef.current = null
    }
  }, [siteKey, appearance])

  return (
    <div data-turnstile-status={status}>
      <div ref={containerRef} />
    </div>
  )
}

export function getTurnstileSiteKey(): string | null {
  const key = import.meta.env.VITE_TURNSTILE_SITE_KEY
  if (typeof key !== 'string' || key.length === 0) {
    return null
  }
  return key
}
