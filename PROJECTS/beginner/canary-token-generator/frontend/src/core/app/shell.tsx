// ===================
// ©AngelaMos | 2026
// shell.tsx
// ===================

import { Suspense } from 'react'
import { ErrorBoundary } from 'react-error-boundary'
import { Outlet } from 'react-router-dom'

function ShellErrorFallback({ error }: { error: Error }): React.ReactElement {
  return <pre>{error.message}</pre>
}

export function Shell(): React.ReactElement {
  return (
    <ErrorBoundary FallbackComponent={ShellErrorFallback}>
      <Suspense fallback={null}>
        <Outlet />
      </Suspense>
    </ErrorBoundary>
  )
}
