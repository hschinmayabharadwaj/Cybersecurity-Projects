// ===================
// ©AngelaMos | 2026
// errors.ts
// ===================

export const ApiErrorCode = {
  NETWORK_ERROR: 'NETWORK_ERROR',
  PARSE_ERROR: 'PARSE_ERROR',
  UNKNOWN_ERROR: 'UNKNOWN_ERROR',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  BAD_JSON: 'BAD_JSON',
  BAD_CURSOR: 'BAD_CURSOR',
  BAD_PARAM: 'BAD_PARAM',
  UNKNOWN_TYPE: 'UNKNOWN_TYPE',
  GENERATE_FAILED: 'GENERATE_FAILED',
  TURNSTILE_FAILED: 'TURNSTILE_FAILED',
  NOT_FOUND: 'NOT_FOUND',
  RATE_LIMITED: 'RATE_LIMITED',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
} as const

export type ApiErrorCode = (typeof ApiErrorCode)[keyof typeof ApiErrorCode]

const USER_FACING_COPY: Partial<Record<string, string>> = {
  [ApiErrorCode.NETWORK_ERROR]:
    'Unable to reach the server. Check your connection.',
  [ApiErrorCode.PARSE_ERROR]: 'Server response did not match expected shape.',
  [ApiErrorCode.UNKNOWN_ERROR]: 'An unexpected error occurred.',
  [ApiErrorCode.RATE_LIMITED]: 'Too many requests. Wait a moment, then retry.',
  [ApiErrorCode.SERVICE_UNAVAILABLE]:
    'Service is temporarily unavailable. Try again shortly.',
}

export class ApiError extends Error {
  readonly code: string
  readonly statusCode: number
  readonly fields?: Readonly<Record<string, string>>

  constructor(
    message: string,
    code: string,
    statusCode: number,
    fields?: Record<string, string>
  ) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.statusCode = statusCode
    this.fields = fields
  }

  getUserMessage(): string {
    if (this.message.length > 0) {
      return this.message
    }
    return USER_FACING_COPY[this.code] ?? 'An unexpected error occurred.'
  }
}

declare module '@tanstack/react-query' {
  interface Register {
    defaultError: ApiError
  }
}
