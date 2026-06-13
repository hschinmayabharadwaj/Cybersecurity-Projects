// ===================
// ©AngelaMos | 2026
// client.ts
// ===================

import axios, {
  type AxiosError,
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from 'axios'
import type { ZodType } from 'zod'
import { ApiError, ApiErrorCode } from '@/core/api'
import { apiErrorEnvelopeSchema, successEnvelope } from './types/error'

const REQUEST_TIMEOUT_MS = 15000
const TURNSTILE_HEADER_NAME = 'CF-Turnstile-Response'

const STATUS_FALLBACK_CODE: Readonly<Record<number, ApiErrorCode>> = {
  400: ApiErrorCode.VALIDATION_ERROR,
  404: ApiErrorCode.NOT_FOUND,
  410: ApiErrorCode.NOT_FOUND,
  429: ApiErrorCode.RATE_LIMITED,
  500: ApiErrorCode.INTERNAL_ERROR,
  502: ApiErrorCode.SERVICE_UNAVAILABLE,
  503: ApiErrorCode.SERVICE_UNAVAILABLE,
  504: ApiErrorCode.SERVICE_UNAVAILABLE,
}

const resolveBaseURL = (): string => {
  const fromEnv = import.meta.env.VITE_API_URL
  if (typeof fromEnv === 'string' && fromEnv.length > 0) {
    return fromEnv
  }
  return '/api'
}

export const apiClient: AxiosInstance = axios.create({
  baseURL: resolveBaseURL(),
  timeout: REQUEST_TIMEOUT_MS,
  headers: { 'Content-Type': 'application/json' },
})

export type TurnstileTokenProvider = () => string | null | undefined

let turnstileProvider: TurnstileTokenProvider | null = null

export function setTurnstileTokenProvider(
  provider: TurnstileTokenProvider | null
): void {
  turnstileProvider = provider
}

function transformAxiosError(error: AxiosError<unknown>): ApiError {
  if (!error.response) {
    return new ApiError('Network error', ApiErrorCode.NETWORK_ERROR, 0)
  }
  const { status, data } = error.response

  const parsed = apiErrorEnvelopeSchema.safeParse(data)
  if (parsed.success) {
    return new ApiError(
      parsed.data.error.message,
      parsed.data.error.code,
      status,
      parsed.data.error.fields
    )
  }

  const fallback = STATUS_FALLBACK_CODE[status] ?? ApiErrorCode.UNKNOWN_ERROR
  return new ApiError('Request failed', fallback, status)
}

apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig): InternalAxiosRequestConfig => {
    const token = turnstileProvider?.()
    if (typeof token === 'string' && token.length > 0) {
      config.headers.set(TURNSTILE_HEADER_NAME, token)
    }
    return config
  },
  (error: unknown) => Promise.reject(error)
)

apiClient.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (axios.isAxiosError(error)) {
      return Promise.reject(transformAxiosError(error))
    }
    return Promise.reject(error)
  }
)

type ParseIssue = {
  path: readonly PropertyKey[]
  message: string
}

function describeParseFailure(issues: readonly ParseIssue[]): string {
  const first = issues[0]
  if (!first) {
    return 'unknown'
  }
  const path = first.path.length > 0 ? first.path.join('.') : '<root>'
  return `${path}: ${first.message}`
}

function unwrapEnvelope<T>(data: unknown, schema: ZodType<T>, status: number): T {
  const parsed = successEnvelope(schema).safeParse(data)
  if (!parsed.success) {
    throw new ApiError(
      `response shape mismatch (${describeParseFailure(parsed.error.issues)})`,
      ApiErrorCode.PARSE_ERROR,
      status
    )
  }
  return parsed.data.data
}

export async function apiGet<T>(path: string, schema: ZodType<T>): Promise<T> {
  const response = await apiClient.get<unknown>(path)
  return unwrapEnvelope(response.data, schema, response.status)
}

export async function apiPost<T>(
  path: string,
  body: unknown,
  schema: ZodType<T>
): Promise<T> {
  const response = await apiClient.post<unknown>(path, body)
  return unwrapEnvelope(response.data, schema, response.status)
}

export async function apiDelete(path: string): Promise<void> {
  await apiClient.delete(path)
}
