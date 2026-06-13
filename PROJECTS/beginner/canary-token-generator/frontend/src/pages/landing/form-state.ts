// ===================
// ©AngelaMos | 2026
// form-state.ts
// ===================

import {
  type CreateTokenInput,
  createTokenRequestSchema,
  type EnvfileIncludeKey,
  type TokenType,
  type TypeDescriptor,
} from '@/api'
import { ApiError } from '@/core/api'

export type FormState = {
  type: TokenType | ''
  memo: string
  filename: string
  alertChannel: 'telegram' | 'webhook'
  telegramBot: string
  telegramChat: string
  webhookUrl: string
  slowredirectDestination: string
  envfileIncludeKeys: EnvfileIncludeKey[]
}

export const INITIAL_FORM: FormState = {
  type: '',
  memo: '',
  filename: '',
  alertChannel: 'telegram',
  telegramBot: '',
  telegramChat: '',
  webhookUrl: '',
  slowredirectDestination: '',
  envfileIncludeKeys: ['aws', 'stripe', 'db'],
}

export const FILE_KIND_TYPES = new Set<TokenType>([
  'docx',
  'pdf',
  'kubeconfig',
  'envfile',
])

export function descriptorFor(
  descriptors: TypeDescriptor[],
  type: TokenType | ''
): TypeDescriptor | undefined {
  if (type === '') {
    return undefined
  }
  return descriptors.find((d) => d.type === type)
}

export function buildPayload(form: FormState): CreateTokenInput {
  if (form.type === '') {
    throw new Error('species not selected')
  }
  const payload: CreateTokenInput = {
    type: form.type,
    memo: form.memo,
    alert_channel: form.alertChannel,
  }
  if (form.filename.length > 0) {
    payload.filename = form.filename
  }
  if (form.alertChannel === 'telegram') {
    payload.telegram_bot = form.telegramBot
    payload.telegram_chat = form.telegramChat
  } else {
    payload.webhook_url = form.webhookUrl
  }
  if (form.type === 'slowredirect') {
    payload.metadata = { destination_url: form.slowredirectDestination }
  } else if (form.type === 'envfile') {
    payload.metadata = { include_keys: form.envfileIncludeKeys }
  }
  return payload
}

export type FieldErrors = Partial<Record<string, string>>

const BACKEND_TO_FORM_FIELD: Readonly<Record<string, string>> = {
  type: 'type',
  memo: 'memo',
  filename: 'filename',
  alert_channel: 'alert_channel',
  telegram_bot: 'telegram_bot',
  telegram_chat: 'telegram_chat',
  webhook_url: 'webhook_url',
  'metadata.destination_url': 'metadata.destination_url',
  'metadata.include_keys': 'metadata.include_keys',
}

export function buildSubmissionState(error: unknown): {
  errors: FieldErrors
} {
  if (!(error instanceof ApiError) || !error.fields) {
    return { errors: { form: 'submission failed — try again' } }
  }
  const errors: FieldErrors = {}
  for (const [key, value] of Object.entries(error.fields)) {
    const mapped = BACKEND_TO_FORM_FIELD[key] ?? key
    errors[mapped] = value
  }
  return { errors }
}

export function validateForm(form: FormState): {
  ok: boolean
  errors: FieldErrors
  payload: CreateTokenInput | null
} {
  if (form.type === '') {
    return { ok: false, errors: { type: 'select a species' }, payload: null }
  }
  let payload: CreateTokenInput
  try {
    payload = buildPayload(form)
  } catch (_err) {
    return { ok: false, errors: { type: 'select a species' }, payload: null }
  }
  const parsed = createTokenRequestSchema.safeParse(payload)
  if (parsed.success) {
    return { ok: true, errors: {}, payload }
  }
  const errors: FieldErrors = {}
  for (const issue of parsed.error.issues) {
    const key = issue.path.join('.') || 'form'
    if (errors[key] === undefined) {
      errors[key] = issue.message
    }
  }
  return { ok: false, errors, payload: null }
}
