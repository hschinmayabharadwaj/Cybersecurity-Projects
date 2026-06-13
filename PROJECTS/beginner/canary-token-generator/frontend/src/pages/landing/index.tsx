// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import {
  type CreateTokenResponse,
  type EnvfileIncludeKey,
  envfileIncludeKeySchema,
  type TokenType,
  type TypeDescriptor,
  useCreateToken,
  useTokenTypes,
} from '@/api'
import {
  Button,
  Halftone,
  Strip,
  StripItem,
  TextareaField,
  TextField,
} from '@/components'
import { getTurnstileSiteKey, Turnstile } from '@/core/turnstile'
import { PAGE_COPY } from './copy'
import {
  buildSubmissionState,
  FILE_KIND_TYPES,
  type FieldErrors,
  type FormState,
  INITIAL_FORM,
  validateForm,
} from './form-state'
import styles from './landing.module.scss'
import { ResultView } from './result'
import { TypePicker } from './type-picker'

const ENVFILE_KEYS = envfileIncludeKeySchema.options

export function Component(): React.ReactElement {
  const typesQuery = useTokenTypes()
  const createMutation = useCreateToken()
  const [form, setForm] = useState<FormState>(INITIAL_FORM)
  const [errors, setErrors] = useState<FieldErrors>({})
  const [created, setCreated] = useState<CreateTokenResponse | null>(null)
  const turnstileSiteKey = useMemo(() => getTurnstileSiteKey(), [])

  function patchForm(next: Partial<FormState>): void {
    setForm((prev) => ({ ...prev, ...next }))
  }

  function handleSubmit(event: React.FormEvent<HTMLFormElement>): void {
    event.preventDefault()
    const result = validateForm(form)
    setErrors(result.errors)
    if (!result.ok || !result.payload) {
      toast.error('Some fields need attention')
      return
    }
    createMutation.mutate(result.payload, {
      onSuccess: (data) => {
        setCreated(data)
        toast.success('Specimen released')
      },
      onError: (error) => {
        const submission = buildSubmissionState(error)
        setErrors(submission.errors)
      },
    })
  }

  function handleAnother(): void {
    setCreated(null)
    setErrors({})
    setForm((prev) => ({ ...prev, memo: '', filename: '' }))
  }

  return (
    <div className={styles.page}>
      <Strip>
        <StripItem label={PAGE_COPY.STRIP_FIELD_STATION}>canary</StripItem>
        <StripItem label={PAGE_COPY.STRIP_VOLUME}>2026·05</StripItem>
        <StripItem label={PAGE_COPY.STRIP_ISSUE} inverted>
          {created ? 'DOSSIER' : 'INTAKE'}
        </StripItem>
      </Strip>

      <header className={styles.hero}>
        <h1 className={styles.headline}>{PAGE_COPY.HEADLINE}</h1>
        <p className={styles.latin}>{PAGE_COPY.HEADLINE_LATIN}</p>
        <p className={styles.purpose}>{PAGE_COPY.HEADLINE_PURPOSE}</p>
      </header>

      <Halftone density="sparse" height={18} />

      <main className={styles.main}>
        {created ? (
          <ResultView
            data={created}
            onAnother={handleAnother}
            filenameFallback={form.filename || defaultFilename(form.type)}
          />
        ) : (
          <FormView
            form={form}
            errors={errors}
            descriptors={typesQuery.data ?? []}
            descriptorsLoading={typesQuery.isLoading}
            descriptorsError={typesQuery.error}
            turnstileSiteKey={turnstileSiteKey}
            submitting={createMutation.isPending}
            onChange={patchForm}
            onSubmit={handleSubmit}
          />
        )}
      </main>

      <Strip align="left" border="top">
        <StripItem label="ROUTING">cloudflare tunnel</StripItem>
        <StripItem label="ALERTS">telegram / webhook</StripItem>
        <StripItem label="LICENSE">©AngelaMos 2026</StripItem>
      </Strip>
    </div>
  )
}

Component.displayName = 'Landing'

type FormViewProps = {
  form: FormState
  errors: FieldErrors
  descriptors: TypeDescriptor[]
  descriptorsLoading: boolean
  descriptorsError: Error | null
  turnstileSiteKey: string | null
  submitting: boolean
  onChange: (next: Partial<FormState>) => void
  onSubmit: (event: React.FormEvent<HTMLFormElement>) => void
}

function FormView({
  form,
  errors,
  descriptors,
  descriptorsLoading,
  descriptorsError,
  turnstileSiteKey,
  submitting,
  onChange,
  onSubmit,
}: FormViewProps): React.ReactElement {
  const showTypeMetadata = form.type === 'slowredirect' || form.type === 'envfile'
  return (
    <form className={styles.form} onSubmit={onSubmit} noValidate>
      <SpeciesSection
        form={form}
        errors={errors}
        descriptors={descriptors}
        descriptorsLoading={descriptorsLoading}
        descriptorsError={descriptorsError}
        onChange={onChange}
      />
      <AnnotateSection form={form} errors={errors} onChange={onChange} />
      <RouteSection form={form} errors={errors} onChange={onChange} />
      {showTypeMetadata ? (
        <ConfigSection form={form} errors={errors} onChange={onChange} />
      ) : null}
      {turnstileSiteKey ? <VerifySection siteKey={turnstileSiteKey} /> : null}
      <SubmitFooter submitting={submitting} />
    </form>
  )
}

type SectionPropsBase = {
  form: FormState
  errors: FieldErrors
  onChange: (next: Partial<FormState>) => void
}

type SpeciesSectionProps = SectionPropsBase & {
  descriptors: TypeDescriptor[]
  descriptorsLoading: boolean
  descriptorsError: Error | null
}

function SpeciesSection({
  form,
  errors,
  descriptors,
  descriptorsLoading,
  descriptorsError,
  onChange,
}: SpeciesSectionProps): React.ReactElement {
  return (
    <Section
      index={PAGE_COPY.SECTION_01_INDEX}
      title={PAGE_COPY.SECTION_01_TITLE}
      body={PAGE_COPY.SECTION_01_BODY}
    >
      {descriptorsError ? (
        <p className={styles.errorBlock}>
          Could not load species catalog. Try again in a moment.
        </p>
      ) : descriptorsLoading ? (
        <p className={styles.statusBlock}>Loading species catalog…</p>
      ) : (
        <TypePicker
          descriptors={descriptors}
          value={form.type}
          onChange={(t) => onChange({ type: t })}
          invalid={errors.type !== undefined}
        />
      )}
      {errors.type ? <p className={styles.fieldError}>{errors.type}</p> : null}
    </Section>
  )
}

function AnnotateSection({
  form,
  errors,
  onChange,
}: SectionPropsBase): React.ReactElement {
  const showFilename =
    form.type !== '' && FILE_KIND_TYPES.has(form.type as TokenType)
  return (
    <Section
      index={PAGE_COPY.SECTION_02_INDEX}
      title={PAGE_COPY.SECTION_02_TITLE}
      body={PAGE_COPY.SECTION_02_BODY}
    >
      <TextareaField
        index="A"
        label="MEMO"
        name="memo"
        value={form.memo}
        maxLength={256}
        placeholder="Q4 bonuses spreadsheet on file-server"
        onChange={(e) => onChange({ memo: e.target.value })}
        error={errors.memo}
        hint={`${form.memo.length} / 256 characters`}
      />
      {showFilename ? (
        <FilenameField form={form} errors={errors} onChange={onChange} />
      ) : null}
    </Section>
  )
}

function FilenameField({
  form,
  errors,
  onChange,
}: SectionPropsBase): React.ReactElement {
  return (
    <TextField
      index="B"
      label="FILENAME (OPTIONAL)"
      name="filename"
      value={form.filename}
      maxLength={128}
      placeholder={defaultFilename(form.type)}
      onChange={(e) => onChange({ filename: e.target.value })}
      error={errors.filename}
      hint="What the bait file will be called when it lands somewhere it shouldn't."
    />
  )
}

function RouteSection({
  form,
  errors,
  onChange,
}: SectionPropsBase): React.ReactElement {
  return (
    <Section
      index={PAGE_COPY.SECTION_03_INDEX}
      title="ROUTE THE REPORT"
      body={PAGE_COPY.SECTION_03_BODY}
    >
      <ChannelToggle
        value={form.alertChannel}
        onChange={(c) => onChange({ alertChannel: c })}
      />
      {form.alertChannel === 'telegram' ? (
        <TelegramFields form={form} errors={errors} onChange={onChange} />
      ) : (
        <WebhookField form={form} errors={errors} onChange={onChange} />
      )}
    </Section>
  )
}

function TelegramFields({
  form,
  errors,
  onChange,
}: SectionPropsBase): React.ReactElement {
  return (
    <div className={styles.subgrid}>
      <TextField
        index="A"
        label="BOT TOKEN"
        name="telegram_bot"
        value={form.telegramBot}
        placeholder="123456789:ABCdefGHIjklMNO..."
        onChange={(e) => onChange({ telegramBot: e.target.value })}
        error={errors.telegram_bot}
      />
      <TextField
        index="B"
        label="CHAT ID"
        name="telegram_chat"
        value={form.telegramChat}
        placeholder="-1001234567890"
        onChange={(e) => onChange({ telegramChat: e.target.value })}
        error={errors.telegram_chat}
      />
    </div>
  )
}

function WebhookField({
  form,
  errors,
  onChange,
}: SectionPropsBase): React.ReactElement {
  return (
    <TextField
      index="A"
      label="WEBHOOK URL"
      name="webhook_url"
      type="url"
      value={form.webhookUrl}
      placeholder="https://hooks.example.com/canary"
      onChange={(e) => onChange({ webhookUrl: e.target.value })}
      error={errors.webhook_url}
      hint="We POST the alert envelope JSON. Optionally HMAC-signed if the server has WEBHOOK_HMAC_SECRET set."
    />
  )
}

function ConfigSection({
  form,
  errors,
  onChange,
}: SectionPropsBase): React.ReactElement {
  const body =
    form.type === 'slowredirect'
      ? 'Visitors will be fingerprinted, then redirected here.'
      : 'Bait credentials to ship alongside the disguised canary URL.'
  return (
    <Section
      index={PAGE_COPY.SECTION_04_INDEX}
      title={descriptorTitle(form.type)}
      body={body}
    >
      {form.type === 'slowredirect' ? (
        <SlowRedirectField form={form} errors={errors} onChange={onChange} />
      ) : (
        <IncludeKeysPicker
          value={form.envfileIncludeKeys}
          onChange={(k) => onChange({ envfileIncludeKeys: k })}
        />
      )}
    </Section>
  )
}

function SlowRedirectField({
  form,
  errors,
  onChange,
}: SectionPropsBase): React.ReactElement {
  return (
    <TextField
      index="A"
      label="DESTINATION URL"
      name="metadata_destination_url"
      type="url"
      value={form.slowredirectDestination}
      placeholder="https://example.com/landing"
      onChange={(e) => onChange({ slowredirectDestination: e.target.value })}
      error={errors['metadata.destination_url']}
    />
  )
}

function VerifySection({ siteKey }: { siteKey: string }): React.ReactElement {
  return (
    <Section
      index={PAGE_COPY.SECTION_05_INDEX}
      title="VERIFY"
      body={PAGE_COPY.SECTION_05_BODY}
    >
      <div className={styles.turnstile}>
        <Turnstile siteKey={siteKey} />
      </div>
    </Section>
  )
}

function SubmitFooter({
  submitting,
}: {
  submitting: boolean
}): React.ReactElement {
  return (
    <div className={styles.submitRow}>
      <p className={styles.submitNote}>
        We never see the alert payload — it routes directly from server to your
        channel.
      </p>
      <Button type="submit" size="lg" busy={submitting}>
        {PAGE_COPY.SUBMIT_LABEL}
      </Button>
    </div>
  )
}

type SectionProps = React.PropsWithChildren<{
  index: string
  title: string
  body: string
}>

function Section({
  index,
  title,
  body,
  children,
}: SectionProps): React.ReactElement {
  return (
    <section className={styles.section}>
      <header className={styles.sectionHead}>
        <span className={styles.sectionIndex}>{index}</span>
        <span className={styles.sectionRule} aria-hidden="true" />
      </header>
      <h2 className={styles.sectionTitle}>{title}</h2>
      <p className={styles.sectionBody}>{body}</p>
      <div className={styles.sectionContent}>{children}</div>
    </section>
  )
}

type ChannelToggleProps = {
  value: 'telegram' | 'webhook'
  onChange: (next: 'telegram' | 'webhook') => void
}

function ChannelToggle({
  value,
  onChange,
}: ChannelToggleProps): React.ReactElement {
  return (
    <fieldset className={styles.channelToggle}>
      <legend className={styles.srOnly}>Alert channel</legend>
      <ChannelOption
        name="alert-channel"
        value="telegram"
        active={value === 'telegram'}
        onChange={() => onChange('telegram')}
        label="Telegram"
        note="message lands in a chat"
      />
      <ChannelOption
        name="alert-channel"
        value="webhook"
        active={value === 'webhook'}
        onChange={() => onChange('webhook')}
        label="Webhook"
        note="JSON POST to your URL"
      />
    </fieldset>
  )
}

function ChannelOption({
  name,
  value,
  active,
  onChange,
  label,
  note,
}: {
  name: string
  value: string
  active: boolean
  onChange: () => void
  label: string
  note: string
}): React.ReactElement {
  return (
    <label className={styles.channelOption} data-active={active}>
      <input
        className={styles.srOnly}
        type="radio"
        name={name}
        value={value}
        checked={active}
        onChange={onChange}
      />
      <span className={styles.channelLabel}>{label}</span>
      <span className={styles.channelNote}>{note}</span>
    </label>
  )
}

type IncludeKeysPickerProps = {
  value: EnvfileIncludeKey[]
  onChange: (next: EnvfileIncludeKey[]) => void
}

function IncludeKeysPicker({
  value,
  onChange,
}: IncludeKeysPickerProps): React.ReactElement {
  function toggle(key: EnvfileIncludeKey): void {
    if (value.includes(key)) {
      onChange(value.filter((k) => k !== key))
    } else {
      onChange([...value, key])
    }
  }
  return (
    <fieldset className={styles.keyGrid}>
      <legend className={styles.srOnly}>Include keys</legend>
      {ENVFILE_KEYS.map((key) => {
        const checked = value.includes(key)
        return (
          <label key={key} className={styles.keyChip} data-selected={checked}>
            <input
              className={styles.srOnly}
              type="checkbox"
              name="envfile-keys"
              value={key}
              checked={checked}
              onChange={() => toggle(key)}
            />
            <span className={styles.keyName}>{key}</span>
          </label>
        )
      })}
    </fieldset>
  )
}

function defaultFilename(type: TokenType | ''): string {
  switch (type) {
    case 'docx':
      return 'Q4_Bonuses_2024.docx'
    case 'pdf':
      return 'Confidential_Report.pdf'
    case 'kubeconfig':
      return 'kubeconfig'
    case 'envfile':
      return '.env'
    default:
      return ''
  }
}

function descriptorTitle(type: TokenType | ''): string {
  if (type === 'slowredirect') {
    return 'SLOWREDIRECT CONFIG'
  }
  if (type === 'envfile') {
    return 'ENVFILE CONFIG'
  }
  return 'CONFIG'
}
