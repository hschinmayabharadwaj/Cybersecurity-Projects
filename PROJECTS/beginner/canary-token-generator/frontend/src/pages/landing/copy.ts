// ===================
// ©AngelaMos | 2026
// copy.ts
// ===================

import type { TokenType } from '@/api'

export const PAGE_COPY = {
  HEADLINE: 'CANARIES',
  HEADLINE_LATIN: 'Serinus Canaria · token-form (n.)',
  HEADLINE_PURPOSE:
    'Field-deployable trip-wires for the quiet hours. Each specimen waits in place, reports when touched, and leaves a forensic note behind.',
  STRIP_FIELD_STATION: 'FIELD STATION',
  STRIP_ISSUE: 'ISSUE',
  STRIP_VOLUME: 'VOL.001',
  STRIP_FOLIO: 'FOLIO',
  SECTION_01_INDEX: '01 / SPECIES',
  SECTION_01_TITLE: 'SELECT SPECIES',
  SECTION_01_BODY:
    'Each type lives in a different habitat. Pick the one that fits where the trap will be set.',
  SECTION_02_INDEX: '02 / FIELD LABEL',
  SECTION_02_TITLE: 'ANNOTATE THE SPECIMEN',
  SECTION_02_BODY:
    'A short note describing where this specimen will be deployed. You will see it again when the trap reports.',
  SECTION_03_INDEX: '03 / ALERT ROUTE',
  SECTION_03_TITLE: 'ROUTE THE REPORT',
  SECTION_03_BODY:
    'When the trap is touched, where should the message land? Choose one channel.',
  SECTION_04_INDEX: '04 / SPECIES CONFIG',
  SECTION_04_BODY: 'Configuration specific to the chosen species.',
  SECTION_05_INDEX: '05 / VERIFY',
  SECTION_05_BODY:
    'A one-touch human check from Cloudflare. Skipped in development.',
  SUBMIT_LABEL: 'Release specimen',
  ISSUE_ANOTHER_LABEL: 'Release another',
  RESULT_HEADLINE: 'SPECIMEN ISSUED',
  RESULT_BODY:
    'The trap is live. Keep the manage URL safe — it is the only way back to this dossier.',
} as const

export const TOKEN_BLURB: Record<TokenType, string> = {
  webbug:
    '1×1 transparent pixel. Embed anywhere an <img> works — emails, wiki pages, slide decks.',
  slowredirect:
    'A redirect that pauses to fingerprint the visitor before delivering them. Drop-in short link replacement.',
  docx: 'A Word document that phones home the moment Word renders its footer.',
  pdf: 'A PDF whose embedded URI action fires in Adobe Reader. Quiet against Chromium / PDF.js.',
  kubeconfig:
    'A kubeconfig pointing at a fake Kubernetes API. kubectl calls trigger and are recorded with their verb + path.',
  envfile:
    'A plausible-looking .env file with bait credentials and one disguised canary URL.',
  mysql:
    'A fake MySQL server that answers the handshake, captures the username, then 1045 ACCESS DENIED.',
}

export const ARTIFACT_LABEL = {
  url: 'TRIGGER URL',
  file: 'DOWNLOAD',
  text: 'CONTENT',
  connection_string: 'CONNECTION STRING',
} as const
