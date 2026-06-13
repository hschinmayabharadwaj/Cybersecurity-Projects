// ===================
// ©AngelaMos | 2026
// artifact.tsx
// ===================

import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import type { Artifact } from '@/api'
import { CopyField, Pill } from '@/components'
import styles from './landing.module.scss'

type ArtifactDisplayProps = {
  artifact: Artifact
  filenameFallback: string
}

export function ArtifactDisplay({
  artifact,
  filenameFallback,
}: ArtifactDisplayProps): React.ReactElement {
  if (artifact.kind === 'url') {
    return <UrlArtifact artifact={artifact} />
  }
  if (artifact.kind === 'file') {
    return (
      <FileArtifact artifact={artifact} filenameFallback={filenameFallback} />
    )
  }
  if (artifact.kind === 'text') {
    return (
      <TextArtifact artifact={artifact} filenameFallback={filenameFallback} />
    )
  }
  return <ConnectionStringArtifact artifact={artifact} />
}

function UrlArtifact({
  artifact,
}: {
  artifact: Extract<Artifact, { kind: 'url' }>
}): React.ReactElement {
  const url = artifact.url ?? ''
  return (
    <div className={styles.artifactStack}>
      <CopyField label="TRIGGER URL" value={url} fullWidth />
      {artifact.destination_url ? (
        <CopyField
          label="DESTINATION"
          value={artifact.destination_url}
          fullWidth
        />
      ) : null}
    </div>
  )
}

function FileArtifact({
  artifact,
  filenameFallback,
}: {
  artifact: Extract<Artifact, { kind: 'file' }>
  filenameFallback: string
}): React.ReactElement {
  const filename = artifact.filename ?? filenameFallback
  const contentType = artifact.content_type ?? 'application/octet-stream'
  const href = useBase64ObjectUrl(artifact.content_b64, contentType)

  if (!href) {
    return <Pill tone="alarm">artifact unreadable</Pill>
  }

  return (
    <div className={styles.artifactStack}>
      <div className={styles.fileBar}>
        <span className={styles.fileMeta}>
          <span className={styles.fileLabel}>FILE</span>
          <span className={styles.fileName}>{filename}</span>
          <span className={styles.fileType}>{contentType}</span>
        </span>
        <a
          className={styles.downloadBtn}
          href={href}
          download={filename}
          onClick={() => toast.success(`Issuing ${filename}`)}
        >
          download
        </a>
      </div>
    </div>
  )
}

function TextArtifact({
  artifact,
  filenameFallback,
}: {
  artifact: Extract<Artifact, { kind: 'text' }>
  filenameFallback: string
}): React.ReactElement {
  const filename = artifact.filename ?? filenameFallback
  const content = artifact.content ?? ''
  const contentType = artifact.content_type ?? 'text/plain'
  const href = useTextObjectUrl(content, contentType)

  return (
    <div className={styles.artifactStack}>
      <div className={styles.fileBar}>
        <span className={styles.fileMeta}>
          <span className={styles.fileLabel}>TEXT</span>
          <span className={styles.fileName}>{filename}</span>
          <span className={styles.fileType}>{contentType}</span>
        </span>
        {href ? (
          <a className={styles.downloadBtn} href={href} download={filename}>
            download
          </a>
        ) : null}
      </div>
      <pre className={styles.textPreview}>{content}</pre>
    </div>
  )
}

function ConnectionStringArtifact({
  artifact,
}: {
  artifact: Extract<Artifact, { kind: 'connection_string' }>
}): React.ReactElement {
  const value = artifact.connection_string ?? ''
  return (
    <div className={styles.artifactStack}>
      <CopyField label="CONNECTION" value={value} fullWidth />
      <p className={styles.note}>
        Open in any MySQL client. The handshake will trip the trap.
      </p>
    </div>
  )
}

function useBase64ObjectUrl(
  b64: string | undefined,
  contentType: string
): string | null {
  const [url, setUrl] = useState<string | null>(null)
  useEffect(() => {
    if (!b64 || b64.length === 0) {
      setUrl(null)
      return
    }
    let created: string | null = null
    try {
      const bytes = base64ToBytes(b64)
      const blob = new Blob([bytes], { type: contentType })
      created = URL.createObjectURL(blob)
      setUrl(created)
    } catch (_err) {
      setUrl(null)
    }
    return () => {
      if (created !== null) {
        URL.revokeObjectURL(created)
      }
    }
  }, [b64, contentType])
  return url
}

function useTextObjectUrl(content: string, contentType: string): string | null {
  const [url, setUrl] = useState<string | null>(null)
  useEffect(() => {
    if (content.length === 0) {
      setUrl(null)
      return
    }
    const blob = new Blob([content], { type: contentType })
    const next = URL.createObjectURL(blob)
    setUrl(next)
    return () => {
      URL.revokeObjectURL(next)
    }
  }, [content, contentType])
  return url
}

function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(b64)
  const len = binary.length
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}
