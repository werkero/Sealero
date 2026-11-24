import type { CloudFile, CloudStorage } from './cloud-backup.ts'

/**
 * WebDAV destination (PRD §9.1: V1, mandatory). Plain HTTPS + Basic auth.
 * Credentials live only in local browser storage (System Design §6) and are
 * passed in here; this module never persists them itself.
 *
 * `fetchFn` is injectable so tests can run without a network.
 */

export interface WebDavConfig {
  /** Base collection URL, e.g. `https://nas.example.test/dav/Sealero`. No trailing slash needed. */
  baseUrl: string
  username: string
  password: string
  fetchFn?: typeof fetch
}

function isLocalOrPrivateHost(hostname: string): boolean {
  const host = hostname.toLowerCase()
  if (host === 'localhost' || host === '::1' || host === '[::1]' || host.endsWith('.localhost') || host.endsWith('.local')) return true
  if (host === '127.0.0.1' || host.startsWith('127.')) return true
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host)
  if (ipv4) {
    const [a, b] = [Number(ipv4[1]), Number(ipv4[2])]
    if (a === 10) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
  }
  // Single-label hostnames (e.g. http://nas/) only resolve on the local network.
  if (!host.includes('.')) return true
  return false
}

function trimBaseUrl(baseUrl: string): string {
  const trimmed = baseUrl.trim().replace(/\/+$/, '')
  if (trimmed.startsWith('https://')) return trimmed
  if (trimmed.startsWith('http://')) {
    // Plain HTTP is only acceptable for a local NAS / loopback address:
    // over a public network the Basic password travels in cleartext.
    let hostname: string
    try {
      hostname = new URL(trimmed).hostname
    } catch {
      throw new Error('cloud_webdav_invalid_url')
    }
    if (isLocalOrPrivateHost(hostname)) return trimmed
    throw new Error('cloud_webdav_insecure_url')
  }
  throw new Error('cloud_webdav_invalid_url')
}

function basicAuth(username: string, password: string): string {
  // Encode to UTF-8 bytes first: bare `btoa` throws on non-Latin-1 input.
  const bytes = new TextEncoder().encode(`${username}:${password}`)
  let binary = ''
  const chunk = 0x8000
  for (let index = 0; index < bytes.length; index += chunk) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunk))
  }
  return `Basic ${btoa(binary)}`
}

function decodeHref(href: string): string {
  try {
    return decodeURIComponent(href)
  } catch {
    return href
  }
}

/** Extracts resource paths from a PROPFIND multistatus body (Depth: 1). */
export function parsePropfindHrefs(body: string): string[] {
  const hrefs: string[] = []
  const pattern = /<(?:\w+:)?href>([^<]*)<\/(?:\w+:)?href>/gi
  let match: RegExpExecArray | null
  while ((match = pattern.exec(body)) !== null) {
    hrefs.push(decodeHref(match[1]!.trim()))
  }
  return hrefs
}

export class WebDavClient implements CloudStorage {
  readonly destination = 'webdav' as const
  private readonly baseUrl: string
  private readonly authHeader: string
  private readonly fetchFn: typeof fetch

  constructor(config: WebDavConfig) {
    this.baseUrl = trimBaseUrl(config.baseUrl)
    if (!config.username) throw new Error('cloud_webdav_missing_credentials')
    this.authHeader = basicAuth(config.username, config.password)
    this.fetchFn = config.fetchFn ?? fetch
  }

  private async request(path: string, init: RequestInit): Promise<Response> {
    const response = await this.fetchFn(`${this.baseUrl}${path}`, {
      ...init,
      headers: { Authorization: this.authHeader, ...(init.headers ?? {}) },
    })
    return response
  }

  async testConnection(): Promise<void> {
    const response = await this.request('', { method: 'PROPFIND', headers: { Depth: '0' } })
    if (response.status !== 207 && response.status !== 200) throw new Error('cloud_webdav_connection_failed')
  }

  async upload(filename: string, data: Uint8Array): Promise<void> {
    const response = await this.request(`/${encodeURIComponent(filename)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: data as BodyInit,
    })
    if (response.status !== 200 && response.status !== 201 && response.status !== 204) throw new Error('cloud_upload_failed')
  }

  async list(): Promise<CloudFile[]> {
    const response = await this.request('', { method: 'PROPFIND', headers: { Depth: '1', 'Content-Type': 'application/xml' } })
    if (response.status !== 207 && response.status !== 200) throw new Error('cloud_list_failed')
    const body = await response.text()
    const basePath = new URL(this.baseUrl).pathname.replace(/\/+$/, '')
    return parsePropfindHrefs(body)
      .map((href) => {
        const path = new URL(href, this.baseUrl).pathname.replace(/\/+$/, '')
        return path.slice(basePath.length + 1)
      })
      .filter((name) => name.length > 0 && !name.includes('/'))
      .map((name) => ({ name }))
  }

  async deleteFile(file: CloudFile): Promise<void> {
    const response = await this.request(`/${encodeURIComponent(file.name)}`, { method: 'DELETE' })
    if (response.status !== 200 && response.status !== 204 && response.status !== 404) throw new Error('cloud_delete_failed')
  }
}
