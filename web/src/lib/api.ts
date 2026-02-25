const DEFAULT_API_BASE_URL = "http://localhost:3001"
const API_KEY_STORAGE_KEY = "ironveil.api_key"
const JWT_STORAGE_KEY = "ironveil.jwt"

type ApiErrorOptions = {
  status: number
  endpoint: string
  code?: string
  payload?: unknown
}

type ApiErrorPayload = {
  error?: string
  code?: string
}

export class ApiError extends Error {
  status: number
  endpoint: string
  code?: string
  payload?: unknown

  constructor(message: string, options: ApiErrorOptions) {
    super(message)
    this.name = "ApiError"
    this.status = options.status
    this.endpoint = options.endpoint
    this.code = options.code
    this.payload = options.payload
  }
}

function trimTrailingSlash(value: string): string {
  return value.endsWith("/") ? value.slice(0, -1) : value
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null
}

function getResponseStatus(response: Response): number {
  return typeof response.status === "number" ? response.status : 200
}

function isResponseOk(response: Response): boolean {
  return typeof response.ok === "boolean" ? response.ok : true
}

async function readJsonSafely(response: Response): Promise<unknown> {
  try {
    return await response.json()
  } catch {
    return undefined
  }
}

function headersToRecord(headers?: HeadersInit): Record<string, string> {
  if (!headers) {
    return {}
  }

  if (headers instanceof Headers) {
    return Object.fromEntries(headers.entries())
  }

  if (Array.isArray(headers)) {
    return Object.fromEntries(headers)
  }

  return { ...headers }
}

function getAuthHeaders(): Record<string, string> {
  const envApiKey = process.env.NEXT_PUBLIC_IRONVEIL_API_KEY
  const envBearerToken = process.env.NEXT_PUBLIC_IRONVEIL_BEARER_TOKEN

  let apiKey = envApiKey
  let bearerToken = envBearerToken

  if (typeof window !== "undefined") {
    apiKey = localStorage.getItem(API_KEY_STORAGE_KEY) || apiKey
    bearerToken = localStorage.getItem(JWT_STORAGE_KEY) || bearerToken
  }

  const authHeaders: Record<string, string> = {}
  if (apiKey) {
    authHeaders["X-API-Key"] = apiKey
  }
  if (bearerToken) {
    authHeaders.Authorization = `Bearer ${bearerToken}`
  }

  return authHeaders
}

export function getApiBaseUrl(): string {
  const fromEnv = process.env.NEXT_PUBLIC_API_BASE_URL?.trim()
  if (!fromEnv) {
    return DEFAULT_API_BASE_URL
  }
  return trimTrailingSlash(fromEnv)
}

export function buildApiUrl(path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`
  return `${getApiBaseUrl()}${normalizedPath}`
}

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const providedHeaders = headersToRecord(init?.headers)
  const headers = {
    ...getAuthHeaders(),
    ...providedHeaders,
  }

  const requestInit: RequestInit = init ? { ...init } : {}
  if (Object.keys(headers).length > 0) {
    requestInit.headers = headers
  }

  if (Object.keys(requestInit).length === 0) {
    return fetch(buildApiUrl(path))
  }

  return fetch(buildApiUrl(path), requestInit)
}

export async function apiFetchJson<T = unknown>(path: string, init?: RequestInit): Promise<T> {
  const response = await apiFetch(path, init)
  const payload = await readJsonSafely(response)
  const status = getResponseStatus(response)

  if (!isResponseOk(response)) {
    const errorPayload = isRecord(payload) ? (payload as ApiErrorPayload) : undefined
    const message = typeof errorPayload?.error === "string"
      ? errorPayload.error
      : `Request to ${path} failed with status ${status}`
    const code = typeof errorPayload?.code === "string" ? errorPayload.code : undefined

    throw new ApiError(message, {
      status,
      endpoint: path,
      code,
      payload,
    })
  }

  return payload as T
}
