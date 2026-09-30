declare global {
  interface Window {
    CRIBL_API_URL?: string;
    CRIBL_BASE_PATH?: string;
    getCriblUser?: () => Promise<CriblUser>;
  }
}

export interface CriblUser {
  id: string;
  username: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  initials?: string;
}

/** True inside Cribl (installed or Live Preview). Outside Cribl only demo mode works. */
export const isInCribl = () => typeof window.CRIBL_API_URL === 'string' && window.CRIBL_API_URL.length > 0;

export const apiUrl = (path: string) => `${window.CRIBL_API_URL}${path.startsWith('/') ? path : `/${path}`}`;

export class HttpError extends Error {
  readonly status: number;
  readonly body: unknown;
  constructor(status: number, message: string, body?: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

async function readBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export async function criblFetch<T>(path: string, init: RequestInit & { signal?: AbortSignal } = {}): Promise<T> {
  const res = await fetch(apiUrl(path), { ...init, headers: { accept: 'application/json', ...(init.body ? { 'content-type': 'application/json' } : {}), ...(init.headers ?? {}) } });
  const body = await readBody(res);
  if (!res.ok) throw new HttpError(res.status, `HTTP ${res.status}`, body);
  return body as T;
}

let userPromise: Promise<CriblUser> | null = null;
export function getUser(): Promise<CriblUser> {
  if (!userPromise) userPromise = window.getCriblUser ? window.getCriblUser() : Promise.resolve({ id: 'local', username: 'local-demo' });
  return userPromise;
}

// ── App KV store. Outside Cribl it falls back to memory (demo only). ─────
const memoryKv = new Map<string, string>();

export const kv = {
  async get(key: string): Promise<string | null> {
    if (!isInCribl()) return memoryKv.get(key) ?? null;
    const res = await fetch(apiUrl(`/kvstore/${key}`));
    if (res.status === 404) return null;
    if (!res.ok) throw new HttpError(res.status, `KV read failed (${res.status})`);
    const text = await res.text();
    return text === '' ? null : text;
  },
  async put(key: string, value: string, opts: { encrypted?: boolean } = {}): Promise<void> {
    if (!isInCribl()) {
      if (!opts.encrypted) memoryKv.set(key, value);
      return;
    }
    const res = await fetch(apiUrl(`/kvstore/${key}${opts.encrypted ? '?encrypted=true' : ''}`), { method: 'PUT', headers: { 'content-type': 'text/plain;charset=UTF-8' }, body: value });
    if (!res.ok) throw new HttpError(res.status, `KV write failed (${res.status})`);
  },
  async delete(key: string): Promise<void> {
    if (!isInCribl()) {
      memoryKv.delete(key);
      return;
    }
    const res = await fetch(apiUrl(`/kvstore/${key}`), { method: 'DELETE' });
    if (!res.ok && res.status !== 404) throw new HttpError(res.status, `KV delete failed (${res.status})`);
  },
  async getJson<T>(key: string): Promise<T | null> {
    const raw = await kv.get(key);
    if (raw == null) return null;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return null;
    }
  },
  putJson: (key: string, value: unknown) => kv.put(key, JSON.stringify(value)),
};
