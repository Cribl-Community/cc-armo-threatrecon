import type { IocType } from './types.ts';

/**
 * Field names are configurable (Settings) because no schema is guaranteed.
 * Structured-field matching is preferred; raw-text matching is only a fallback.
 */
export interface FieldStrategy {
  ip: string[];
  domain: string[];
  hash: string[];
  sourceHost: string[];
  destinationHost: string[];
  user: string[];
  eventType: string[];
  sourceIp: string[];
  destinationIp: string[];
  destinationPort: string[];
  details: string[];
  /** Also match the IOC as a term in raw event text when no structured field matches. */
  rawFallback: boolean;
}

export const DEFAULT_FIELDS: FieldStrategy = {
  ip: ['src_ip', 'source_ip', 'dst_ip', 'dest_ip', 'destination_ip', 'client_ip', 'server_ip', 'ip', 'remote_addr'],
  domain: ['domain', 'fqdn', 'host', 'url', 'query', 'destination_domain', 'dest_domain'],
  hash: ['md5', 'sha1', 'sha256', 'hash', 'file_hash'],
  sourceHost: ['src_host', 'source_host', 'hostname', 'host', 'computer_name', 'device_name'],
  destinationHost: ['dst_host', 'dest_host', 'destination_host', 'dest', 'server'],
  user: ['user', 'src_user', 'username', 'user_name', 'account'],
  eventType: ['event_type', 'eventtype', 'action', 'type', 'sourcetype', 'category'],
  sourceIp: ['src_ip', 'source_ip', 'client_ip', 'src'],
  destinationIp: ['dst_ip', 'dest_ip', 'destination_ip', 'server_ip', 'dst'],
  destinationPort: ['dst_port', 'dest_port', 'destination_port', 'port'],
  details: ['message', 'msg', 'details', 'signature', 'reason', '_raw'],
  rawFallback: true,
};

export function iocFields(strategy: FieldStrategy, type: IocType): string[] {
  if (type === 'ipv4' || type === 'ipv6') return strategy.ip;
  if (type === 'domain') return strategy.domain;
  return strategy.hash;
}

/** First non-empty value among candidate field names. */
export function pick(fields: Record<string, unknown>, names: string[]): string | null {
  for (const n of names) {
    const v = fields[n];
    if (v === undefined || v === null || v === '') continue;
    return typeof v === 'object' ? JSON.stringify(v) : String(v);
  }
  return null;
}

export const splitList = (s: string) =>
  s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
