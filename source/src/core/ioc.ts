import type { Indicator, IocType } from './types.ts';

export const IOC_TYPE_LABELS: Record<IocType, string> = {
  ipv4: 'IP Address (IPv4)',
  ipv6: 'IP Address (IPv6)',
  domain: 'Domain',
  md5: 'MD5',
  sha1: 'SHA-1',
  sha256: 'SHA-256',
};

export const isIp = (t: IocType) => t === 'ipv4' || t === 'ipv6';
export const isHash = (t: IocType) => t === 'md5' || t === 'sha1' || t === 'sha256';

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const HEX = /^[0-9a-f]+$/;
const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const TLD = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;

export function isValidIpv4(v: string): boolean {
  return IPV4.test(v);
}

export function isValidIpv6(v: string): boolean {
  if (!v.includes(':') || v.length > 45) return false;
  let s = v.toLowerCase();
  const lastColon = s.lastIndexOf(':');
  const tail = s.slice(lastColon + 1);
  if (tail.includes('.')) {
    // Embedded IPv4 (e.g. ::ffff:192.0.2.1) counts as two 16-bit groups.
    if (!isValidIpv4(tail)) return false;
    s = `${s.slice(0, lastColon + 1)}0:0`;
  }
  const dbl = s.split('::');
  if (dbl.length > 2) return false;
  const parts = (x: string) => (x === '' ? [] : x.split(':'));
  const all = [...parts(dbl[0]), ...(dbl.length === 2 ? parts(dbl[1]) : [])];
  if (!all.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return false;
  return dbl.length === 2 ? all.length < 8 : all.length === 8;
}

export function isValidDomain(v: string): boolean {
  if (v.length > 253 || !v.includes('.')) return false;
  const labels = v.split('.');
  if (labels.some((l) => !LABEL.test(l))) return false;
  return TLD.test(labels[labels.length - 1]);
}

/** Candidate types for a trimmed, lower-cased value. Hashes and IPs are unambiguous; domains last. */
export function candidateTypes(value: string): IocType[] {
  const v = value.trim().toLowerCase();
  if (!v) return [];
  if (isValidIpv4(v)) return ['ipv4'];
  if (isValidIpv6(v)) return ['ipv6'];
  if (HEX.test(v)) {
    if (v.length === 32) return ['md5'];
    if (v.length === 40) return ['sha1'];
    if (v.length === 64) return ['sha256'];
    return [];
  }
  const d = v.endsWith('.') ? v.slice(0, -1) : v;
  if (isValidDomain(d)) return ['domain'];
  return [];
}

/**
 * Normalization never changes meaning: trim, lower-case hashes/domains/IPv6,
 * drop a single trailing root dot on domains. IPv6 is not compressed/expanded.
 */
export function normalize(raw: string, type: IocType): string {
  const v = raw.trim();
  switch (type) {
    case 'ipv4':
      return v;
    case 'ipv6':
      return v.toLowerCase();
    case 'domain':
      return (v.endsWith('.') ? v.slice(0, -1) : v).toLowerCase();
    default:
      return v.toLowerCase();
  }
}

export function isValidFor(value: string, type: IocType): boolean {
  switch (type) {
    case 'ipv4':
      return isValidIpv4(value);
    case 'ipv6':
      return isValidIpv6(value);
    case 'domain':
      return isValidDomain(value);
    case 'md5':
      return HEX.test(value) && value.length === 32;
    case 'sha1':
      return HEX.test(value) && value.length === 40;
    case 'sha256':
      return HEX.test(value) && value.length === 64;
  }
}

export type ParseResult = { ok: true; indicator: Indicator } | { ok: false; reason: 'empty' | 'unrecognized' | 'invalid_for_type' | 'too_long'; message: string };

/** Parse user input; `manualType` overrides auto-detection but must still validate. */
export function parseIndicator(raw: string, manualType?: IocType): ParseResult {
  const trimmed = raw.trim();
  if (!trimmed) return { ok: false, reason: 'empty', message: 'Enter an IP address, domain, MD5, SHA-1 or SHA-256.' };
  if (trimmed.length > 253) return { ok: false, reason: 'too_long', message: 'Indicator is too long.' };
  if (/\s/.test(trimmed)) return { ok: false, reason: 'unrecognized', message: 'Enter a single indicator without spaces.' };
  const type = manualType ?? candidateTypes(trimmed)[0];
  if (!type) return { ok: false, reason: 'unrecognized', message: 'Unable to determine IOC type.' };
  const value = normalize(trimmed, type);
  if (!isValidFor(value, type)) return { ok: false, reason: 'invalid_for_type', message: `Not a valid ${IOC_TYPE_LABELS[type]}.` };
  return { ok: true, indicator: { raw, value, type } };
}

/** Mask an indicator for diagnostics so full IOC values are never logged. */
export function maskIndicator(value: string): string {
  if (value.length <= 6) return '***';
  return `${value.slice(0, 3)}…${value.slice(-2)}`;
}
