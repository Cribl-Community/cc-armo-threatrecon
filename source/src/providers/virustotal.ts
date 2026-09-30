import { isHash } from '../core/ioc.ts';
import { parseVtObject, vtEndpoint, vtError } from '../core/virustotal.ts';
import type { Indicator, VtResult } from '../core/types.ts';
import { isInCribl } from '../platform/cribl.ts';
import { ProviderFailure, type ProviderContext, type ThreatIntelProvider } from './types.ts';

/**
 * Calls VirusTotal through the Cribl App external proxy. The browser never sees
 * the API key: config/proxies.yml injects `x-apikey` from the encrypted App KV
 * value `virustotalApiKey` on the platform side.
 */
export class VirusTotalProvider implements ThreatIntelProvider {
  readonly kind = 'virustotal';
  readonly demo = false;

  async lookup(ind: Indicator, ctx: ProviderContext): Promise<VtResult> {
    if (!isInCribl()) throw new ProviderFailure({ kind: 'unavailable', message: 'VirusTotal is only available when the App runs inside Cribl.' });
    if (!isHash(ind.type) && ind.type !== 'domain' && ind.type !== 'ipv4' && ind.type !== 'ipv6') throw new ProviderFailure({ kind: 'invalid', message: 'Unsupported indicator type for VirusTotal.' });
    let res: Response;
    try {
      res = await fetch(vtEndpoint(ind), { signal: ctx.signal, headers: { accept: 'application/json' } });
    } catch (e) {
      if (e instanceof DOMException && e.name === 'AbortError') throw e;
      throw new ProviderFailure({ kind: 'network', message: 'External lookup failed.', hint: 'Check VirusTotal configuration and that the App may reach www.virustotal.com.' });
    }
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    if (!res.ok) throw new ProviderFailure(vtError(res.status, body));
    return parseVtObject(body, ind);
  }
}
