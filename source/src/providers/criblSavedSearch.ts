import type { DetectionCandidate } from '../core/types.ts';
import { HttpError, criblFetch, isInCribl } from '../platform/cribl.ts';

/** Saved-search id: lowercase letters, digits and underscores (conservative; naming rules are undocumented). */
export const savedSearchId = (c: DetectionCandidate) =>
  `threat_recon_${c.indicator.value.toLowerCase().replace(/[^a-z0-9]+/g, '_').slice(0, 40)}_${c.id.replace(/[^a-z0-9]/gi, '').slice(-6)}`.toLowerCase();

/**
 * Creates a Cribl Search saved search (POST /m/default_search/search/saved, fields id/name/query required).
 * Called only after an explicit, named confirmation. It creates; it never overwrites.
 */
export async function createSavedSearch(c: DetectionCandidate): Promise<{ id: string }> {
  if (!isInCribl()) throw new Error('Saved searches can only be created inside Cribl.');
  const id = savedSearchId(c);
  try {
    await criblFetch(`/m/default_search/search/saved`, {
      method: 'POST',
      body: JSON.stringify({ id, name: c.name, description: `ArMo - Threat Recon detection candidate. ${c.why}`, query: c.query, earliest: '-24h', latest: 'now' }),
    });
    return { id };
  } catch (e) {
    if (e instanceof HttpError) {
      if (e.status === 401 || e.status === 403) throw new Error('Permission denied: your role cannot create saved searches.');
      if (e.status === 409) throw new Error(`A saved search with id "${id}" already exists.`);
      throw new Error(`Cribl rejected the saved search (HTTP ${e.status}).`);
    }
    throw new Error('Network error while creating the saved search.');
  }
}
