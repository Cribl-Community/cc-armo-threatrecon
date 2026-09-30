import { demoProviders } from './demo';
import { liveProviders } from './live';
import type { ProviderSet } from './types';

/** Single switch between real and demo providers. The two are never mixed in one run. */
export function getProviders(demo: boolean): ProviderSet {
  return demo ? demoProviders() : liveProviders();
}
