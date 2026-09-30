import type { ProviderSet } from './types';
import { CriblLookupProvider } from './criblLookups';
import { CriblSearchProvider } from './criblSearch';
import { VirusTotalProvider } from './virustotal';

export const liveProviders = (): ProviderSet => ({
  lookups: new CriblLookupProvider(),
  search: new CriblSearchProvider(),
  virustotal: new VirusTotalProvider(),
});
