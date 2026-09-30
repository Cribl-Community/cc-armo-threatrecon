import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { isInCribl } from './cribl';

export type HostTheme = 'light' | 'dark';

/** Applies the Cribl shell's theme (CRIBL_APP_LAYOUT postMessage) to this document. */
export function installThemeBridge(onTheme?: (theme: HostTheme) => void): () => void {
  const onMessage = (event: MessageEvent) => {
    if (event.source !== window.parent) return;
    const data = event.data as { type?: string; theme?: HostTheme } | null;
    if (data?.type !== 'CRIBL_APP_LAYOUT') return;
    if (data.theme !== 'light' && data.theme !== 'dark') return;
    document.body.classList.toggle('dark', data.theme === 'dark');
    onTheme?.(data.theme);
  };
  window.addEventListener('message', onMessage);
  return () => window.removeEventListener('message', onMessage);
}

/** Outside Cribl no host pushes a theme, so local demo follows the OS preference. */
function installLocalFallback(onTheme: (theme: HostTheme) => void): () => void {
  if (isInCribl()) return () => undefined;
  const mq = window.matchMedia('(prefers-color-scheme: dark)');
  const apply = () => {
    document.body.classList.toggle('dark', mq.matches);
    onTheme(mq.matches ? 'dark' : 'light');
  };
  apply();
  mq.addEventListener('change', apply);
  return () => mq.removeEventListener('change', apply);
}

const ThemeContext = createContext<HostTheme>('light');

export function HostThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<HostTheme>(() => (document.body.classList.contains('dark') ? 'dark' : 'light'));
  useEffect(() => {
    const a = installLocalFallback(setTheme);
    const b = installThemeBridge(setTheme);
    return () => {
      a();
      b();
    };
  }, []);
  return <ThemeContext.Provider value={theme}>{children}</ThemeContext.Provider>;
}

export const useHostTheme = () => useContext(ThemeContext);
