import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { withDefaults, type AppSettings } from '../core/settings';
import type { DetectionCandidate, SavedInvestigation } from '../core/types';
import { getUser, isInCribl, kv } from '../platform/cribl';

/** App-wide keys (per Workspace) and per-user keys. Raw events are never stored. */
const K = {
  settings: 'settings/v1',
  vtStatus: 'virustotal/status',
  /** Encrypted, write-only. Referenced from config/proxies.yml as kv.virustotalApiKey. */
  vtSecret: 'virustotalApiKey',
  invIndex: (u: string) => `users/${u}/investigations/index`,
  inv: (u: string, id: string) => `users/${u}/investigations/${id}`,
  detIndex: (u: string) => `users/${u}/detections/index`,
};

export interface VtStatus {
  configured: boolean;
  updatedAt: string | null;
  updatedBy: string | null;
}

interface Store {
  ready: boolean;
  connected: boolean;
  userId: string;
  userName: string;
  settings: AppSettings;
  saveSettings: (next: AppSettings) => Promise<void>;
  vtStatus: VtStatus;
  setVtKey: (key: string) => Promise<void>;
  clearVtKey: () => Promise<void>;
  investigations: SavedInvestigation[];
  saveInvestigation: (inv: SavedInvestigation) => Promise<void>;
  deleteInvestigation: (id: string) => Promise<void>;
  detections: DetectionCandidate[];
  saveDetection: (d: DetectionCandidate) => Promise<void>;
  deleteDetection: (id: string) => Promise<void>;
  loadError: string | null;
}

const Ctx = createContext<Store | null>(null);

export function AppStoreProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [userId, setUserId] = useState('local');
  const [userName, setUserName] = useState('');
  const [settings, setSettings] = useState<AppSettings>(withDefaults(null));
  const [vtStatus, setVtStatus] = useState<VtStatus>({ configured: false, updatedAt: null, updatedBy: null });
  const [investigations, setInvestigations] = useState<SavedInvestigation[]>([]);
  const [detections, setDetections] = useState<DetectionCandidate[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const invRef = useRef(investigations);
  const detRef = useRef(detections);
  useEffect(() => {
    invRef.current = investigations;
    detRef.current = detections;
  }, [investigations, detections]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const user = await getUser();
        // Each key loads independently: a missing or unreadable key falls back to its default.
        const safe = <T,>(p: Promise<T | null>) => p.catch(() => null);
        const [s, vt, inv, det] = await Promise.all([
          safe(kv.getJson<Partial<AppSettings>>(K.settings)),
          safe(kv.getJson<VtStatus>(K.vtStatus)),
          safe(kv.getJson<SavedInvestigation[]>(K.invIndex(user.id))),
          safe(kv.getJson<DetectionCandidate[]>(K.detIndex(user.id))),
        ]);
        if (cancelled) return;
        setUserId(user.id);
        setUserName(user.firstName ?? user.username);
        // Outside Cribl there is nothing real to query, so demo mode is forced on.
        setSettings({ ...withDefaults(s), demoMode: isInCribl() ? withDefaults(s).demoMode : true });
        if (vt) setVtStatus(vt);
        setInvestigations(inv ?? []);
        setDetections(det ?? []);
      } catch (e) {
        if (!cancelled) setLoadError(e instanceof Error ? e.message : 'Could not load app data');
      } finally {
        if (!cancelled) setReady(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const saveSettings = useCallback(async (next: AppSettings) => {
    setSettings(next);
    await kv.putJson(K.settings, next);
  }, []);

  const setVtKey = useCallback(
    async (key: string) => {
      await kv.put(K.vtSecret, key.trim(), { encrypted: true });
      const st: VtStatus = { configured: true, updatedAt: new Date().toISOString(), updatedBy: userName || userId };
      await kv.putJson(K.vtStatus, st);
      setVtStatus(st);
    },
    [userId, userName],
  );

  const clearVtKey = useCallback(async () => {
    await kv.delete(K.vtSecret);
    const st: VtStatus = { configured: false, updatedAt: new Date().toISOString(), updatedBy: userName || userId };
    await kv.putJson(K.vtStatus, st);
    setVtStatus(st);
  }, [userId, userName]);

  const saveInvestigation = useCallback(
    async (inv: SavedInvestigation) => {
      const next = [inv, ...invRef.current.filter((i) => i.id !== inv.id)].slice(0, 200);
      setInvestigations(next);
      await kv.putJson(K.invIndex(userId), next);
    },
    [userId],
  );

  const deleteInvestigation = useCallback(
    async (id: string) => {
      const next = invRef.current.filter((i) => i.id !== id);
      setInvestigations(next);
      await kv.putJson(K.invIndex(userId), next);
    },
    [userId],
  );

  const saveDetection = useCallback(
    async (d: DetectionCandidate) => {
      const next = [d, ...detRef.current.filter((x) => x.id !== d.id)].slice(0, 200);
      setDetections(next);
      await kv.putJson(K.detIndex(userId), next);
    },
    [userId],
  );

  const deleteDetection = useCallback(
    async (id: string) => {
      const next = detRef.current.filter((x) => x.id !== id);
      setDetections(next);
      await kv.putJson(K.detIndex(userId), next);
    },
    [userId],
  );

  const value = useMemo<Store>(
    () => ({ ready, connected: isInCribl(), userId, userName, settings, saveSettings, vtStatus, setVtKey, clearVtKey, investigations, saveInvestigation, deleteInvestigation, detections, saveDetection, deleteDetection, loadError }),
    [ready, userId, userName, settings, saveSettings, vtStatus, setVtKey, clearVtKey, investigations, saveInvestigation, deleteInvestigation, detections, saveDetection, deleteDetection, loadError],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp() {
  const c = useContext(Ctx);
  if (!c) throw new Error('useApp must be used within AppStoreProvider');
  return c;
}

export const newId = () => `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
