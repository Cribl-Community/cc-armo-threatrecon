import type { MouseEvent, ReactNode } from 'react';
import { RouterProvider, Spinner, Text, VerticalNavigation } from '@capra/core';
import { Bullseye, Cog, HistoryOutlined, Search } from '@capra/icons';
import { SearchColor } from '@capra/icons/logos';
import { Navigate, Route, Routes, useHref, useLocation, useNavigate, type NavigateOptions } from 'react-router-dom';
import InvestigationPage from './pages/InvestigationPage';
import SavedPage from './pages/SavedPage';
import DetectionsPage from './pages/DetectionsPage';
import SettingsPage from './pages/SettingsPage';
import { useApp } from './state/AppStore';
import { DemoBadge, Pill } from './ui/common';

declare module '@capra/core' {
  interface RouterConfig {
    routerOptions: NavigateOptions;
  }
}

/** VerticalNavigation.Item renders a plain <a>; route client-side and resolve the href under CRIBL_BASE_PATH. */
function NavItem({ to, label, icon, isActive, right }: { to: string; label: string; icon: ReactNode; isActive: boolean; right?: ReactNode }) {
  const navigate = useNavigate();
  const href = useHref(to);
  return (
    <VerticalNavigation.Item
      label={label}
      icon={icon}
      href={href}
      isActive={isActive}
      rightElement={right}
      onClick={(e: MouseEvent) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
        e.preventDefault();
        navigate(to);
      }}
    />
  );
}

export default function App() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const { ready, settings, investigations, detections } = useApp();

  return (
    <RouterProvider navigate={navigate} useHref={useHref}>
      <div className="tr-app">
        <header className="tr-header">
          <div className="tr-brand">
            <span className="tr-brand__mark">
              <SearchColor size="lg" aria-hidden />
            </span>
            <div className="stack" style={{ gap: 0 }}>
              <div className="tr-brand__title">
                <Text as="h1" variant="heading-md">
                  ArMo - Threat Recon
                </Text>
                <Pill tone="brand">Beta</Pill>
                {settings.demoMode && <DemoBadge />}
              </div>
              <Text variant="body-sm-normal" color="secondary">
                From Indicator to Evidence to Detection
              </Text>
            </div>
          </div>
          <div className="tr-header__right">
            <Text variant="body-sm-normal" color="secondary">
              Search. Enrich. Investigate. Turn insights into action.
            </Text>
          </div>
        </header>
        <div className="tr-body">
          <div className="tr-nav">
            <VerticalNavigation aria-label="ArMo - Threat Recon navigation">
              <VerticalNavigation.ItemList>
                <NavItem to="/" label="IOC Investigation" icon={<Search />} isActive={pathname === '/'} />
                <NavItem to="/saved" label="Saved Investigations" icon={<HistoryOutlined />} isActive={pathname === '/saved'} right={investigations.length ? <Pill>{investigations.length}</Pill> : undefined} />
                <NavItem to="/detections" label="Detection Candidates" icon={<Bullseye />} isActive={pathname === '/detections'} right={detections.length ? <Pill>{detections.length}</Pill> : undefined} />
              </VerticalNavigation.ItemList>
              <VerticalNavigation.Footer>
                <NavItem to="/settings" label="Settings" icon={<Cog />} isActive={pathname === '/settings'} />
              </VerticalNavigation.Footer>
            </VerticalNavigation>
          </div>
          <main className="tr-main">
            {!ready ? (
              <div className="empty-hero">
                <Spinner size="lg" title="Loading" />
              </div>
            ) : (
              <Routes>
                <Route path="/" element={<InvestigationPage />} />
                <Route path="/saved" element={<SavedPage />} />
                <Route path="/detections" element={<DetectionsPage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            )}
          </main>
        </div>
      </div>
    </RouterProvider>
  );
}
