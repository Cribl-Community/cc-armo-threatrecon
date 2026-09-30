import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@capra/theme/base.css';
import '@capra/core/styles.css';
import '@capra/icons/styles.css';
import './styles/app.css';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { HostThemeProvider } from './platform/hostTheme';
import { AppStoreProvider } from './state/AppStore';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter basename={window.CRIBL_BASE_PATH || '/'}>
      <HostThemeProvider>
        <AppStoreProvider>
          <App />
        </AppStoreProvider>
      </HostThemeProvider>
    </BrowserRouter>
  </StrictMode>,
);
