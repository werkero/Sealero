import { describe, expect, it } from 'vitest';

/**
 * VaultLayout render test (profile menu + sign-out confirm), via React's
 * server renderer — no jsdom or component renderer exists in this repo, so
 * the layout is rendered to static markup and the initial (closed) state is
 * asserted on: the profile button must be a menu button, not a logout
 * button, and neither the menu nor the confirm dialog may be in the
 * initial markup. Browser globals are stubbed before the dynamic import
 * because src/i18n.ts reads navigator/localStorage/document at import time.
 * This file lives under server/test/ only so the existing vitest run
 * (pnpm test:api) executes it; it tests web UI, not the API.
 */

function installBrowserStubs(): void {
  const storage = new Map<string, string>();
  const localStorageStub = {
    getItem: (key: string): string | null => storage.get(key) ?? null,
    setItem: (key: string, value: string): void => {
      storage.set(key, value);
    },
    removeItem: (key: string): void => {
      storage.delete(key);
    },
  };
  const documentStub = {
    // preferences.ts sets documentElement.style.colorScheme at import time.
    documentElement: { lang: 'en', dataset: { theme: 'light' } as Record<string, string>, style: {} as Record<string, string> },
  };
  const windowStub = {
    localStorage: localStorageStub,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    matchMedia: (): MediaQueryList => ({
      matches: false,
      media: '',
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    }),
  };
  // Node exposes navigator as a getter-only global; assign the rest normally.
  Object.defineProperty(globalThis, 'navigator', {
    value: { languages: ['en'], language: 'en' },
    configurable: true,
  });
  Object.assign(globalThis, {
    window: windowStub,
    document: documentStub,
    localStorage: localStorageStub,
  });
}

async function renderVaultLayout(): Promise<string> {
  installBrowserStubs();
  const { renderToStaticMarkup } = await import('react-dom/server');
  const { VaultLayout } = await import('../../src/App.tsx');
  return renderToStaticMarkup(
    <VaultLayout
      user={{ id: 'user-1', email: 'alice@example.test' }}
      filter="all"
      itemCount={3}
      isAdmin={false}
      onFilterChange={() => undefined}
      onNavigate={() => undefined}
      onLock={() => undefined}
      onLogout={() => undefined}
    >
      <div>vault body</div>
    </VaultLayout>,
  );
}

describe('VaultLayout profile menu and sign-out confirm', () => {
  it('renders the profile control as a menu button, with menu and confirm dialog closed', async () => {
    const html = await renderVaultLayout();
    // Avatar shows the first letter of the email.
    expect(html).toContain('profile-avatar');
    expect(html).toContain('>A<');
    // The profile button opens a menu; it must not act as a logout button.
    expect(html).toContain('aria-haspopup="menu"');
    expect(html).toContain('data-state="closed"');
    // Menu and confirm dialog are state-driven and start closed.
    expect(html).not.toContain('class="profile-menu"');
    expect(html).not.toContain('profile-menu-backdrop');
    expect(html).not.toContain('Lock vault');
    expect(html).not.toContain('confirm-dialog');
    expect(html).not.toContain('Are you sure you want to sign out?');
  });

  it('still offers sign out from the sidebar, without logging out on render', async () => {
    const html = await renderVaultLayout();
    expect(html).toContain('sidebar-sign-out');
    expect(html).toContain('Sign out');
    expect(html).toContain('vault body');
  });
});
