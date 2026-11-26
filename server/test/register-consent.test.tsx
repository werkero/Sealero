import { describe, expect, it } from 'vitest';
import type { VaultClient } from '../../src/client/contracts';

/**
 * Register-page consent test, via React's server renderer — same harness
 * as landing-render.test.tsx (no jsdom in this repo). The account step
 * must show a Terms/Privacy consent checkbox with links to /terms and
 * /privacy, and the Continue button must start disabled until it is
 * checked.
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

async function renderRegister(): Promise<string> {
  installBrowserStubs();
  const { renderToStaticMarkup } = await import('react-dom/server');
  const { Register } = await import('../../src/pages/Register.tsx');
  const stubClient = {
    register: async () => ({ emailVerificationRequired: true }),
  } as unknown as VaultClient;
  return renderToStaticMarkup(
    <Register
      vaultClient={stubClient}
      onSessionLogin={async () => null}
      onNavigate={() => undefined}
      onAppearanceChange={() => undefined}
    />,
  );
}

describe('Register consent', () => {
  it('shows the Terms/Privacy consent checkbox with links, and starts with Continue disabled', async () => {
    const html = await renderRegister();
    expect(html).toContain('I have read and agree to the');
    expect(html).toContain('href="/terms"');
    expect(html).toContain('Terms of Service');
    expect(html).toContain('href="/privacy"');
    expect(html).toContain('Privacy Policy');
    expect(html).toContain('role="checkbox"');
    expect(html).toContain('aria-checked="false"');
    expect(html).toContain('Continue to vault');
    expect(html).toMatch(/<button[^>]*disabled[^>]*>[^<]*Continue to vault/);
  });
});
