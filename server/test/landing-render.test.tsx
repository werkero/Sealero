import { describe, expect, it } from 'vitest';

/**
 * Landing-page render test (logged-in vs logged-out), via React's server
 * renderer — no jsdom or component renderer exists in this repo, so the
 * page is rendered to static markup and the header / hero / pricing markup
 * is asserted on. Browser globals are stubbed before the dynamic import
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
    documentElement: { lang: 'en', dataset: { theme: 'light' } as Record<string, string> },
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

async function renderLanding(user: { id: string; email: string } | null): Promise<string> {
  installBrowserStubs();
  const { renderToStaticMarkup } = await import('react-dom/server');
  const { default: Landing } = await import('../../src/pages/Landing.tsx');
  return renderToStaticMarkup(
    <Landing user={user} onNavigate={() => undefined} onAppearanceChange={() => undefined} />,
  );
}

describe('Landing logged-in vs logged-out', () => {
  it('shows the login link and all three register CTAs when logged out', async () => {
    const html = await renderLanding(null);
    expect(html).toContain('href="/login"');
    expect(html).toContain('Sign in');
    expect(html).toContain('Create an account');
    expect(html).toContain('Get started');
    expect(html).toContain('Choose Pro');
    expect(html.match(/href="\/register"/g)?.length).toBe(4);
    expect(html).not.toContain('Enter your vault');
    expect(html).not.toContain('profile-avatar');
  });

  it('shows the avatar and Enter-your-vault hero, and hides every register CTA, when logged in', async () => {
    const html = await renderLanding({ id: 'user-1', email: 'alice@example.test' });
    expect(html).toContain('profile-avatar');
    expect(html).toContain('>A<');
    expect(html).toContain('Enter your vault');
    expect(html).toContain('href="/users/user-1"');
    expect(html).not.toContain('href="/login"');
    expect(html).not.toContain('href="/register"');
    expect(html).not.toContain('Create an account');
    expect(html).not.toContain('Get started');
    expect(html).not.toContain('Choose Pro');
    expect(html).not.toContain('Sign in');
  });

  it('renders the AI screen with the isometric cube visual and four feature points', async () => {
    const html = await renderLanding(null);
    expect(html).toContain('ai-screen');
    expect(html).toContain('Ask your AI for a password');
    expect(html).toContain('Ask once, get your password. No copy-paste.');
    expect(html).toContain('One authorization');
    expect(html).toContain('You approve every time');
    expect(html).toContain('Master password stays with you');
    expect(html).toContain('Valid 5 minutes, single use');
    expect(html).toContain('ai-cubes');
    // Server render runs no effects, so the flow is at phase 0: the first
    // cube is active and the later steps are not done yet.
    expect(html).toContain('ai-cube--active');
    expect(html).not.toContain('ai-cube--done');
    // The old chat demo panel is gone.
    expect(html).not.toContain('AI assistant');
    expect(html).not.toContain('Get me my GitHub password');
    expect(html).not.toContain('Confirmed · valid for 5 minutes');
    expect(html).not.toContain('Password fetched');
  });
});
