import { lazy, Suspense } from 'react';
import { defineRwpPlugin, type RwpAdminPageProps } from '../../src/lib/plugin-api';
import manifest from './manifest.json';

/**
 * Plugin Check.
 *
 * One admin screen: drop a plugin ZIP, read a plain-language report. The check runs entirely in the
 * browser (`lib/check.ts` is pure) and installs nothing. The screen is a lazy chunk, so a visitor to the
 * public site downloads none of it, and the name tables and the TypeScript compiler it uses load only
 * when a check actually runs.
 */

const PluginCheckAdmin = lazy(() => import('./admin/PluginCheckAdmin'));

const loading = <div style={{ padding: 40, font: '500 15px system-ui', color: '#475569' }} role="status">Loading…</div>;

function AdminScreen(props: RwpAdminPageProps) {
  return <Suspense fallback={loading}><PluginCheckAdmin {...props} /></Suspense>;
}

export const pluginCheckCleanup = defineRwpPlugin(manifest, ({ admin }) => {
  const cleanup = admin.registerPage({
    id: 'rwp-plugin-check',
    label: 'Plugin Check',
    icon: '🛡️',
    // The ZIP is chosen on this computer and read here; the screen is for the people who may install
    // plugins at all.
    capability: 'manage_options',
    component: AdminScreen,
  });
  return () => cleanup();
});

if (import.meta.hot) {
  import.meta.hot.dispose(() => {
    pluginCheckCleanup();
  });
}
