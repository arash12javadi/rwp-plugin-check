import type { CheckOptions, Entries, Finding, Report, Verdict } from './types';
import { CLIENT_FILE, SOURCE_FILE, checkSource } from './code';
import { checkSql, createdTables } from './sql';
import { lineAt } from './scan';

/**
 * The plugin checker: takes the files of a plugin ZIP (already unpacked, see `zip.ts`) and returns a
 * report. Pure: no DOM, no network, nothing is written or installed. It runs in the admin before a
 * plugin is uploaded, and in node for the tests.
 *
 * What it can and cannot tell you is part of the report (`scope`): it reads the source and finds the
 * mistakes an AI converter makes most (invented `rwp_` names, leftover WordPress code, missing row
 * level security, secrets, files that do not exist); it does not build or run the plugin.
 */

/** Ids of plugins that ship with the product; an upload may not take one of them. */
const RESERVED_IDS = new Set([
  'rwp-page-builder', 'rwp-shop', 'rwp-chat', 'rwp-code-snippets', 'rwp-ai-factory', 'rwp-saas-installer',
  'rwp-plugin-marketplace', 'rwp-owner-vault', 'rwp-plugin-check', 'persian-origins',
]);

const ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const MAX_FILES = 5000;
const DANGEROUS_FILE = /\.(?:exe|dll|so|dylib|bat|cmd|ps1|sh|msi|scr|jar|apk)$/i;
const TEXT_FILE = /\.(?:tsx?|jsx?|mjs|cjs|json|sql|md|css|html?|txt|svg)$/i;

const decoder = new TextDecoder('utf-8');
const textOf = (value: Uint8Array | string): string =>
  (typeof value === 'string' ? value : decoder.decode(value)).replace(/^﻿/, '');

const make = (
  severity: Finding['severity'], code: string, message: string, fix?: string, file?: string, line?: number,
): Finding => ({ severity, code, message, fix, file, line });

const ORDER = { error: 0, warning: 1, info: 2 } as const;

export function checkPlugin(entries: Entries, options: CheckOptions): Report {
  const findings: Finding[] = [];
  const files = new Set(entries.keys());
  const text = new Map<string, string>();
  for (const [name, value] of entries) {
    if (TEXT_FILE.test(name) || typeof value === 'string') text.set(name, textOf(value));
  }

  // ----- structure -------------------------------------------------------------------------------
  let manifest: Record<string, unknown> | null = null;
  if (!files.has('manifest.json')) {
    findings.push(make('error', 'structure.no-manifest', 'manifest.json is missing. Every plugin needs one at the top of the ZIP.',
      'Add a manifest.json with an id, a name and a version.', 'manifest.json'));
  } else {
    try {
      const parsed = JSON.parse(text.get('manifest.json') || '');
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) manifest = parsed as Record<string, unknown>;
      else findings.push(make('error', 'structure.manifest-shape', 'manifest.json must contain a JSON object.', undefined, 'manifest.json'));
    } catch (error) {
      findings.push(make('error', 'structure.manifest-json', `manifest.json is not valid JSON: ${(error as Error).message}.`,
        'Fix the JSON (a trailing comma or a missing quote is the usual cause).', 'manifest.json'));
    }
  }
  if (manifest) {
    const id = manifest.id;
    if (typeof id !== 'string' || !ID_PATTERN.test(id)) {
      findings.push(make('error', 'structure.manifest-id',
        `"id" must be 1-64 lowercase letters, digits or hyphens, starting with a letter or digit (got ${JSON.stringify(id)}).`,
        'Use something like "my-plugin".', 'manifest.json'));
    } else if (RESERVED_IDS.has(id)) {
      findings.push(make('error', 'structure.reserved-id', `The id "${id}" belongs to a plugin that already ships with React-WP, so this one cannot be installed beside it.`,
        'Choose a different id.', 'manifest.json'));
    }
    if (typeof manifest.name !== 'string' || !manifest.name.trim() || manifest.name.length > 200) {
      findings.push(make('error', 'structure.manifest-name', '"name" must be a non-empty string of at most 200 characters.', undefined, 'manifest.json'));
    }
    if (typeof manifest.version !== 'string' || !VERSION_PATTERN.test(manifest.version)) {
      findings.push(make('error', 'structure.manifest-version', `"version" must look like 1.2.3 (got ${JSON.stringify(manifest.version)}).`, undefined, 'manifest.json'));
    }
    if (manifest.edition === 'dev') {
      findings.push(make('warning', 'structure.dev-edition', 'The manifest says "edition": "dev". A plugin marked that way is never loaded in a site build.',
        'Remove the "edition" field.', 'manifest.json'));
    }
    if (typeof manifest.entry === 'string' && manifest.entry.replace(/^\.\//, '') !== 'index.tsx') {
      findings.push(make('warning', 'structure.entry', `"entry" is ${JSON.stringify(manifest.entry)}, but the site's build always loads index.tsx.`,
        'Use "./index.tsx".', 'manifest.json'));
    }
  }
  if (!files.has('index.tsx')) {
    findings.push(make('error', 'structure.no-index', 'index.tsx is missing next to manifest.json. The site\'s build loads the plugin from plugins/<id>/index.tsx.',
      'Add index.tsx, which registers the plugin with defineRwpPlugin.', 'index.tsx'));
  } else {
    const index = text.get('index.tsx') || '';
    if (!/\b(?:defineRwpPlugin|registerPlugin)\b/.test(index)) {
      findings.push(make('warning', 'structure.not-registered', 'index.tsx never calls defineRwpPlugin (or registerPlugin), so nothing the plugin does is registered.',
        'Export the plugin with defineRwpPlugin(manifest, ({ admin, shortcodes, routes }) => { … }).', 'index.tsx'));
    }
  }
  if (files.size > MAX_FILES) {
    findings.push(make('error', 'structure.too-many-files', `The ZIP has ${files.size} files; the limit is ${MAX_FILES}.`));
  }
  for (const name of files) {
    if (DANGEROUS_FILE.test(name)) {
      findings.push(make('error', 'structure.executable', `\`${name}\` is an executable or script file. A plugin must not carry programs.`, 'Remove it.', name));
    } else if (/(^|\/)\.env(?:\.|$)/i.test(name) && !/\.example$/i.test(name)) {
      findings.push(make('error', 'structure.env-file', `\`${name}\` looks like an environment file, which usually holds secrets and would be copied to every site.`, 'Remove it.', name));
    } else if (/\.php$/i.test(name)) {
      findings.push(make('warning', 'structure.php-file', `\`${name}\` is PHP. PHP files do nothing in React-WP.`, 'Convert the logic to TypeScript or drop the file.', name));
    } else if (/(^|\/)node_modules\//.test(name) || /(^|\/)\.git\//.test(name)) {
      findings.push(make('warning', 'structure.junk-folder', `\`${name}\` belongs to a development folder that should not be in a plugin ZIP.`, 'Leave node_modules and .git out of the ZIP.', name));
    }
  }

  // ----- database block and SQL --------------------------------------------------------------------
  const database = manifest?.database && typeof manifest.database === 'object' ? manifest.database as Record<string, unknown> : null;
  const sqlFiles = [...files].filter((name) => /\.sql$/i.test(name));
  const schemaPath = typeof database?.schema === 'string' ? database.schema.replace(/^\.\//, '') : '';
  const uninstallPath = typeof database?.uninstall === 'string' ? database.uninstall.replace(/^\.\//, '') : '';
  if (sqlFiles.length && !database) {
    findings.push(make('warning', 'structure.sql-undeclared', 'The ZIP has .sql files but the manifest has no "database" block, so nothing runs them when the plugin is activated.',
      'Declare them: "database": { "schema": "./schema.sql", "uninstall": "./uninstall.sql", "tables": [ … ] }.', 'manifest.json'));
  }
  for (const [label, declared] of [['schema', schemaPath], ['uninstall', uninstallPath]] as const) {
    if (declared && !files.has(declared)) {
      findings.push(make('error', 'structure.sql-missing', `The manifest names ${declared} as the ${label} file, but it is not in the ZIP.`, 'Add the file or fix the path.', 'manifest.json'));
    }
  }
  let tablesCreated: string[] = [];
  for (const name of sqlFiles) {
    const sql = text.get(name) || '';
    const isUninstall = /uninstall/i.test(name) || name === uninstallPath;
    findings.push(...checkSql(name, sql, { uninstall: isUninstall }));
    if (!isUninstall) tablesCreated = tablesCreated.concat(createdTables(sql));
  }
  if (tablesCreated.length && !uninstallPath && !sqlFiles.some((name) => /uninstall/i.test(name))) {
    findings.push(make('warning', 'structure.no-uninstall', 'The plugin creates tables but has no uninstall.sql, so an administrator can never remove its data.',
      'Add an uninstall.sql that drops only what schema.sql creates.', 'manifest.json'));
  }
  if (database && Array.isArray(database.tables) && tablesCreated.length) {
    const declared = new Set((database.tables as unknown[]).map(String));
    const missing = tablesCreated.filter((name) => !declared.has(name));
    if (missing.length) {
      findings.push(make('warning', 'structure.tables-undeclared', `schema.sql creates ${missing.join(', ')}, which the manifest's "database.tables" does not list. The uninstall backup only exports declared tables.`,
        'List every table the schema creates.', 'manifest.json'));
    }
  }

  // ----- source files ------------------------------------------------------------------------------
  const sources = [...files].filter((name) => SOURCE_FILE.test(name) && !/(^|\/)node_modules\//.test(name));
  for (const name of sources) {
    const source = text.get(name);
    if (source === undefined) continue;
    findings.push(...checkSource(name, source, options.names, files));
    if (options.syntax) {
      for (const problem of options.syntax(name, source)) {
        findings.push(make('error', 'syntax.error', `Syntax error: ${problem.message}`,
          'Fix the line; the build stops on it.', name, problem.line));
      }
    }
  }
  for (const name of files) {
    if (/\.json$/i.test(name) && name !== 'manifest.json') {
      try {
        JSON.parse(text.get(name) || '');
      } catch (error) {
        findings.push(make('error', 'syntax.json', `${name} is not valid JSON: ${(error as Error).message}.`, undefined, name));
      }
    }
  }
  // Client files that look like server code.
  for (const name of sources.filter(CLIENT_FILE)) {
    const source = text.get(name) || '';
    const hit = /\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE)\b/.exec(source);
    if (hit) {
      findings.push(make('warning', 'structure.route-in-client', 'This looks like a route handler, but routes only run from server.mjs.',
        'Move it into server.mjs.', name, lineAt(source, hit.index)));
    }
  }

  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]
    || (a.file || '').localeCompare(b.file || '') || (a.line || 0) - (b.line || 0));

  const counts = {
    error: findings.filter((f) => f.severity === 'error').length,
    warning: findings.filter((f) => f.severity === 'warning').length,
    info: findings.filter((f) => f.severity === 'info').length,
  };
  const verdict: Verdict = counts.error ? 'fail' : counts.warning ? 'warn' : 'pass';

  return {
    plugin: {
      id: typeof manifest?.id === 'string' ? manifest.id : undefined,
      name: typeof manifest?.name === 'string' ? manifest.name : undefined,
      version: typeof manifest?.version === 'string' ? manifest.version : undefined,
    },
    verdict,
    findings,
    counts,
    files: files.size,
    scope: [
      'Read: manifest, file structure, imports, JavaScript/TypeScript source, SQL files.',
      options.syntax ? 'Syntax of every source file was checked.' : 'Syntax was not checked in this environment.',
      'Not done: the plugin was not built or run, types were not checked, and behaviour was not tested. A pass means none of the common mistakes was found, not that the plugin works.',
    ],
  };
}
