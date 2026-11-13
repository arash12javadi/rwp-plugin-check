import type { Finding } from './types';
import { splitSql } from './scan';

/**
 * Rules for a plugin's `schema.sql` / `uninstall.sql`.
 *
 * They are the rules this project's own `schema.sql` files live by (re-runnable, row level security,
 * safe SECURITY DEFINER functions) plus the ones the automatic database update enforces: a schema
 * file that drops, deletes or rewrites rows is never run by the guard and leaves the site waiting for a
 * manual step.
 */

/** Core tables a plugin must not create or redefine. */
export const CORE_TABLES = new Set([
  'pages', 'categories', 'comments', 'profiles', 'profile_details', 'options', 'menus', 'media', 'media_folders',
  'plugins', 'theme_settings', 'rwp_quota_overrides', 'rwp_role_capabilities', 'rwp_user_capabilities',
  'rwp_translations', 'likes', 'follows', 'taxonomy_follows', 'bookmarks', 'page_views', 'rwp_view_salts',
  'rwp_security_secrets', 'rwp_meta', 'rwp_terms', 'rwp_term_relationships', 'system_settings',
]);

const PGCRYPTO = /(?<![.\w])(gen_random_bytes|crypt|digest|hmac|gen_salt)\s*\(/gi;
const ident = String.raw`(?:"[^"]+"|[A-Za-z_][\w$]*)`;
const qualified = String.raw`(?:${ident}\.)?${ident}`;
const bare = (value: string) => value.replace(/"/g, '').replace(/^public\./i, '').toLowerCase();

const finding = (
  severity: Finding['severity'], code: string, file: string, line: number, message: string, fix?: string,
): Finding => ({ severity, code, file, line, message, fix });

export function checkSql(file: string, sql: string, options: { uninstall: boolean }): Finding[] {
  const out: Finding[] = [];
  const statements = splitSql(sql);
  const lower = statements.map((s) => ({ ...s, raw: s.text, text: s.text.replace(/\s+/g, ' ') }));
  const created = new Map<string, number>();
  const rls = new Set<string>();
  const droppedPolicies = new Set<string>();
  const droppedTriggers = new Set<string>();
  const revoked = new Set<string>();
  let notified = false;

  for (const { text, line, raw } of lower) {
    let m: RegExpExecArray | null;
    if ((m = new RegExp(String.raw`^drop policy if exists (${ident}) on (${qualified})`, 'i').exec(text))) {
      droppedPolicies.add(`${bare(m[1])}@${bare(m[2])}`);
    }
    if ((m = new RegExp(String.raw`^drop trigger if exists (${ident}) on (${qualified})`, 'i').exec(text))) {
      droppedTriggers.add(`${bare(m[1])}@${bare(m[2])}`);
    }
    if ((m = new RegExp(String.raw`^alter table (?:only )?(?:if exists )?(${qualified}) enable row level security`, 'i').exec(text))) {
      rls.add(bare(m[1]));
    }
    if (/^revoke execute on function/i.test(text)) {
      for (const f of text.matchAll(new RegExp(String.raw`function (${qualified})`, 'gi'))) revoked.add(bare(f[1]).split('.').pop() || '');
    }
    if (/^notify pgrst/i.test(text)) notified = true;

    if (options.uninstall) continue;

    // ----- tables
    if ((m = new RegExp(String.raw`^create (?:unlogged |temporary |temp )?table (if not exists )?(${qualified})`, 'i').exec(text))) {
      const name = bare(m[2]);
      created.set(name, line);
      if (!m[1]) {
        out.push(finding('error', 'sql.table-not-rerunnable', file, line,
          `\`create table ${name}\` has no \`if not exists\`. Schema files are re-run (a partial failure, a re-activation), and the second run stops here.`,
          'Write `create table if not exists`.'));
      }
      if (CORE_TABLES.has(name)) {
        out.push(finding('error', 'sql.core-table', file, line,
          `\`${name}\` is a core table. A plugin must never create or redefine core tables.`,
          'Use your own table with a prefix that names the plugin.'));
      }
    }
    if ((m = new RegExp(String.raw`^create (?:unique )?index (?:concurrently )?(if not exists )?`, 'i').exec(text)) && !m[1]) {
      out.push(finding('error', 'sql.index-not-rerunnable', file, line,
        'An index is created without `if not exists`, so a second run fails.',
        'Write `create index if not exists`.'));
    }
    if (/^alter table .* add column (?!if not exists)/i.test(text)) {
      out.push(finding('error', 'sql.column-not-rerunnable', file, line,
        'A column is added without `if not exists`, so a second run fails.',
        'Write `add column if not exists`.'));
    }
    if (new RegExp(String.raw`^create (?!or replace)(?:aggregate |procedure )?function `, 'i').test(text)) {
      out.push(finding('error', 'sql.function-not-rerunnable', file, line,
        '`create function` has no `or replace`, so a second run fails.',
        'Write `create or replace function`.'));
    }
    if (/^create type /i.test(text)) {
      out.push(finding('warning', 'sql.type-not-rerunnable', file, line,
        '`create type` fails when the type exists, and Postgres has no `if not exists` for it.',
        'Wrap it in a DO block that checks pg_type first.'));
    }
    if ((m = new RegExp(String.raw`^create policy (${ident}) on (${qualified})`, 'i').exec(text))) {
      if (!droppedPolicies.has(`${bare(m[1])}@${bare(m[2])}`)) {
        out.push(finding('error', 'sql.policy-not-rerunnable', file, line,
          `Policy ${m[1]} is created without a \`drop policy if exists\` for the same name just before it, so a re-run fails ("already exists").`,
          `Add \`drop policy if exists ${m[1]} on ${m[2]};\` before it.`));
      }
    }
    if ((m = new RegExp(String.raw`^create (?:or replace )?(?:constraint )?trigger (${ident}) .*? on (${qualified})`, 'i').exec(text))) {
      if (!droppedTriggers.has(`${bare(m[1])}@${bare(m[2])}`)) {
        out.push(finding('error', 'sql.trigger-not-rerunnable', file, line,
          `Trigger ${m[1]} is created without a \`drop trigger if exists\` first, so a re-run fails.`,
          `Add \`drop trigger if exists ${m[1]} on ${m[2]};\` before it.`));
      }
    }

    // ----- statements the automatic updater refuses
    const refused: Array<[RegExp, string]> = [
      [/^drop (?:table|schema|type|column)\b/i, 'drops an object'],
      [/^alter table .* drop column\b/i, 'drops a column'],
      [/^truncate\b/i, 'empties a table'],
      [/^delete from\b/i, 'deletes rows'],
      [/^alter table .* rename\b/i, 'renames something'],
      [/^alter table .* alter column .* type\b/i, 'changes a column type'],
    ];
    for (const [pattern, what] of refused) {
      if (pattern.test(text)) {
        out.push(finding('error', 'sql.destructive', file, line,
          `This statement ${what}. The site's automatic database update refuses it, so the update waits for a manual step on every site.`,
          'Keep schema.sql additive. Put removals in uninstall.sql, and migrate data with a new nullable column.'));
        break;
      }
    }
    if (/^update\b/i.test(text) && !isNullFillUpdate(text)) {
      out.push(finding('error', 'sql.rewrites-rows', file, line,
        'This `update` rewrites existing rows. The automatic database update only allows filling NULL values.',
        'Use `update … set col = … where col is null`, or leave existing rows alone.'));
    }
    if (/^insert\b.*\bon conflict\b.*\bdo update\b/i.test(text)) {
      out.push(finding('error', 'sql.upsert', file, line,
        'An upsert (`on conflict … do update`) overwrites rows an administrator may have changed. The automatic update refuses it.',
        'Use `on conflict do nothing`.'));
    }

    // ----- functions
    if (/^create (?:or replace )?function /i.test(text)) {
      const name = bare(new RegExp(String.raw`function (${qualified})`, 'i').exec(text)?.[1] || '');
      const definer = /\bsecurity definer\b/i.test(text);
      if (definer) {
        if (!/\bset search_path\b/i.test(text)) {
          out.push(finding('error', 'sql.definer-search-path', file, line,
            `Function ${name} is SECURITY DEFINER without \`set search_path\`. A caller can plant an object with the same name in their own schema and run code with the owner's rights.`,
            'Add `set search_path = public` (and schema-qualify anything outside it).'));
        } else if (!/search_path\s*(?:=|to)\s*[^;$]*?\bextensions\b/i.test(text)) {
          PGCRYPTO.lastIndex = 0;
          // Comments inside a function body are not code: strip them before looking for calls.
          const hit = PGCRYPTO.exec(raw.replace(/--[^\n]*/g, ''));
          if (hit) {
            out.push(finding('error', 'sql.pgcrypto-unqualified', file, line,
              `Function ${name} calls ${hit[1]}() with \`search_path = public\`. On Supabase pgcrypto lives in the \`extensions\` schema, so this raises "function does not exist" (404 from the API), which looks like the function is not installed.`,
              `Call it as \`extensions.${hit[1]}(…)\`.`));
          }
        }
      }
    }
  }

  if (options.uninstall) return out;

  // A schema may enable RLS for several tables in one loop (a DO block over an array of names).
  const loopedRls = lower
    .filter(({ text }) => /enable row level security/i.test(text)
      && !/^alter table (?:only )?(?:if exists )?\S+ enable row level security\s*$/i.test(text))
    .map(({ text }) => text.toLowerCase());
  for (const [name, line] of created) {
    if (!rls.has(name) && !loopedRls.some((text) => text.includes(name))) {
      out.push(finding('error', 'sql.rls-missing', file, line,
        `Table \`${name}\` has no row level security. New tables are readable and writable with the public key by default, so anyone could read or change every row.`,
        `Add \`alter table ${name} enable row level security;\` and a policy for each role that should have access.`));
    }
  }
  for (const { text, line } of lower) {
    const m = new RegExp(String.raw`^create (?:or replace )?function (${qualified})`, 'i').exec(text);
    if (m && /\bsecurity definer\b/i.test(text) && !revoked.has(bare(m[1]).split('.').pop() || '')) {
      out.push(finding('warning', 'sql.definer-executable', file, line,
        `SECURITY DEFINER function ${m[1]} stays executable by anonymous visitors (new functions are executable by anyone).`,
        'If only signed-in users or the server should call it, add `revoke execute on function … from public, anon, authenticated;` and grant what is needed.'));
    }
  }
  if (!notified) {
    out.push(finding('warning', 'sql.no-notify', file, Math.max(1, sql.split('\n').length),
      'The file does not end with `notify pgrst, \'reload schema\';`, so the API may not see new tables or columns until it restarts.',
      'Add `notify pgrst, \'reload schema\';` as the last statement.'));
  }
  return out;
}

/**
 * True for `update T set c = … where c is null [and …]`: every assigned column is tested `is null` in a
 * where with no `or`. Mirrors `isNullFillUpdate` in server/schemaMigrate.mjs, which decides at run time.
 */
function isNullFillUpdate(statement: string): boolean {
  const match = /^update\s+(?:only\s+)?[\w."]+(?:\s+(?:as\s+)?\w+)?\s+set\s+([\s\S]+?)\s+where\s+([\s\S]+)$/i.exec(statement);
  if (!match) return false;
  const [, assignments, condition] = match;
  if (/\bor\b/i.test(condition)) return false;
  const targets = assignments.split(',').map((part) => /^\s*"?(\w+)"?\s*=/.exec(part)?.[1]).filter(Boolean) as string[];
  if (!targets.length) return false;
  return targets.every((column) => new RegExp(`\\b${column}\\s+is\\s+null\\b`, 'i').test(condition));
}

/** The names of tables a schema file creates, for the manifest comparison. */
export function createdTables(sql: string): string[] {
  const names: string[] = [];
  for (const { text } of splitSql(sql)) {
    const m = new RegExp(String.raw`^create (?:unlogged )?table (?:if not exists )?(${qualified})`, 'i').exec(text.replace(/\s+/g, ' '));
    if (m) names.push(bare(m[1]));
  }
  return names;
}
