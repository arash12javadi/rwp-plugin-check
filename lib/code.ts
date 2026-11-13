import type { Finding, Names } from './types';
import { closest, lineAt, mask } from './scan';
import { declaredNames, lookupFor, rwpName } from './lookup';

/**
 * Rules for one JavaScript/TypeScript file: leftover WordPress code, names React-WP does not have,
 * unsafe constructs, secrets and imports.
 *
 * These are text heuristics over comment- and string-masked source (`mask`), not a type check. They are
 * tuned to raise a finding only when the cost of a false alarm is a sentence, and the report says so.
 */

export const SOURCE_FILE = /\.(?:tsx?|jsx?|mjs|cjs)$/i;
/** `.mjs`/`.cjs` files are the plugin's server side (server.mjs and the modules it imports). */
export const SERVER_SIDE = (file: string) => /\.(?:mjs|cjs)$/i.test(file);
export const CLIENT_FILE = (file: string) => SOURCE_FILE.test(file) && !SERVER_SIDE(file);

/** Unprefixed WordPress functions worth flagging although their names have no underscore. */
const PLAIN_WP_NAMES = new Set(['absint', 'wpautop', 'trailingslashit', 'untrailingslashit', 'wptexturize', 'sanitize_text_field']);

/** Core modules a plugin may import without a note: they are the documented plugin-facing API. */
const STABLE_CORE = /^src\/lib\/(?:plugin-api|rwp-api|db|i18n|roles|rwp)(?:\/|$)/;

const HOOK_CALL = /(?:\b(?:addAction|addFilter|doAction|applyFilters|hasAction|hasFilter|removeAction|removeFilter|rwp_add_action|rwp_add_filter|rwp_do_action|rwp_apply_filters|rwp_has_action|rwp_has_filter|rwp_remove_action|rwp_remove_filter)|\bactions\s*\.\s*(?:add|do)|\bfilters\s*\.\s*(?:add|apply))\s*\(\s*(['"`])([^'"`$\n]+)\1/g;

const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/\bsk-ant-[A-Za-z0-9_-]{20,}/, 'an Anthropic API key'],
  [/\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/, 'an OpenAI-style API key'],
  [/\bAIza[0-9A-Za-z_-]{30,}/, 'a Google API key'],
  [/\bAKIA[0-9A-Z]{16}\b/, 'an AWS access key'],
  [/\bgh[pousr]_[A-Za-z0-9]{30,}/, 'a GitHub token'],
  [/\b[sr]k_live_[A-Za-z0-9]{16,}/, 'a live Stripe key'],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}/, 'a Slack token'],
  [/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{60,}/, 'a private key'],
  [/\beyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}/, 'a JWT (a Supabase service_role key looks like this)'],
];

const finding = (
  severity: Finding['severity'], code: string, file: string, line: number, message: string, fix?: string,
): Finding => ({ severity, code, file, line, message, fix });

/** Resolves a relative import against the archive; returns true when some candidate exists. */
function resolvesInside(from: string, specifier: string, files: Set<string>): boolean {
  const clean = specifier.replace(/[?#].*$/, '');
  const parts = from.split('/').slice(0, -1);
  for (const part of clean.split('/')) {
    if (part === '.' || part === '') continue;
    if (part === '..') parts.pop();
    else parts.push(part);
  }
  const base = parts.join('/');
  const stem = base.replace(/\.(?:js|jsx|mjs)$/, '');
  const exts = ['', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.json', '.css'];
  for (const candidate of [base, stem]) {
    for (const ext of exts) if (files.has(candidate + ext)) return true;
    for (const ext of exts.slice(1)) if (files.has(`${candidate}/index${ext}`)) return true;
  }
  return false;
}

/** How many folders above the archive root a relative import climbs, and what follows. */
function climbsTo(from: string, specifier: string): { above: number; rest: string } | null {
  const clean = specifier.replace(/[?#].*$/, '');
  const depth = from.split('/').length - 1;
  let level = depth;
  const rest: string[] = [];
  for (const part of clean.split('/')) {
    if (part === '.' || part === '') continue;
    if (part === '..') {
      if (rest.length) rest.pop();
      else level -= 1;
    } else rest.push(part);
  }
  return level < 0 ? { above: -level, rest: rest.join('/') } : null;
}

export function checkSource(
  file: string,
  source: string,
  names: Names,
  allFiles: Set<string>,
): Finding[] {
  const out: Finding[] = [];
  const lookup = lookupFor(names);
  const { noComments, codeOnly } = mask(source);
  const declared = declaredNames(codeOnly);
  const isServer = SERVER_SIDE(file);
  const isRouteFile = /(^|\/)server\.mjs$/.test(file);
  const at = (offset: number) => lineAt(source, offset);
  /** True when the text at `offset` is code, not the inside of a string (a prompt or a code sample). */
  const inCode = (offset: number) => codeOnly[offset] !== ' ' && codeOnly[offset] === noComments[offset];

  // ----- leftover PHP / WordPress ---------------------------------------------------------------
  const php = /<\?php|<\?=/.exec(noComments);
  if (php) {
    out.push(finding('error', 'wp.php-code', file, at(php.index),
      'PHP code is inside a JavaScript file. PHP does not run in React-WP.',
      'Rewrite it in TypeScript/React. Echoed HTML becomes JSX; database calls become the database client.'));
  }
  for (const match of codeOnly.matchAll(/\$wpdb\b|\$_(?:GET|POST|REQUEST|SERVER|COOKIE|SESSION|FILES)\b|\bglobal\s+\$\w+/g)) {
    out.push(finding('error', 'wp.php-variable', file, at(match.index ?? 0),
      `\`${match[0]}\` is a PHP/WordPress variable. It does not exist here.`,
      'Use the database client for data, the signed-in session for the user, and a plugin server route for server-side work.'));
    break;
  }
  for (const match of codeOnly.matchAll(/\b(ABSPATH|WPINC|WP_CONTENT_DIR|WP_PLUGIN_DIR|WP_CONTENT_URL|WP_DEBUG|DB_NAME|DB_HOST)\b/g)) {
    out.push(finding('error', 'wp.constant', file, at(match.index ?? 0),
      `\`${match[1]}\` is a WordPress constant. React-WP has no such constant.`,
      'Remove it; there is no wp-config or file path to read.'));
    break;
  }
  for (const match of codeOnly.matchAll(/\bnew\s+(WP_[A-Za-z_]+)|\b(WP_(?:Query|Post|User|Term|Comment|Roles|Role|Widget|Meta_Query|Tax_Query|Rewrite|Screen|Hook))\b/g)) {
    const cls = match[1] || match[2];
    if (declared.has(cls)) continue;
    out.push(finding('error', 'wp.class', file, at(match.index ?? 0),
      `\`${cls}\` is a WordPress class with no counterpart in React-WP (there is no PHP object model, Loop or query builder).`,
      'Read content through the database client or the `rwp_get_*` functions, and render it with React.'));
    break;
  }

  // WordPress function called under its WordPress name.
  const seenFunctions = new Set<string>();
  for (const match of codeOnly.matchAll(/(?<![.\w$])([a-z_][a-z0-9_]*)\s*\(/gi)) {
    const name = match[1];
    if (seenFunctions.has(name) || declared.has(name)) continue;
    if (/^_?rwp/i.test(name)) continue;
    if (!name.includes('_') && !PLAIN_WP_NAMES.has(name)) continue;
    const reason = lookup.reason('functions', name);
    const target = rwpName(name);
    if (reason) {
      seenFunctions.add(name);
      out.push(finding('error', 'wp.no-counterpart', file, at(match.index ?? 0),
        `\`${name}()\` is a WordPress function with no counterpart in React-WP. ${reason}`,
        'Rewrite this part with React or a plugin server route instead of keeping the call.'));
    } else if (lookup.functions.has(target) && target !== name) {
      seenFunctions.add(name);
      out.push(finding('error', 'wp.unprefixed-function', file, at(match.index ?? 0),
        `\`${name}()\` is a WordPress function name. In React-WP it is \`${target}()\`${lookup.asyncFunctions.has(target) ? ' and it is async, so it must be awaited' : ''}.`,
        `Rename it to \`${target}\` and import it from the plugin API.`));
    }
  }

  // Hook names.
  for (const match of noComments.matchAll(HOOK_CALL)) {
    if (!inCode(match.index ?? 0)) continue;
    const name = match[2].trim();
    if (!name || lookup.hooks.has(name)) continue;
    const line = at(match.index ?? 0);
    const unprefixed = lookup.reason('hooks', name);
    const target = rwpName(name);
    if (!name.startsWith('rwp_') && lookup.hooks.has(target)) {
      out.push(finding('error', 'wp.unprefixed-hook', file, line,
        `Hook "${name}" is a WordPress hook name. In React-WP it is "${target}".`,
        `Use "${target}".`));
    } else if (!name.startsWith('rwp_') && unprefixed) {
      out.push(finding('error', 'wp.hook-no-counterpart', file, line,
        `Hook "${name}" exists in WordPress but never fires in React-WP. ${unprefixed}`,
        'Pick another hook, or replace this behaviour with React code.'));
    } else if (name.startsWith('rwp_')) {
      const near = closest(name, lookup.hooks, 3);
      out.push(finding('warning', 'hook.unknown', file, line,
        `Hook "${name}" is not a hook React-WP fires${near ? ` (did you mean "${near}"?)` : ''}.`,
        'If it is your own hook, give it your plugin\'s own prefix (for example "my_plugin_saved"). Otherwise fix the spelling.'));
    }
  }

  // rwp_ functions that do not exist.
  const reported = new Set<string>();
  for (const match of codeOnly.matchAll(/(?<![.\w$])(_?rwp_[A-Za-z0-9_]*)\s*\(/g)) {
    const name = match[1];
    if (reported.has(name) || lookup.functions.has(name) || declared.has(name)) continue;
    reported.add(name);
    const near = closest(name, lookup.functions, 3);
    out.push(finding('error', 'rwp.unknown-function', file, at(match.index ?? 0),
      `\`${name}()\` does not exist in React-WP${near ? ` (did you mean \`${near}\`?)` : ''}. A name that only looks right was probably invented.`,
      near ? `Use \`${near}\`, or check docs/wordpress-parity/reference for the real name.` : 'Check the reference for the real name, or write the logic yourself.'));
  }
  for (const match of noComments.matchAll(/import\s+(?:type\s+)?\{([^}]*)\}\s*from\s*['"]([^'"\n]*plugin-api[^'"\n]*)['"]/g)) {
    if (!inCode(match.index ?? 0)) continue;
    for (const part of match[1].split(',')) {
      const name = part.trim().split(/\s+as\s+/)[0].replace(/^type\s+/, '').trim();
      if (!/^_?(?:rwp_|RWP_)/.test(name) || lookup.functions.has(name) || reported.has(name)) continue;
      reported.add(name);
      const near = closest(name, lookup.functions, 3);
      out.push(finding('error', 'rwp.unknown-import', file, at(match.index ?? 0),
        `\`${name}\` is imported from the plugin API but is not exported by it${near ? ` (did you mean \`${near}\`?)` : ''}. The build will stop with a missing-export error.`,
        near ? `Import \`${near}\` instead.` : 'Remove the import or use a function that exists.'));
    }
  }

  // Async functions used as if they were synchronous.
  for (const match of codeOnly.matchAll(/(?:\b(?:const|let|var)\s+[\w${}\s,:[\]]+?=\s*|\bif\s*\(\s*!?\s*)(rwp_[A-Za-z0-9_]+)\s*\(/g)) {
    const name = match[1];
    if (!lookup.asyncFunctions.has(name)) continue;
    out.push(finding('warning', 'rwp.missing-await', file, at(match.index ?? 0),
      `\`${name}()\` returns a Promise but its result is used directly. The value will be a Promise, not the data.`,
      `Write \`await ${name}(...)\` inside an async function.`));
  }

  // ----- security --------------------------------------------------------------------------------
  const unsafe: Array<[RegExp, Finding['severity'], string, string, string]> = [
    [/(?<![.\w$])eval\s*\(/, 'error', 'security.eval', '`eval()` runs a string as code.', 'Remove it. Parse data with JSON.parse; never execute text.'],
    [/\bnew\s+Function\s*\(/, 'error', 'security.new-function', '`new Function()` runs a string as code.', 'Remove it. A plugin must not compile code at run time.'],
    [/\bdocument\s*\.\s*write(?:ln)?\s*\(/, 'error', 'security.document-write', '`document.write()` injects markup that can carry script.', 'Render with React instead.'],
    [/\bimport\s*\(\s*['"`]https?:/, 'error', 'security.remote-import', 'The plugin loads code from a web address at run time. That code could change after you reviewed this one.', 'Bundle the dependency in the plugin instead of importing it from a URL.'],
    [/\bimportScripts\s*\(/, 'error', 'security.import-scripts', '`importScripts()` loads code from another address.', 'Bundle the code in the plugin.'],
  ];
  for (const [pattern, severity, code, message, fix] of unsafe) {
    const hit = pattern.exec(code === 'security.remote-import' ? noComments : codeOnly);
    if (hit) out.push(finding(severity, code, file, at(hit.index), message, fix));
  }
  for (const [pattern, code, message, fix] of [
    [/\.\s*(?:inner|outer)HTML\s*=(?!=)/, 'security.inner-html', 'Assigning `innerHTML` writes unsanitised markup into the page.', 'Use React elements, or sanitise the HTML first.'],
    [/\bdangerouslySetInnerHTML\b/, 'security.dangerous-html', '`dangerouslySetInnerHTML` renders raw HTML. If any of it comes from a visitor or from the database it is a cross-site-scripting hole.', 'Sanitise the HTML first (the site\'s content renderer does this) or render it as React elements.'],
    [/\.\s*src\s*=\s*['"`]https?:|createElement\(\s*['"]script['"]\s*\)/, 'security.script-injection', 'The plugin adds a script tag from code. That runs whatever the address serves.', 'Bundle the script in the plugin, or use the site\'s tracking-scripts setting.'],
    [/fetch\(\s*['"`]http:\/\//, 'security.insecure-http', 'A request goes to a plain http:// address, which can be read or changed on the way.', 'Use https://.'],
  ] as Array<[RegExp, string, string, string]>) {
    const hit = pattern.exec(code === 'security.script-injection' || code === 'security.insecure-http' ? noComments : codeOnly);
    if (hit) out.push(finding('warning', code, file, at(hit.index), message, fix));
  }

  for (const [pattern, label] of SECRET_PATTERNS) {
    const hit = pattern.exec(noComments);
    if (hit) {
      out.push(finding('error', 'security.secret-in-code', file, at(hit.index),
        `This looks like ${label}. A plugin's code is copied to every site that installs it and is served to browsers.`,
        'Delete the value and rotate the credential. Store credentials in an admin setting, never in source.'));
    }
  }
  const password = /\b(?:password|passwd|secret|api_?key|token)\s*[:=]\s*['"][^'"\s]{8,}['"]/i.exec(noComments);
  if (password) {
    out.push(finding('warning', 'security.hardcoded-credential', file, at(password.index),
      'A credential-like value is written into the source.',
      'Read it from an admin setting instead.'));
  }
  for (const match of noComments.matchAll(/import\.meta\.env\.(VITE_\w+)/g)) {
    if (/(SECRET|PRIVATE|SERVICE|PASSWORD|TOKEN|KEY)/.test(match[1]) && !/(PUBLISHABLE|ANON|PUBLIC)/.test(match[1])) {
      out.push(finding('error', 'security.vite-secret', file, at(match.index ?? 0),
        `\`${match[1]}\` is compiled into the public JavaScript that every visitor downloads. A secret there is not secret.`,
        'Keep it server-side in an admin setting and call it from a plugin server route.'));
      break;
    }
  }
  if (!isServer) {
    const hit = /\b(?:service_role|SUPABASE_SECRET_KEY|SUPABASE_SERVICE\w*)\b/.exec(noComments);
    if (hit) {
      out.push(finding('warning', 'security.service-key-client', file, at(hit.index),
        `Browser code mentions \`${hit[0]}\`. If it uses that key, the key bypasses every access rule and is visible to every visitor. (A sentence that only explains the setting is fine.)`,
        'Do privileged work in the plugin\'s server.mjs only.'));
    }
  }
  if (!isServer) {
    const env = /\bprocess\s*\.\s*env\b/.exec(codeOnly);
    if (env) {
      out.push(finding('warning', 'security.process-env-client', file, at(env.index),
        '`process.env` does not exist in the browser and is never a safe place for a value the page needs.',
        'Read settings from the database or from `import.meta.env.VITE_*` for public values only.'));
    }
    const storage = /localStorage\s*\.\s*setItem\(\s*[^)]*\b(?:password|token|secret|api_?key)\b/i.exec(noComments);
    if (storage) {
      out.push(finding('warning', 'security.token-in-storage', file, at(storage.index),
        'A credential is written to localStorage, where any script on the page can read it.',
        'Keep it in memory or sessionStorage, and say so to the user.'));
    }
  } else {
    const child = /\b(?:child_process|execSync|execFile|spawnSync)\b|(?<![.\w$])(?:exec|spawn)\s*\(/.exec(codeOnly + noComments);
    if (child) {
      out.push(finding('error', 'security.child-process', file, at(child.index),
        'The server file starts operating-system processes. A plugin route runs with the site\'s service key; this lets a request run commands.',
        'Remove it. A plugin must not run shell commands.'));
    }
    if (/\b(?:writeFile|appendFile|createWriteStream|mkdir|rmSync|unlink)\b/.test(codeOnly)) {
      const hit = /\b(?:writeFile|appendFile|createWriteStream|mkdir|rmSync|unlink)\b/.exec(codeOnly);
      out.push(finding('warning', 'server.writes-disk', file, at(hit?.index ?? 0),
        'The server file writes to disk. On Vercel the filesystem is read-only, so this fails there.',
        'Store data in the database.'));
    }
    const env = /\bprocess\s*\.\s*env\s*\.\s*([A-Z_][A-Z0-9_]*)/.exec(codeOnly);
    if (env) {
      out.push(finding('warning', 'server.reads-env', file, at(env.index),
        `The server file reads the environment variable ${env[1]}. A client cannot set environment variables for a plugin.`,
        'Keep plugin credentials in an admin setting (system_settings), with the site\'s own settings as the fallback.'));
    }
    if (isRouteFile && !/authorize|capabilit|user_has_cap|getUser|session|bearer|requireUser|token/i.test(noComments)) {
      out.push(finding('warning', 'server.no-authorization', file, 1,
        'No authorisation check was found. Every plugin route runs with the site\'s service key, so a route that does not check who is asking is open to anyone.',
        'Verify the caller (session and capability) at the start of every route that changes or reveals data.'));
    }
  }

  // ----- imports ---------------------------------------------------------------------------------
  const specifiers: Array<{ specifier: string; offset: number }> = [];
  for (const match of noComments.matchAll(/(?:import|export)\s+(?:type\s+)?(?:[^'"`;]*?\sfrom\s*)?['"]([^'"\n]+)['"]|import\(\s*['"]([^'"\n]+)['"]\s*\)|require\(\s*['"]([^'"\n]+)['"]\s*\)/g)) {
    if (!inCode(match.index ?? 0)) continue;
    specifiers.push({ specifier: match[1] || match[2] || match[3], offset: match.index ?? 0 });
  }
  const seen = new Set<string>();
  for (const { specifier, offset } of specifiers) {
    if (seen.has(specifier)) continue;
    seen.add(specifier);
    const line = at(offset);
    if (specifier.startsWith('.')) {
      const climb = climbsTo(file, specifier);
      if (climb) {
        const first = climb.rest.split('/').slice(0, 3).join('/');
        if (climb.above === 2 && STABLE_CORE.test(`${climb.rest}/`)) continue;
        if (climb.above === 2 && climb.rest.startsWith('src/')) {
          out.push(finding('info', 'import.core-internal', file, line,
            `Imports \`${first}\`, a core file outside the documented plugin API. It can change in a core release, so check this plugin after updating React-WP.`,
            'Prefer \'../../src/lib/plugin-api\' where it offers the same thing.'));
        } else if (climb.above === 2 && isServer && climb.rest.startsWith('server/')) {
          out.push(finding('info', 'import.core-server', file, line,
            `Imports the core server module \`${first}\`. It can change in a core release, so check this plugin after updating React-WP.`));
        } else {
          out.push(finding('error', 'import.outside-plugin', file, line,
            `Imports \`${specifier}\`, which is outside the plugin's own folder.`,
            'Keep the plugin self-contained; only \'../../src/lib/plugin-api\' may be imported from outside.'));
        }
        continue;
      }
      if (!resolvesInside(file, specifier, allFiles)) {
        out.push(finding('error', 'import.missing-file', file, line,
          `Imports \`${specifier}\`, but that file is not in the ZIP. The build will stop.`,
          'Add the file, or remove the import.'));
      }
      continue;
    }
    if (/^(?:node:|fs$|path$|os$|child_process$|crypto$|http$|https$|net$|tls$|zlib$|stream$|url$)/.test(specifier)) {
      if (!isServer) {
        out.push(finding('error', 'import.node-in-browser', file, line,
          `Imports the Node module \`${specifier}\` in code that runs in the browser.`,
          'Move it into server.mjs, or use a browser API.'));
      }
      continue;
    }
    if (/^(?:[a-z]+:|#|@\/|~\/)/i.test(specifier)) continue;
    const parts = specifier.split('/');
    const pkg = specifier.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
    if (!lookup.packages.has(pkg) && pkg !== 'react' && pkg !== 'react-dom') {
      out.push(finding('warning', 'import.package', file, line,
        `Imports the package \`${pkg}\`, which this site's build does not include.`,
        `The build stops unless it is installed. Prefer code already in the site, or run \`npm install ${pkg}\` where the site is built.`));
    }
  }
  return out;
}
