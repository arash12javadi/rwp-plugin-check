import type { Names } from './types';

/**
 * WordPress name -> React-WP name. The same rule as `scripts/wpParity/lib/naming.mjs`, which the
 * extractor, the alias table and the codemod use; it is repeated here because this plugin ships to
 * sites that do not have `scripts/`.
 */
const SPECIAL: Record<string, string> = {
  __: 'rwp__', _e: 'rwp_e', _x: 'rwp_x', _ex: 'rwp_ex', _n: 'rwp_n', _nx: 'rwp_nx',
  _n_noop: 'rwp_n_noop', _nx_noop: 'rwp_nx_noop', _c: 'rwp_c',
};

export function rwpName(name: string): string {
  if (!name) return name;
  if (SPECIAL[name]) return SPECIAL[name];
  if (/^_?rwp/i.test(name)) return name;
  if (/^_wp(?=[_\-a-z0-9])/.test(name)) return `_rwp${name.slice(3)}`;
  if (/^wp(?=[_\-a-z0-9])/.test(name)) return `r${name}`;
  if (name.startsWith('_')) return `_rwp_${name.slice(1)}`;
  return `rwp_${name}`;
}

export interface Lookup {
  hooks: Set<string>;
  functions: Set<string>;
  asyncFunctions: Set<string>;
  packages: Set<string>;
  names: Names;
  reason: (kind: 'hooks' | 'functions', name: string) => string | undefined;
}

const cache = new WeakMap<Names, Lookup>();

export function lookupFor(names: Names): Lookup {
  const found = cache.get(names);
  if (found) return found;
  const lookup: Lookup = {
    hooks: new Set(names.hooks),
    functions: new Set(names.functions),
    asyncFunctions: new Set(names.asyncFunctions),
    packages: new Set(names.packages),
    names,
    reason: (kind, name) => {
      const index = names.notApplicable[kind][name];
      return index === undefined ? undefined : names.reasons[index];
    },
  };
  cache.set(names, lookup);
  return lookup;
}

/** The names a source file declares itself: functions, variables, classes and imports. */
export function declaredNames(codeOnly: string): Set<string> {
  const declared = new Set<string>();
  for (const match of codeOnly.matchAll(/\b(?:function\*?|const|let|var|class|enum|interface|type)\s+([A-Za-z_$][\w$]*)/g)) {
    declared.add(match[1]);
  }
  for (const match of codeOnly.matchAll(/\bimport\s+(?:type\s+)?([A-Za-z_$][\w$]*)\s*(?:,|from)/g)) declared.add(match[1]);
  for (const match of codeOnly.matchAll(/\bimport\s+(?:type\s+)?\*\s+as\s+([A-Za-z_$][\w$]*)/g)) declared.add(match[1]);
  for (const match of codeOnly.matchAll(/\b(?:import|export)\s+(?:type\s+)?\{([^}]*)\}/g)) {
    for (const part of match[1].split(',')) {
      const name = part.trim().split(/\s+as\s+/).pop()?.replace(/^type\s+/, '').trim();
      if (name) declared.add(name);
    }
  }
  // Parameters and destructured bindings: `(a, b) =>`, `({ a, b }) =>`, `function f(a, b)`.
  for (const match of codeOnly.matchAll(/(?:\(|,)\s*([A-Za-z_$][\w$]*)\s*(?::[^,)=]+)?(?=\s*[,)=])/g)) declared.add(match[1]);
  for (const match of codeOnly.matchAll(/\{\s*([^{}]*?)\s*\}\s*=/g)) {
    for (const part of match[1].split(',')) {
      const name = part.trim().split(':').pop()?.trim().split('=')[0].trim();
      if (name && /^[A-Za-z_$][\w$]*$/.test(name)) declared.add(name);
    }
  }
  return declared;
}
