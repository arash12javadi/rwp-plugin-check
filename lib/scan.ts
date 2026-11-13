/**
 * Small text helpers shared by the rules. No DOM and no imports, so the checker runs in the browser
 * and in plain node tests.
 */

export interface Masked {
  /** Comments blanked out; strings kept. Used to read hook names and import paths. */
  noComments: string;
  /** Comments and the inside of strings blanked out. Used to find calls and identifiers. */
  codeOnly: string;
}

const blank = (text: string): string => text.replace(/[^\n]/g, ' ');

/**
 * Blanks comments (and, for `codeOnly`, string contents) while keeping every newline and every
 * offset, so a match in the masked text has the same line number in the original.
 *
 * It is a scanner, not a parser: a regular-expression literal is recognised from the character before
 * it. Rules that use it are heuristics and say so.
 */
export function mask(source: string): Masked {
  const length = source.length;
  let noComments = '';
  let codeOnly = '';
  let index = 0;
  let previous = ''; // last significant character, to tell a regex from a division

  while (index < length) {
    const char = source[index];
    const next = source[index + 1];

    if (char === '/' && next === '/') {
      let end = source.indexOf('\n', index);
      if (end === -1) end = length;
      const piece = blank(source.slice(index, end));
      noComments += piece;
      codeOnly += piece;
      index = end;
      continue;
    }
    if (char === '/' && next === '*') {
      let end = source.indexOf('*/', index + 2);
      end = end === -1 ? length : end + 2;
      const piece = blank(source.slice(index, end));
      noComments += piece;
      codeOnly += piece;
      index = end;
      continue;
    }
    if (char === '"' || char === "'" || char === '`') {
      let end = index + 1;
      while (end < length) {
        if (source[end] === '\\') { end += 2; continue; }
        if (source[end] === char) break;
        if (char !== '`' && source[end] === '\n') break; // unterminated: stop at the line end
        end += 1;
      }
      const stop = Math.min(end + 1, length);
      const text = source.slice(index, stop);
      noComments += text;
      codeOnly += char + blank(text.slice(1, -1)) + (text.length > 1 ? text[text.length - 1] : '');
      index = stop;
      previous = char;
      continue;
    }
    if (char === '/' && (/[(,=:[!&|?{};]/.test(previous || ';') || /(?:^|[^\w$.])(?:return|typeof|case|of|in|delete|void|throw|new|else|do|yield|await)\s*$/.test(codeOnly.slice(-14)))) {
      // A regular-expression literal.
      let end = index + 1;
      let inClass = false;
      while (end < length) {
        const c = source[end];
        if (c === '\\') { end += 2; continue; }
        if (c === '\n') break;
        if (c === '[') inClass = true;
        else if (c === ']') inClass = false;
        else if (c === '/' && !inClass) break;
        end += 1;
      }
      const stop = Math.min(end + 1, length);
      noComments += source.slice(index, stop);
      codeOnly += blank(source.slice(index, stop));
      index = stop;
      previous = '/';
      continue;
    }
    noComments += char;
    codeOnly += char;
    if (!/\s/.test(char)) previous = char;
    index += 1;
  }
  return { noComments, codeOnly };
}

/** 1-based line of an offset. */
export const lineAt = (text: string, offset: number): number => {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i += 1) if (text.charCodeAt(i) === 10) line += 1;
  return line;
};

/** Classic Levenshtein distance, bounded: returns `limit + 1` once it is certain to exceed `limit`. */
export function distance(a: string, b: string, limit = 3): number {
  if (Math.abs(a.length - b.length) > limit) return limit + 1;
  let row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    const next = [i];
    let best = i;
    for (let j = 1; j <= b.length; j += 1) {
      const value = Math.min(row[j] + 1, next[j - 1] + 1, row[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      next.push(value);
      if (value < best) best = value;
    }
    if (best > limit) return limit + 1;
    row = next;
  }
  return row[b.length];
}

/** The closest name in `pool`, or '' when nothing is near enough. */
export function closest(name: string, pool: Iterable<string>, limit = 3): string {
  let best = '';
  let bestDistance = limit + 1;
  for (const candidate of pool) {
    const d = distance(name, candidate, limit);
    if (d < bestDistance) {
      bestDistance = d;
      best = candidate;
      if (d === 0) break;
    }
  }
  return bestDistance <= limit ? best : '';
}

/** Splits SQL into statements at `;`, honouring quotes, `$$` bodies and comments. */
export function splitSql(sql: string): Array<{ text: string; line: number }> {
  const statements: Array<{ text: string; line: number }> = [];
  let current = '';
  let startLine = 1;
  let line = 1;
  let index = 0;
  let dollar = '';
  const flush = () => {
    const text = current.trim();
    if (text) statements.push({ text, line: startLine });
    current = '';
  };
  const append = (piece: string) => {
    if (!current.trim() && /\S/.test(piece)) startLine = line;
    current += piece;
    line += (piece.match(/\n/g) || []).length;
  };

  while (index < sql.length) {
    const char = sql[index];
    if (!dollar && char === '-' && sql[index + 1] === '-') {
      let end = sql.indexOf('\n', index);
      if (end === -1) end = sql.length;
      index = end;
      continue;
    }
    if (!dollar && char === '/' && sql[index + 1] === '*') {
      let end = sql.indexOf('*/', index + 2);
      end = end === -1 ? sql.length : end + 2;
      line += (sql.slice(index, end).match(/\n/g) || []).length;
      index = end;
      continue;
    }
    if (!dollar && char === "'") {
      let end = index + 1;
      while (end < sql.length) {
        if (sql[end] === "'" && sql[end + 1] === "'") { end += 2; continue; }
        if (sql[end] === "'") break;
        end += 1;
      }
      append(sql.slice(index, end + 1));
      index = end + 1;
      continue;
    }
    if (char === '$') {
      const tag = /^\$[A-Za-z_]*\$/.exec(sql.slice(index, index + 64))?.[0];
      if (tag) {
        if (!dollar) dollar = tag;
        else if (dollar === tag) dollar = '';
        append(tag);
        index += tag.length;
        continue;
      }
    }
    if (!dollar && char === ';') {
      flush();
      index += 1;
      continue;
    }
    append(char);
    index += 1;
  }
  flush();
  return statements;
}
