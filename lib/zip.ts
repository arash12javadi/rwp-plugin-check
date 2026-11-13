import { unzipSync } from 'fflate';
import type { Entries } from './types';

/**
 * Unpacks a plugin ZIP in the browser with the same safety rules the server installer applies
 * (`unpack` in server/pluginInstaller.mjs): no unsafe paths, a file-count and size limit, one plugin per
 * ZIP, `manifest.json` at the root or inside a single top-level folder, and no two names that differ only
 * by case.
 *
 * Nothing is written anywhere; the bytes stay in memory.
 */

const MAX_FILES = 5000;
const MAX_UNPACKED_BYTES = 150 * 1024 * 1024;
const IGNORED = [/^__MACOSX\//, /(^|\/)\.DS_Store$/, /(^|\/)Thumbs\.db$/];

export class ZipProblem extends Error {}

const safeName = (name: string): boolean => {
  if (!name || name.startsWith('/') || /^[A-Za-z]:/.test(name) || name.includes('\\') || name.includes('\0')) return false;
  return !name.split('/').some((part) => part === '..');
};

export function unpackPluginZip(bytes: Uint8Array): Entries {
  if (bytes.length < 4 || bytes[0] !== 0x50 || bytes[1] !== 0x4b || bytes[2] !== 0x03 || bytes[3] !== 0x04) {
    throw new ZipProblem(bytes.length === 0 ? 'The file is empty.' : 'This is not a ZIP archive (it does not start with a ZIP header).');
  }
  let files = 0;
  let total = 0;
  const unsafe: string[] = [];
  let archive: Record<string, Uint8Array>;
  try {
    archive = unzipSync(bytes, {
      filter: (file) => {
        if (file.name.endsWith('/') || IGNORED.some((pattern) => pattern.test(file.name))) return false;
        if (!safeName(file.name)) {
          unsafe.push(file.name);
          return false;
        }
        files += 1;
        total += file.originalSize;
        if (files > MAX_FILES) throw new ZipProblem(`The ZIP contains more than ${MAX_FILES} files.`);
        if (total > MAX_UNPACKED_BYTES) throw new ZipProblem('The ZIP unpacks to more than 150 MB.');
        return true;
      },
    });
  } catch (error) {
    if (error instanceof ZipProblem) throw error;
    throw new ZipProblem(`The ZIP is damaged or uses an unsupported format: ${(error as Error)?.message || error}.`);
  }
  if (unsafe.length) {
    throw new ZipProblem(`The ZIP contains unsafe file paths, so it would be refused: ${unsafe.slice(0, 5).map((n) => JSON.stringify(n)).join(', ')}.`);
  }
  const names = Object.keys(archive);
  if (!names.length) throw new ZipProblem('The ZIP contains no files.');

  let prefix = '';
  if (!names.includes('manifest.json')) {
    const nested = names.filter((name) => /^[^/]+\/manifest\.json$/.test(name));
    const top = nested.length === 1 ? nested[0].slice(0, nested[0].indexOf('/') + 1) : '';
    if (top && names.every((name) => name.startsWith(top))) prefix = top;
    else if (nested.length > 1) throw new ZipProblem(`The ZIP contains several plugins (${nested.join(', ')}). Upload one plugin per ZIP.`);
    // else: no manifest at all. Let the checker report it with the rest, from the root.
  }

  const entries: Entries = new Map();
  const lower = new Map<string, string>();
  for (const name of names) {
    const relative = name.slice(prefix.length);
    const clash = lower.get(relative.toLowerCase());
    if (clash) throw new ZipProblem(`The ZIP contains both "${clash}" and "${relative}", which are the same file on Windows and macOS.`);
    lower.set(relative.toLowerCase(), relative);
    entries.set(relative, archive[name]);
  }
  return entries;
}
