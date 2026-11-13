import type { SyntaxChecker } from './types';

/**
 * A syntax checker backed by the TypeScript compiler, loaded only when a check runs (it is large).
 * `transpileModule` with diagnostics reports syntax errors without needing the plugin's imports to
 * resolve, which is exactly the question here. Returns null when the compiler cannot be loaded, and the
 * report then says syntax was not checked rather than implying it was.
 */
export async function loadSyntaxChecker(): Promise<SyntaxChecker | null> {
  try {
    const mod = await import('typescript');
    const ts = (mod as unknown as { default?: typeof import('typescript') }).default ?? (mod as unknown as typeof import('typescript'));
    if (typeof ts.transpileModule !== 'function') return null;
    return (file, source) => {
      const result = ts.transpileModule(source, {
        fileName: file,
        reportDiagnostics: true,
        compilerOptions: {
          jsx: ts.JsxEmit.Preserve,
          target: ts.ScriptTarget.ES2022,
          module: ts.ModuleKind.ESNext,
          allowJs: true,
          isolatedModules: true,
        },
      });
      return (result.diagnostics || []).map((diagnostic) => {
        const position = diagnostic.file && diagnostic.start !== undefined
          ? diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start).line + 1
          : 1;
        return { line: position, message: ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n') };
      });
    };
  } catch {
    return null;
  }
}
