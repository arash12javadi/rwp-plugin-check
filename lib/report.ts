import type { Finding, Report } from './types';

const where = (finding: Finding): string =>
  finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ''}` : 'whole plugin';

export const verdictText = (report: Report): string => {
  if (report.verdict === 'pass') return 'No problems found. It is reasonable to install.';
  if (report.verdict === 'warn') return 'Installable, but read the warnings first.';
  return `Do not install yet: ${report.counts.error} problem${report.counts.error === 1 ? '' : 's'} must be fixed.`;
};

/**
 * Plain text to paste back into the converter (the AI Factory) so it can repair the plugin: every error
 * and warning with its file and line and what to do, and nothing else.
 */
export function reportForAi(report: Report): string {
  const lines = report.findings.filter((f) => f.severity !== 'info');
  if (!lines.length) return 'The plugin check found no problems.';
  const out = [
    `Plugin check of ${report.plugin.id || 'the plugin'} ${report.plugin.version || ''}`.trim() + `: ${report.counts.error} error(s), ${report.counts.warning} warning(s).`,
    'Fix every ERROR and, where reasonable, every WARNING below, then return the complete plugin again (all files). Do not invent functions or hook names: use only names that exist in React-WP.',
    '',
  ];
  for (const finding of lines) {
    out.push(`${finding.severity.toUpperCase()} [${finding.code}] ${where(finding)}`);
    out.push(`  ${finding.message}`);
    if (finding.fix) out.push(`  Fix: ${finding.fix}`);
  }
  return out.join('\n');
}
